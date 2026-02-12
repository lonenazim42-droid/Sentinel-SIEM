# --- Standard library ---
import uuid
import hashlib
import requests  #To talk to Ollama
import sqlite3
import copy
import json
import logging
import os
import tempfile
import threading
import time
import re
from collections import defaultdict, deque, Counter
from dataclasses import asdict, dataclass
from math import exp, log
from typing import Any, Dict, Set, List, Optional, Tuple, Deque
from datetime import datetime, timedelta
from urllib.parse import quote

# --- Third-party ---
import torch
from nltk.stem import WordNetLemmatizer  # type: ignore[import-untyped]

@dataclass
class LogEvent:
    """Rich log event container for security context."""
    timestamp: datetime
    severity: str
    service: str
    message: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    error_code: Optional[str] = None
    raw: str = ""

class LogParser:
    """
    The 'Eagle Eyes' of the Sentinel.
    Auto-detects format: Standard, Syslog, Apache, JSON, CEF, or Windows.
    """
    def __init__(self):
        self.patterns = {
            # 1. YOUR EXISTING STANDARD FORMAT (server.log)
            'standard': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                r'\s+\[(?P<severity>\w+)\]'
                r'\s+(?P<service>[\w\-\.]+)'
                r'\s+(?P<message>.*?)$'
            ),

            # 2. YOUR EXISTING APACHE FORMAT (attack.log)
            'apache': re.compile(
                r'(?P<source_ip>\d+\.\d+\.\d+\.\d+)'
                r'\s+-\s+(?P<user>\S+)'
                r'\s+\[(?P<timestamp>[^\]]+)\]'
                r'\s+"(?P<message>[^"]+)"'
                r'\s+(?P<error_code>\d{3})'
            ),

            # 3. NEW: SYSLOG (Linux/System)
            'syslog': re.compile(
                r'(?P<timestamp>\w+\s+\d+\s+\d{2}:\d{2}:\d{2})'
                r'\s+(?P<hostname>[\w\-\.]+)'
                r'\s+(?P<service>[\w\-\[\]]+):'
                r'\s+(?P<message>.*?)$'
            ),

            # 4. NEW: CEF (Common Event Format - Security Appliances)
            'cef': re.compile(
                r'CEF:(?P<version>\d+)\|(?P<vendor>[^|]+)\|(?P<product>[^|]+)\|(?P<version2>[^|]+)\|(?P<signature>[^|]+)\|'
                r'(?P<name>[^|]+)\|(?P<severity>\d+)\|(?P<extensions>.*?)$'
            ),

            # 5. NEW: WINDOWS EVENT LOG
            'windows_event': re.compile(
                r'(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})'
                r'\s+(?P<event_id>\d+)\s+'
                r'(?P<level>\w+)\s+'
                r'(?P<source>[^:]+):\s+'
                r'(?P<message>.*?)$'
            ),

            # 6. JSON Placeholder
            'json': None
        }

    def _parse_ts(self, ts_str):
        """Robust timestamp parsing - tries multiple formats"""
        formats = [
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S",  # Apache style (e.g., 29/Jan/2026:14:00:00)
            "%d/%b/%Y:%H:%M:%S %z",
            "%b %d %H:%M:%S",     # Syslog style (e.g., Jan 29 14:00:00)
            "%Y-%m-%dT%H:%M:%S.%fZ" # ISO 8601
        ]
        for fmt in formats:
            try:
                # Remove brackets if present (common in Apache)
                clean_ts = ts_str.strip('[]')
                return datetime.strptime(clean_ts, fmt)
            except ValueError:
                continue
        return datetime.now()

    def _parse_json_log(self, data: dict, raw: str) -> Optional[LogEvent]:
        """Parse JSON-formatted logs"""
        try:
            ts_str = data.get('timestamp') or data.get('time') or data.get('@timestamp')
            timestamp = self._parse_ts(ts_str) if ts_str else datetime.now()

            return LogEvent(
                timestamp=timestamp,
                severity=(data.get('level') or data.get('severity') or 'INFO').upper(),
                service=data.get('service') or data.get('logger') or 'app',
                message=data.get('message') or data.get('msg') or str(data),
                source_ip=data.get('source_ip') or data.get('src_ip') or data.get('client_ip'),
                user=data.get('user') or data.get('username'),
                error_code=data.get('error_code') or data.get('code'),
                raw=raw
            )
        except Exception:
            return None

    def _parse_syslog(self, groups: dict, raw: str) -> Optional[LogEvent]:
        """Parse syslog format"""
        severity = "ERROR" if any(kw in groups['message'].lower() for kw in ['error', 'fail', 'critical']) else "INFO"
        return LogEvent(
            timestamp=self._parse_ts(groups['timestamp']),
            severity=severity,
            service=groups.get('service', 'syslog'),
            message=groups['message'],
            raw=raw
        )

    def _parse_cef(self, groups: dict, raw: str) -> Optional[LogEvent]:
        """Parse CEF logs"""
        severity_map = {'0': 'INFO', '3': 'WARNING', '5': 'ERROR', '7': 'CRITICAL'}
        return LogEvent(
            timestamp=datetime.now(),
            severity=severity_map.get(groups.get('severity', '3'), 'INFO'),
            service=f"{groups['vendor']}/{groups['product']}",
            message=f"{groups['name']} - {groups['extensions']}",
            raw=raw
        )

    def parse(self, line: str) -> Optional[LogEvent]:
        line = line.strip()
        if not line: return None

        # 1. Try JSON First (Most structured)
        if line.startswith('{'):
            try:
                data = json.loads(line)
                return self._parse_json_log(data, line)
            except:
                pass

        # 2. Try Regex Patterns Loop
        # We explicitly list them to control priority
        priority_order = ['standard', 'apache', 'syslog', 'cef', 'windows_event']

        for fmt_name in priority_order:
            pattern = self.patterns.get(fmt_name)
            if not pattern: continue

            match = pattern.search(line)
            if match:
                data = match.groupdict()

                if fmt_name == 'standard':
                    return LogEvent(
                        timestamp=self._parse_ts(data['timestamp']),
                        severity=data['severity'],
                        service=data['service'],
                        message=data['message'],
                        raw=line
                    )

                elif fmt_name == 'apache':
                    # Infer severity from HTTP code
                    code = int(data['error_code'])
                    severity = "CRITICAL" if code >= 500 else "ERROR" if code >= 400 else "INFO"
                    return LogEvent(
                        timestamp=self._parse_ts(data['timestamp']),
                        severity=severity,
                        service="web-server",
                        message=f"{data['message']} (Code: {code})",
                        source_ip=data['source_ip'],
                        user=data['user'],
                        error_code=str(code),
                        raw=line
                    )

                elif fmt_name == 'syslog':
                    return self._parse_syslog(data, line)

                elif fmt_name == 'cef':
                    return self._parse_cef(data, line)

                elif fmt_name == 'windows_event':
                    return LogEvent(
                        timestamp=self._parse_ts(data['timestamp']),
                        severity=data['level'].upper(),
                        service=data['source'],
                        message=f"{data['message']} (ID: {data['event_id']})",
                        raw=line
                    )

        return None

class AnomalyDetector:
    """
    The 'Reflex System' - Enterprise Edition.
    Detects Brute Force, Scans, Degradation, Privilege Escalation, and Lateral Movement.
    """
    def __init__(self):
        # State tracking
        self.failed_logins = defaultdict(deque)  # IP -> timestamps
        self.service_scan = defaultdict(set)     # IP -> services
        self.user_services = defaultdict(set)    # User -> services (Lateral Movement)

        # ⚙️ CONFIGURATION (Enterprise Tuned)
        self.BRUTE_FORCE_THRESHOLD = 5
        self.BRUTE_FORCE_WINDOW = 60
        self.SCAN_THRESHOLD = 3
        self.LATERAL_MOVE_THRESHOLD = 5          # 5+ services by one user
        self.ERROR_RATE_THRESHOLD = 0.15         # 15% error rate = degradation
        self.PRIV_KEYWORDS = ["sudo", "root", "admin", "privilege"]

    def check(self, event: LogEvent) -> List[Dict[str, Any]]:
        """Returns a list of anomalies found in this event."""
        anomalies = []
        now = event.timestamp.timestamp()

        # --- 1. BRUTE FORCE DETECTOR ---
        is_failure = event.severity in ["CRITICAL", "ERROR"] or \
                     (event.error_code and int(event.error_code) >= 400) or \
                     "fail" in event.message.lower()

        if is_failure and event.source_ip:
            self.failed_logins[event.source_ip].append(now)
            # Clean window
            while self.failed_logins[event.source_ip] and \
                  self.failed_logins[event.source_ip][0] < now - self.BRUTE_FORCE_WINDOW:
                self.failed_logins[event.source_ip].popleft()

            if len(self.failed_logins[event.source_ip]) >= self.BRUTE_FORCE_THRESHOLD:
                anomalies.append({
                    "type": "BRUTE_FORCE",
                    "severity": "CRITICAL",
                    "source": event.source_ip,
                    "message": f"Detected {len(self.failed_logins[event.source_ip])} failed logins"
                })
                self.failed_logins[event.source_ip].clear()

        # --- 2. PORT/SERVICE SCAN DETECTOR ---
        if event.source_ip:
            self.service_scan[event.source_ip].add(event.service)
            if len(self.service_scan[event.source_ip]) >= self.SCAN_THRESHOLD:
                 anomalies.append({
                        "type": "PORT_SCAN",
                        "severity": "WARNING",
                        "source": event.source_ip,
                        "message": f"Scanned {len(self.service_scan[event.source_ip])} distinct services"
                    })
                 self.service_scan[event.source_ip].clear()

        # --- 3. LATERAL MOVEMENT DETECTOR (New) ---
        # Detects if one user is hopping across many services
        if event.user:
            self.user_services[event.user].add(event.service)
            if len(self.user_services[event.user]) >= self.LATERAL_MOVE_THRESHOLD:
                anomalies.append({
                    "type": "LATERAL_MOVEMENT",
                    "severity": "HIGH",
                    "source": event.user,
                    "message": f"User accessed {len(self.user_services[event.user])} distinct services"
                })
                self.user_services[event.user].clear()

        # --- 4. PRIVILEGE ESCALATION DETECTOR (New) ---
        # Detects failed attempts to use "sudo" or "root"
        if is_failure and event.message:
            msg_lower = event.message.lower()
            if any(kw in msg_lower for kw in self.PRIV_KEYWORDS):
                anomalies.append({
                    "type": "PRIVILEGE_ESCALATION",
                    "severity": "CRITICAL",
                    "source": event.user or event.source_ip or "unknown",
                    "message": f"Suspicious privilege failure: {event.message}"
                })

        # --- 5. SERVICE DEGRADATION (New) ---
        # Note: This is usually batch-calculated, but we can do a simple realtime check
        # If we see a CRITICAL error, flag it immediately as potential degradation
        if event.severity == "CRITICAL":
             anomalies.append({
                    "type": "SERVICE_DEGRADATION",
                    "severity": "HIGH",
                    "source": event.service,
                    "message": "Critical failure detected - potential degradation"
                })

        return anomalies

    def set_threshold(self, threshold_name: str, value: int):
        """
        Change detection thresholds at runtime.
        Example: detector.set_threshold('BRUTE_FORCE_THRESHOLD', 3)
        """
        valid_thresholds = [
            'BRUTE_FORCE_THRESHOLD',
            'BRUTE_FORCE_WINDOW',
            'SCAN_THRESHOLD',
            'LATERAL_MOVE_THRESHOLD'
        ]

        if threshold_name in valid_thresholds:
            setattr(self, threshold_name, value)
            logger.info(f"✅ Set {threshold_name} = {value}")
        else:
            logger.error(f"Unknown threshold: {threshold_name}")
            logger.info(f"Valid thresholds: {valid_thresholds}")

class AlertEngine:
    """
    The 'Voice' of the Sentinel.
    Now with severity-based formatting and file persistence.
    """

    def __init__(self, alert_log_file="alerts.jsonl"):
        self.alert_history = []
        self.alert_log_file = alert_log_file

    def fire(self, anomalies: List[Dict]):
        """Fire alerts, print them with color, and save to disk."""
        for anomaly in anomalies:
            severity = anomaly.get("severity", "UNKNOWN")
            type_name = anomaly["type"]
            source = anomaly["source"]
            message = anomaly["message"]

            # 1. Color-coded Console Output
            if severity == "CRITICAL":
                output = f"\n🔴🔴🔴 [CRITICAL ALERT] {type_name}"
            elif severity == "HIGH":
                output = f"\n🟠 [HIGH ALERT] {type_name}"
            elif severity == "WARNING":
                output = f"\n🟡 [WARNING] {type_name}"
            else:
                output = f"\n🔵 [INFO] {type_name}"

            output += f"\n    From: {source}"
            output += f"\n    {message}"
            print(output)

            # 2. Create Record
            alert_record = {
                "timestamp": datetime.now().isoformat(),
                "severity": severity,
                "type": type_name,
                "source": source,
                "message": message
            }

            # 3. Save to File (Persistence)
            self._write_alert(alert_record)
            self.alert_history.append(alert_record)

    def _write_alert(self, alert_record: Dict):
        """Append alert to log file immediately."""
        try:
            with open(self.alert_log_file, "a") as f:
                f.write(json.dumps(alert_record) + "\n")
        except IOError as e:
            logger.error(f"Failed to write alert to {self.alert_log_file}: {e}")

    def load_alerts_from_file(self):
        """Load alert history from disk on startup."""
        if not os.path.exists(self.alert_log_file):
            return []

        alerts = []
        try:
            with open(self.alert_log_file, "r") as f:
                for line in f:
                    if line.strip():
                        alerts.append(json.loads(line))
        except IOError as e:
            logger.error(f"Failed to load alerts: {e}")

        return alerts

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """
        Return recent alerts from history.
        """
        # Return last N alerts (most recent first)
        return self.alert_history[-limit:] if self.alert_history else []

    def get_alert_stats(self) -> Dict[str, Any]:
        """
        Get statistics about alerts (Severity counts, Type counts).
        """
        stats = {
            'total': len(self.alert_history),
            'by_severity': defaultdict(int),
            'by_type': defaultdict(int)
        }

        for alert in self.alert_history:
            severity = alert.get('severity', 'UNKNOWN')
            alert_type = alert.get('type', 'UNKNOWN')

            stats['by_severity'][severity] += 1
            stats['by_type'][alert_type] += 1

        # Convert defaultdict to dict for clean output
        return {
            'total': stats['total'],
            'by_severity': dict(stats['by_severity']),
            'by_type': dict(stats['by_type'])
        }

    def filter_alerts(self, severity: str = None, alert_type: str = None, limit: int = 50) -> List[Dict]:
        """
        Filter alerts by severity and/or type.
        """
        filtered = self.alert_history

        if severity:
            filtered = [a for a in filtered if a.get('severity') == severity]

        if alert_type:
            filtered = [a for a in filtered if a.get('type') == alert_type]

        # Return most recent first
        return filtered[-limit:] if filtered else []

# 🟢 MANUAL MATH TOOL
def cos_sim(a, b):
    """
    Calculates how similar two things are (0 to 1) using raw PyTorch.
    mimics sentence_transformers.util.cos_sim
    """
    import torch
    # Ensure they are tensors
    if not isinstance(a, torch.Tensor): a = torch.tensor(a)
    if not isinstance(b, torch.Tensor): b = torch.tensor(b)

    # Fix shapes if they are 1D arrays
    if len(a.shape) == 1: a = a.unsqueeze(0)
    if len(b.shape) == 1: b = b.unsqueeze(0)

    # Do the Math (Dot product of normalized vectors)
    a_norm = torch.nn.functional.normalize(a, p=2, dim=1)
    b_norm = torch.nn.functional.normalize(b, p=2, dim=1)
    return torch.mm(a_norm, b_norm.transpose(0, 1))

logger = logging.getLogger("ULTRON")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)


MODEL_NAME = "sentence-transformers/all-mpnet-base-v2"
AUTO_TAG_THRESHOLD = 0.85

INFRA_RELATIONS = {
    "status": "has_status",
    "state": "has_status",
    "latency": "has_performance",
    "depends": "depends_on",
    "requires": "depends_on",
    "triggers": "cause",
    "leads": "cause",
    "caused": "cause",
    "resulted": "cause",
    "is": "be",
    "are": "be",
    "was": "be",
    "were": "be"
}

OPPOSITES = {
    "harmful": "healthy",
    "healthy": "harmful",
    "bad": "good",
    "good": "bad",
    "dangerous": "safe",
    "safe": "dangerous",
    "stimulant": "depressant",
    "depressant": "stimulant"
}

NEGATIVE_RELATIONS = {"prevent", "stop", "block", "inhibit", "reduce", "decrease"}

@dataclass
class ConversationTurn:
    timestamp: float
    user_input: str
    agent_thought: Optional[str] = None
    agent_response: Optional[str] = None
    # This dictionary holds metadata about what the agent was waiting for (like a confirmation)
    context_state: Optional[Dict[str, Any]] = None

    def to_dict(self):
        return asdict(self)

# === Goals & Rewards ===
@dataclass
class Goal:
    name: str
    description: str
    priority: float = 1.0  # static weight of importance
    target: float = 1.0  # normalized (0..1) target
    progress: float = 0.0  # normalized progress estimate
    reward_weight: float = 1.0  # how strongly rewards affect this goal
    active: bool = True
    created_at: float = time.time()
    updated_at: float = time.time()

    def to_dict(self):
        return asdict(self)

    @staticmethod
    def from_dict(d):
        return Goal(**d)

# ============================================================================
# FORENSICS ENGINE - Investigate attacks
# ============================================================================

class ForensicsEngine:
    """
    Forensics investigation engine.
    Creates timelines, attack chains, and investigation reports.
    """

    def __init__(self, db_path="sentinel_forensics.db"):
        self.db_path = db_path
        self.conn = None
        self.init_forensics_database()

    def init_forensics_database(self):
        """Create forensics investigation tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # Investigation log table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS investigation_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                alert_id TEXT,
                investigation_type TEXT,
                timeline TEXT,
                attack_chain TEXT,
                evidence TEXT,
                confidence REAL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.conn.commit()
        logger.info("✅ Forensics database initialized")

    def create_timeline(self, workspace_id: str, events: list) -> dict:
        """Create chronological timeline of events."""
        try:
            if not events:
                return {'timeline': [], 'count': 0}

            # Sort by timestamp
            sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))

            timeline = []
            for event in sorted_events:
                timeline.append({
                    'time': event.get('timestamp', 'unknown'),
                    'type': event.get('type', 'unknown'),
                    'severity': event.get('severity', 'INFO'),
                    'details': event.get('message', ''),
                    'source': event.get('source_ip', 'unknown')
                })

            return {
                'timeline': timeline,
                'count': len(timeline),
                'start_time': timeline[0]['time'] if timeline else None,
                'end_time': timeline[-1]['time'] if timeline else None
            }
        except Exception as e:
            logger.error(f"Failed to create timeline: {e}")
            return {'timeline': [], 'count': 0, 'error': str(e)}

    def detect_attack_chain(self, workspace_id: str, events: list) -> dict:
        """Detect attack progression (attack chain)."""
        try:
            if not events or len(events) < 2:
                return {'chain': [], 'detected': False}

            chain = []
            severity_progression = []

            # Sort by timestamp
            sorted_events = sorted(events, key=lambda x: x.get('timestamp', ''))

            for event in sorted_events:
                event_type = event.get('type', 'unknown')
                severity = event.get('severity', 'INFO')
                source_ip = event.get('source_ip', 'unknown')

                severity_progression.append(severity)

                chain.append({
                    'stage': len(chain) + 1,
                    'type': event_type,
                    'severity': severity,
                    'source_ip': source_ip,
                    'time': event.get('timestamp', 'unknown')
                })

            # Detect if escalating (INFO -> WARNING -> CRITICAL)
            is_escalating = ('CRITICAL' in severity_progression and len(chain) > 1)

            return {
                'chain': chain,
                'detected': is_escalating,
                'confidence': 0.95 if is_escalating else 0.5,
                'description': f"Attack progression detected: {len(chain)} stages" if is_escalating else "No clear attack progression"
            }
        except Exception as e:
            logger.error(f"Failed to detect attack chain: {e}")
            return {'chain': [], 'detected': False, 'error': str(e)}

    def collect_evidence(self, workspace_id: str, events: list, alerts: list) -> dict:
        """Collect evidence from events and alerts."""
        try:
            evidence = {
                'total_events': len(events),
                'total_alerts': len(alerts),
                'critical_count': 0,
                'high_count': 0,
                'unique_ips': set(),
                'unique_users': set(),
                'unique_services': set(),
                'attack_types': []
            }

            for alert in alerts:
                severity = alert.get('severity', 'INFO')
                if severity == 'CRITICAL':
                    evidence['critical_count'] += 1
                elif severity == 'HIGH':
                    evidence['high_count'] += 1

                if alert.get('source_ip'):
                    evidence['unique_ips'].add(alert['source_ip'])
                if alert.get('user'):
                    evidence['unique_users'].add(alert['user'])

                alert_type = alert.get('type', 'unknown')
                if alert_type not in evidence['attack_types']:
                    evidence['attack_types'].append(alert_type)

            for event in events:
                if event.get('service'):
                    evidence['unique_services'].add(event['service'])

            return {
                'total_events': evidence['total_events'],
                'total_alerts': evidence['total_alerts'],
                'critical_alerts': evidence['critical_count'],
                'high_alerts': evidence['high_count'],
                'unique_source_ips': list(evidence['unique_ips']),
                'unique_users': list(evidence['unique_users']),
                'affected_services': list(evidence['unique_services']),
                'attack_types': evidence['attack_types'],
                'evidence_strength': 'STRONG' if evidence['critical_count'] > 0 else 'MODERATE'
            }
        except Exception as e:
            logger.error(f"Failed to collect evidence: {e}")
            return {}

    def create_investigation(self, workspace_id: str, alert_id: str, events: list, alerts: list) -> dict:
        """Create complete investigation report."""
        try:
            timeline = self.create_timeline(workspace_id, events)
            attack_chain = self.detect_attack_chain(workspace_id, events)
            evidence = self.collect_evidence(workspace_id, events, alerts)

            investigation = {
                'alert_id': alert_id,
                'workspace_id': workspace_id,
                'investigation_type': 'Incident Investigation',
                'timeline': timeline,
                'attack_chain': attack_chain,
                'evidence': evidence,
                'created_at': datetime.now().isoformat(),
                'severity': 'CRITICAL' if attack_chain['detected'] else 'HIGH',
                'status': 'COMPLETE'
            }

            self._store_investigation(investigation)
            return investigation
        except Exception as e:
            logger.error(f"Failed to create investigation: {e}")
            return {'error': str(e)}

    def _store_investigation(self, investigation: dict):
        """Store investigation in database"""
        try:
            self.conn.execute('''
                INSERT INTO investigation_log
                (workspace_id, alert_id, investigation_type, timeline, attack_chain, evidence, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (
                investigation['workspace_id'],
                investigation['alert_id'],
                investigation['investigation_type'],
                json.dumps(investigation['timeline']),
                json.dumps(investigation['attack_chain']),
                json.dumps(investigation['evidence']),
                investigation['created_at']
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to store investigation: {e}")

    def get_investigation(self, workspace_id: str, alert_id: str) -> dict:
        """Retrieve investigation by alert ID"""
        try:
            row = self.conn.execute(
                'SELECT timeline, attack_chain, evidence, created_at FROM investigation_log WHERE workspace_id = ? AND alert_id = ? ORDER BY created_at DESC LIMIT 1',
                (workspace_id, alert_id)
            ).fetchone()

            if row:
                return {
                    'timeline': json.loads(row[0]),
                    'attack_chain': json.loads(row[1]),
                    'evidence': json.loads(row[2]),
                    'created_at': row[3]
                }
            return None
        except Exception as e:
            logger.error(f"Failed to get investigation: {e}")
            return None

# ============================================================================
# THREAT INTELLIGENCE - Check if IPs are malicious
# ============================================================================

class ThreatIntelligence:
    """
    Checks IPs against threat intelligence databases.
    Uses VirusTotal API for IP reputation.
    """

    def __init__(self, db_path="sentinel_threat_intel.db"):
        self.db_path = db_path
        self.conn = None
        self.init_threat_intel_database()

        # VirusTotal API (free tier available)
        self.vt_api_key = None  # Set your API key here: https://www.virustotal.com/gui/my-apikey
        self.vt_enabled = False

        # Cache for lookups
        self.cache = {}

    def init_threat_intel_database(self):
        """Create threat intel cache tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # IP reputation cache table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS ip_reputation (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT UNIQUE NOT NULL,
                is_malicious INTEGER,
                confidence REAL,
                threat_types TEXT,
                source TEXT,
                last_checked DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME
            )
        ''')

        # Threat intel lookups history table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS threat_intel_lookups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                is_malicious INTEGER,
                confidence REAL,
                details TEXT,
                looked_up_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.conn.commit()
        logger.info("✅ Threat intelligence database initialized")

    def enable_virustotal(self, api_key: str):
        """Enable VirusTotal API for real threat intelligence"""
        self.vt_api_key = api_key
        self.vt_enabled = True
        logger.info("✅ VirusTotal enabled for threat intelligence")

    def check_ip(self, ip: str, workspace_id: str = "default") -> dict:
        """
        Check if IP is malicious.
        Returns: { 'ip': '...', 'is_malicious': True, ... }
        """
        # 1. Check cache first
        cached = self._get_from_cache(ip)
        if cached:
            self._log_lookup(workspace_id, ip, cached['is_malicious'], cached['confidence'])
            return cached

        # 2. Check database cache
        db_cached = self._get_from_db_cache(ip)
        if db_cached:
            self._log_lookup(workspace_id, ip, db_cached['is_malicious'], db_cached['confidence'])
            return db_cached

        # 3. Check VirusTotal if enabled
        if self.vt_enabled:
            result = self._check_virustotal(ip)
        else:
            # Default: Use simple heuristics
            result = self._check_heuristics(ip)

        # 4. Cache the result
        self._add_to_cache(ip, result)
        self._add_to_db_cache(ip, result)

        # 5. Log lookup
        self._log_lookup(workspace_id, ip, result['is_malicious'], result['confidence'])

        return result

    def _check_heuristics(self, ip: str) -> dict:
        """Basic IP reputation heuristics (no API required)"""
        is_malicious = False
        threat_types = []
        confidence = 0.0

        # Check private IPs (usually not malicious in enterprise context)
        if self._is_private_ip(ip):
            confidence = 0.0
            is_malicious = False
        else:
            # Mark as low confidence without real intel
            confidence = 0.1
            is_malicious = False

        return {
            'ip': ip,
            'is_malicious': is_malicious,
            'confidence': confidence,
            'threat_types': threat_types,
            'source': 'Heuristics (Real-time intel disabled)',
            'details': 'Enable VirusTotal API for real threat intelligence'
        }

    def _check_virustotal(self, ip: str) -> dict:
        """Check IP reputation on VirusTotal"""
        try:
            headers = {'x-apikey': self.vt_api_key}
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'

            response = requests.get(url, headers=headers, timeout=5)

            if response.status_code != 200:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return self._check_heuristics(ip)

            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})

            # Count malicious verdicts
            last_analysis_stats = attributes.get('last_analysis_stats', {})
            malicious_count = last_analysis_stats.get('malicious', 0)
            total_vendors = sum(last_analysis_stats.values())

            is_malicious = malicious_count > 0
            confidence = malicious_count / max(total_vendors, 1) if total_vendors > 0 else 0

            # Get threat types
            threat_types = []
            last_analysis_results = attributes.get('last_analysis_results', {})
            for vendor, result in last_analysis_results.items():
                if result.get('category') != 'undetected':
                    threat_types.append(result.get('category', 'unknown'))

            threat_types = list(set(threat_types))  # Remove duplicates

            return {
                'ip': ip,
                'is_malicious': is_malicious,
                'confidence': confidence,
                'threat_types': threat_types[:5],  # Top 5 threat types
                'source': 'VirusTotal',
                'details': f'{malicious_count}/{total_vendors} vendors detected as malicious'
            }

        except Exception as e:
            logger.error(f"VirusTotal check failed: {e}")
            return self._check_heuristics(ip)

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (RFC 1918)"""
        try:
            parts = [int(p) for p in ip.split('.')]
            if len(parts) != 4:
                return False

            # Check private ranges
            if parts[0] == 10:
                return True
            if parts[0] == 172 and 16 <= parts[1] <= 31:
                return True
            if parts[0] == 192 and parts[1] == 168:
                return True
            if parts[0] == 127: # Localhost
                return True

            return False
        except:
            return False

    def _get_from_cache(self, ip: str) -> dict:
        """Get IP reputation from in-memory cache"""
        return self.cache.get(ip)

    def _add_to_cache(self, ip: str, result: dict):
        """Add IP reputation to in-memory cache"""
        self.cache[ip] = result

    def _get_from_db_cache(self, ip: str) -> dict:
        """Get IP reputation from database cache"""
        try:
            row = self.conn.execute(
                'SELECT is_malicious, confidence, threat_types, source FROM ip_reputation WHERE ip_address = ? AND (expires_at IS NULL OR expires_at > ?)',
                (ip, datetime.now())
            ).fetchone()

            if row:
                return {
                    'ip': ip,
                    'is_malicious': bool(row[0]),
                    'confidence': row[1],
                    'threat_types': row[2].split(',') if row[2] else [],
                    'source': row[3]
                }
            return None
        except Exception as e:
            logger.error(f"Failed to get from DB cache: {e}")
            return None

    def _add_to_db_cache(self, ip: str, result: dict):
        """Add IP reputation to database cache"""
        try:
            from datetime import timedelta
            expires_at = datetime.now() + timedelta(days=7)  # Cache for 7 days

            self.conn.execute('''
                INSERT OR REPLACE INTO ip_reputation
                (ip_address, is_malicious, confidence, threat_types, source, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                ip,
                int(result['is_malicious']),
                result['confidence'],
                ','.join(result.get('threat_types', [])),
                result['source'],
                expires_at
            ))

            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to add to DB cache: {e}")

    def _log_lookup(self, workspace_id: str, ip: str, is_malicious: bool, confidence: float):
        """Log threat intel lookup"""
        try:
            self.conn.execute('''
                INSERT INTO threat_intel_lookups (workspace_id, ip_address, is_malicious, confidence)
                VALUES (?, ?, ?, ?)
            ''', (workspace_id, ip, int(is_malicious), confidence))

            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to log lookup: {e}")

    def get_lookup_history(self, workspace_id: str, limit: int = 100) -> list:
        """Get threat intel lookup history"""
        try:
            rows = self.conn.execute(
                'SELECT ip_address, is_malicious, confidence, looked_up_at FROM threat_intel_lookups WHERE workspace_id = ? ORDER BY looked_up_at DESC LIMIT ?',
                (workspace_id, limit)
            ).fetchall()

            return [
                {
                    'ip': row[0],
                    'is_malicious': bool(row[1]),
                    'confidence': row[2],
                    'timestamp': row[3]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to get lookup history: {e}")
            return []

#================================================
# BLOCKLIST MANAGER - Track blocked IPs and users
#===============================================

class BlocklistManager:
    """
    Manages blocklist of IPs and users that should be blocked.
    Prevents repeated attacks from same source.
    """

    def __init__(self, db_path="sentinel_blocklist.db"):
        self.db_path = db_path
        self.conn = None
        self.init_blocklist_database()

    def init_blocklist_database(self):
        """Create blocklist tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # Blocklist table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS blocklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                block_type TEXT NOT NULL,
                block_value TEXT NOT NULL,
                reason TEXT,
                severity TEXT,
                auto_block INTEGER DEFAULT 1,
                blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                UNIQUE(workspace_id, block_type, block_value)
            )
        ''')

        # Response history table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS response_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                alert_id TEXT,
                action_type TEXT NOT NULL,
                target TEXT,
                status TEXT,
                details TEXT,
                executed_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        self.conn.commit()
        logger.info("✅ Blocklist database initialized")

    def add_to_blocklist(self, workspace_id: str, block_type: str, block_value: str,
                        reason: str = "", severity: str = "CRITICAL", expires_hours: int = 24) -> bool:
        """
        Add IP or user to blocklist.
        """
        try:
            from datetime import timedelta
            expires_at = datetime.now() + timedelta(hours=expires_hours)

            self.conn.execute('''
                INSERT OR REPLACE INTO blocklist
                (workspace_id, block_type, block_value, reason, severity, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (workspace_id, block_type.lower(), block_value, reason, severity, expires_at))

            self.conn.commit()
            logger.info(f"✅ Added to blocklist: {block_type}={block_value} ({reason})")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to add to blocklist: {e}")
            return False

    def is_blocked(self, workspace_id: str, block_type: str, block_value: str) -> bool:
        """Check if IP/user is currently blocked"""
        try:
            row = self.conn.execute('''
                SELECT id FROM blocklist
                WHERE workspace_id = ? AND block_type = ? AND block_value = ?
                AND (expires_at IS NULL OR expires_at > ?)
            ''', (workspace_id, block_type.lower(), block_value, datetime.now())).fetchone()

            return row is not None

        except Exception as e:
            logger.error(f"Failed to check blocklist: {e}")
            return False

    def get_blocklist(self, workspace_id: str, block_type: str = None) -> list:
        """Get all blocked items for workspace"""
        try:
            if block_type:
                rows = self.conn.execute('''
                    SELECT block_type, block_value, reason, severity, blocked_at, expires_at
                    FROM blocklist
                    WHERE workspace_id = ? AND block_type = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                    ORDER BY blocked_at DESC
                ''', (workspace_id, block_type.lower(), datetime.now())).fetchall()
            else:
                rows = self.conn.execute('''
                    SELECT block_type, block_value, reason, severity, blocked_at, expires_at
                    FROM blocklist
                    WHERE workspace_id = ?
                    AND (expires_at IS NULL OR expires_at > ?)
                    ORDER BY blocked_at DESC
                ''', (workspace_id, datetime.now())).fetchall()

            return [
                {
                    'type': row[0],
                    'value': row[1],
                    'reason': row[2],
                    'severity': row[3],
                    'blocked_at': row[4],
                    'expires_at': row[5]
                }
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Failed to get blocklist: {e}")
            return []

    def remove_from_blocklist(self, workspace_id: str, block_type: str, block_value: str) -> bool:
        """Remove from blocklist (whitelist)"""
        try:
            self.conn.execute('''
                DELETE FROM blocklist
                WHERE workspace_id = ? AND block_type = ? AND block_value = ?
            ''', (workspace_id, block_type.lower(), block_value))

            self.conn.commit()
            logger.info(f"✅ Removed from blocklist: {block_type}={block_value}")
            return True

        except Exception as e:
            logger.error(f"Failed to remove from blocklist: {e}")
            return False

    def log_response(self, workspace_id: str, action_type: str, target: str,
                    status: str = "success", details: str = "") -> bool:
        """Log automated response for audit trail"""
        try:
            self.conn.execute('''
                INSERT INTO response_history
                (workspace_id, action_type, target, status, details)
                VALUES (?, ?, ?, ?, ?)
            ''', (workspace_id, action_type, target, status, details))

            self.conn.commit()
            return True

        except Exception as e:
            logger.error(f"Failed to log response: {e}")
            return False

    def get_response_history(self, workspace_id: str, limit: int = 100) -> list:
        """Get history of automated responses"""
        try:
            rows = self.conn.execute('''
                SELECT action_type, target, status, details, executed_at
                FROM response_history
                WHERE workspace_id = ?
                ORDER BY executed_at DESC
                LIMIT ?
            ''', (workspace_id, limit)).fetchall()

            return [
                {
                    'action': row[0],
                    'target': row[1],
                    'status': row[2],
                    'details': row[3],
                    'timestamp': row[4]
                }
                for row in rows
            ]

        except Exception as e:
            logger.error(f"Failed to get response history: {e}")
            return []

# JIRA CONNECTOR - Create tickets automatically
class JiraConnector:
    """
    Creates Jira tickets automatically when critical alerts fire.
    """

    def __init__(self, jira_url: str = None, api_token: str = None, project_key: str = "SEC"):
        self.jira_url = jira_url
        self.api_token = api_token
        self.project_key = project_key
        self.enabled = jira_url and api_token

    def create_ticket(self, alert_type: str, source: str, message: str,
                     severity: str = "CRITICAL") -> dict:
        if not self.enabled:
            return {'status': 'skipped', 'reason': 'Not configured'}

        try:
            import requests
            # Simple priority mapping
            priority_map = {'CRITICAL': 'Highest', 'HIGH': 'High', 'WARNING': 'Medium'}

            issue_data = {
                'fields': {
                    'project': {'key': self.project_key},
                    'summary': f'[{severity}] {alert_type} from {source}',
                    'description': f'Auto-Created by Sentinel.\nType: {alert_type}\nMessage: {message}',
                    'issuetype': {'name': 'Task'}, # Default to Task usually works
                    'priority': {'name': priority_map.get(severity, 'Medium')},
                }
            }

            response = requests.post(
                f"{self.jira_url}/rest/api/3/issues",
                auth=(self.api_token.split(':')[0], self.api_token.split(':')[1]),
                json=issue_data,
                timeout=5
            )

            if response.status_code in [200, 201]:
                return {'status': 'success', 'ticket_id': response.json().get('key')}
            return {'status': 'error', 'message': response.text}

        except Exception as e:
            return {'status': 'error', 'message': str(e)}


    # RESPONSE RULES

RESPONSE_RULES = {
    'BRUTE_FORCE': {
        'auto_block_ip': True,
        'block_duration_hours': 24,
        'create_jira': True,
        'send_slack': True,
        'slack_channel': '#security-alerts',
    },
    'LATERAL_MOVEMENT': {
        'auto_block_ip': True,
        'block_duration_hours': 24,
        'create_jira': True,
        'send_slack': True,
        'slack_channel': '#security-critical',
    },
    'PRIVILEGE_ESCALATION': {
        'auto_block_ip': True,
        'block_duration_hours': 48,
        'create_jira': True,
        'send_slack': True,
    },
    'PORT_SCAN': {
        'auto_block_ip': True,
        'block_duration_hours': 12,
        'create_jira': False,
        'send_slack': True,
    },
    'SERVICE_DEGRADATION': {
        'auto_block_ip': False,
        'create_jira': True,
        'send_slack': True,
    }
}


# RESPONSE AUTOMATION - Main orchestrator

class ResponseAutomation:
    def __init__(self, blocklist_manager: BlocklistManager, jira_connector: JiraConnector = None):
        self.blocklist = blocklist_manager
        self.jira = jira_connector
        self.rules = RESPONSE_RULES

    def respond_to_alert(self, alert: dict, workspace_id: str) -> dict:
        alert_type = alert.get('type', 'UNKNOWN')
        source = alert.get('source', 'unknown')
        message = alert.get('message', '')
        severity = alert.get('severity', 'WARNING')

        rule = self.rules.get(alert_type)
        if not rule:
            return {'status': 'skipped', 'reason': 'No rule defined'}

        responses = []

        # 1. Block IP
        if rule.get('auto_block_ip') and source != 'unknown':
            # Add to blocklist
            success = self.blocklist.add_to_blocklist(
                workspace_id=workspace_id,
                block_type='ip',
                block_value=source,
                reason=f'Auto-blocked: {alert_type}',
                severity=severity,
                expires_hours=rule.get('block_duration_hours', 24)
            )
            self.blocklist.log_response(
                workspace_id, 'BLOCK_IP', source,
                'success' if success else 'failed', f'Due to {alert_type}'
            )
            responses.append({'action': 'BLOCK_IP', 'status': success})

        # 2. Jira
        if rule.get('create_jira') and self.jira and self.jira.enabled:
            res = self.jira.create_ticket(alert_type, source, message, severity)
            responses.append({'action': 'JIRA', 'result': res})

        # 3. Slack is handled by the existing pipeline, so we skip it here to avoid duplicates.

        return {'status': 'success', 'responses': responses}



# ROLE DEFINITIONS & PERMISSIONS

ROLE_PERMISSIONS = {
    'admin': {
        'read:events': True,
        'read:alerts': True,
        'create:analysis': True,
        'manage:users': True,  # Invite/Remove users
        'view:audit': True,
    },
    'analyst': {
        'read:events': True,
        'read:alerts': True,
        'create:analysis': True, # Can upload logs
        'manage:users': False,
        'view:audit': False,
    },
    'viewer': {
        'read:events': True,
        'read:alerts': True,
        'create:analysis': False, # Read-only
        'manage:users': False,
        'view:audit': False,
    }
}

def has_permission(role: str, action: str) -> bool:
    """Check if a role has permission for an action."""
    return ROLE_PERMISSIONS.get(role, {}).get(action, False)

class WorkspaceManager:
    """
    Manages workspaces (isolated environments for each company/team).
    Each workspace has its own events, alerts, and knowledge.
    """
    def __init__(self, db_path="sentinel_workspaces.db"):
        self.db_path = db_path
        self.conn = None
        self.init_workspace_database()

    def init_workspace_database(self):
        """Create workspaces, users, and audit_log tables"""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # Workspaces table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS workspaces (
                id TEXT PRIMARY KEY,
                name TEXT UNIQUE NOT NULL,
                owner_id INTEGER NOT NULL,
                description TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')

        # Users table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                workspace_id TEXT NOT NULL,
                role TEXT DEFAULT 'analyst',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
            )
        ''')

        # 🟢 NEW: Login attempts tracking
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS login_attempts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                attempt_time DATETIME DEFAULT CURRENT_TIMESTAMP,
                success INTEGER DEFAULT 0
            )
        ''')

        # 🟢 NEW: Password reset tokens
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS password_reset_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                token TEXT UNIQUE NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expires_at DATETIME,
                used INTEGER DEFAULT 0
            )
        ''')
        self.conn.commit()

        # Audit log table
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                user_id INTEGER,
                action TEXT NOT NULL,
                target_user TEXT,
                details TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(workspace_id) REFERENCES workspaces(id)
            )
        ''')

        self.conn.commit()
        logger.info("✅ Workspace database initialized")

    def _hash_password(self, password):
        """Simple SHA256 hashing to avoid plain-text storage."""
        return hashlib.sha256(password.encode()).hexdigest()

    def create_workspace(self, workspace_name: str, owner_id: int, description: str = "") -> str:
        workspace_id = str(uuid.uuid4())[:8]
        try:
            self.conn.execute('''
                INSERT INTO workspaces (id, name, owner_id, description)
                VALUES (?, ?, ?, ?)
            ''', (workspace_id, workspace_name, owner_id, description))
            self.conn.commit()
            return workspace_id
        except Exception as e:
            return None

    def create_user(self, username: str, password: str, email: str, workspace_id: str, role: str = 'analyst') -> bool:
        """
        Create a new user in workspace.
        """
        try:
            # 🟢 FIX IS HERE: Hash the password before storing it!
            hashed_pw = self._hash_password(password)

            self.conn.execute('''
                INSERT INTO users (username, password_hash, email, workspace_id, role)
                VALUES (?, ?, ?, ?, ?)
            ''', (username, hashed_pw, email, workspace_id, role))

            # Log audit event
            self.conn.execute('''
                INSERT INTO audit_log (workspace_id, action, target_user, created_at)
                VALUES (?, ?, ?, ?)
            ''', (workspace_id, f'USER_CREATED:{role}', username, datetime.now()))

            self.conn.commit()
            logger.info(f"✅ User created: {username} ({role}) in workspace {workspace_id}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to create user: {e}")
            return False

    def verify_user(self, username: str, password: str) -> dict:
        try:
            # This hashes the input to compare against the stored hash
            hashed_pw = self._hash_password(password)

            row = self.conn.execute(
                'SELECT id, username, password_hash, email, workspace_id, role FROM users WHERE username = ?',
                (username,)
            ).fetchone()

            # Now both are hashes, so they should match
            if row and row[2] == hashed_pw:
                ws_row = self.conn.execute('SELECT name FROM workspaces WHERE id = ?', (row[4],)).fetchone()
                ws_name = ws_row[0] if ws_row else "Unknown"

                return {
                    'id': row[0],
                    'username': row[1],
                    'email': row[3],
                    'workspace_id': row[4],
                    'workspace_name': ws_name,
                    'role': row[5]
                }
            return None
        except Exception:
            return None

    # 🟢 NEW: Security Methods
    def check_login_attempts(self, username: str) -> dict:
        """Check if user is locked out"""
        try:
            from datetime import datetime, timedelta
            # 🟢 FIX: Use datetime.utcnow() to match SQLite's UTC timestamp
            cutoff_time = datetime.utcnow() - timedelta(minutes=30)

            # Count failed attempts in last 30 mins
            row = self.conn.execute('''
                SELECT COUNT(*) FROM login_attempts
                WHERE username = ? AND success = 0 AND attempt_time > ?
            ''', (username, cutoff_time)).fetchone()

            failed_attempts = row[0] if row else 0

            if failed_attempts >= 5:
                return {
                    'locked': True,
                    'failed_attempts': failed_attempts,
                    'message': f'Account locked. Too many failed attempts. Try again in 30 minutes.'
                }
            return {'locked': False, 'failed_attempts': failed_attempts, 'remaining_attempts': 5 - failed_attempts}
        except Exception as e:
            logger.error(f"Failed to check login attempts: {e}")
            return {'locked': False, 'failed_attempts': 0}

    def record_login_attempt(self, username: str, success: bool = False):
        try:
            self.conn.execute('INSERT INTO login_attempts (username, success) VALUES (?, ?)', (username, int(success)))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to record login attempt: {e}")

    def reset_login_attempts(self, username: str):
        try:
            self.conn.execute('DELETE FROM login_attempts WHERE username = ?', (username,))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to reset login attempts: {e}")

    def create_password_reset_token(self, username: str) -> str:
        try:
            import secrets
            from datetime import datetime, timedelta
            token = secrets.token_urlsafe(32)
            expires_at = datetime.now() + timedelta(hours=1)
            self.conn.execute('INSERT INTO password_reset_tokens (username, token, expires_at) VALUES (?, ?, ?)', (username, token, expires_at))
            self.conn.commit()
            return token
        except Exception as e:
            logger.error(f"Failed to create token: {e}")
            return None

    def reset_password(self, token: str, new_password: str) -> bool:
        try:
            from datetime import datetime
            row = self.conn.execute('SELECT username FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > ?', (token, datetime.now())).fetchone()
            if not row: return False

            username = row[0]
            self.conn.execute('UPDATE users SET password_hash = ? WHERE username = ?', (new_password, username))
            self.conn.execute('UPDATE password_reset_tokens SET used = 1 WHERE token = ?', (token,))
            self.conn.commit()
            return True
        except Exception as e:
            logger.error(f"Failed to reset password: {e}")
            return False

    def get_workspace(self, workspace_id: str) -> dict:
        try:
            row = self.conn.execute('SELECT id, name FROM workspaces WHERE id = ?', (workspace_id,)).fetchall()
            if row:
                return {'id': row[0][0], 'name': row[0][1]} # Fixed tuple indexing
            return None
        except Exception:
            return None

class Brain:
    def __init__(
        self,
        memory_file="memory.json",
        reasoning_file=None,
        start_worker: bool = True,
    ):
        self.memory_file = os.path.abspath(memory_file)
        # --- Reasoning memory file path (default next to memory_file) ---
        if reasoning_file is None:
            self.reasoning_file = os.path.join(
                os.path.dirname(self.memory_file), "reasoning_memory.json"
            )
        else:
            self.reasoning_file = os.path.abspath(reasoning_file)

        # 🟢 NEW: Initialize Workspace Manager
        self.workspace_manager = WorkspaceManager()

        # 🟢 NEW: Initialize Response Automation
        self.blocklist_manager = BlocklistManager()
        self.jira_connector = JiraConnector(
            jira_url=None, # Configure these if you have Jira
            api_token=None
        )
        self.response_automation = ResponseAutomation(
            self.blocklist_manager,
            self.jira_connector
        )

        # 🟢 NEW: Threat Intelligence
        self.threat_intelligence = ThreatIntelligence()
        logger.info("🔍 Threat intelligence initialized")

        #Forensic
        self.forensics_engine = ForensicsEngine()
        logger.info("🔎 Forensics engine initialized")

        # --- Core state ---
        self.knowledge: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
        self.reasoning_memory: List[Dict[str, Any]] = []
        self.short_term_memory: List[Dict[str, Any]] = []
        self.short_term_limit = 200
        self.uncertainty_memory: List[Dict[str, Any]] = []
        self.self_evaluation_log: List[Any] = []
        self.causal_graph: Dict[str, List[Tuple[str, str]]] = defaultdict(list)
        self.reverse_causal_graph: Dict[str, List[Tuple[str, str]]] = defaultdict(list)

        # 🟢 NEW: Initialize the Reflexes
        self.anomaly_detector = AnomalyDetector()
        self.alert_engine = AlertEngine()

        # 🟢 NEW: Deduplication Memory
        # Key: (service, message) -> Value: {count, last_seen}
        self.event_fingerprints: Dict[Tuple, Dict] = {}

        # Load previous alerts so we remember them after restart
        self.alert_engine.alert_history = self.alert_engine.load_alerts_from_file()
        logger.info(f"🛡️ Sentinel Memory: Loaded {len(self.alert_engine.alert_history)} past alerts.")

        # --- Threading ---
        self.lock = threading.RLock()

        # --- Model (set later in _ensure_model) ---
        self.model = None  # ✅ Fix: ensure attribute always exists
        self._embedding_cache: Dict[str, Any] = {}
        self._last_prediction = None

        # 🟢 NEW: The Voice Box
        self.active_thought: Optional[str] = None

        # 🟢 NEW: The Conversation Stack (Episodic Memory)
        # This holds the last 20 turns of conversation, so he remembers context.
        self.episodic_buffer: Deque[ConversationTurn] = deque(maxlen=20)

        # --- Lemmatizer (safe fallback) ---
        try:
            self.lemmatizer = WordNetLemmatizer()
            _ = self.lemmatizer.lemmatize("tests", pos="n")
        except (LookupError, ImportError) as e:
            logger.warning(
                "NLTK wordnet not available (%s); falling back to identity lemmatization.",
                e,
                exc_info=True,
            )

            class _IdLemma:
                def lemmatize(self, w, _pos=None):
                    return w or ""

            self.lemmatizer = _IdLemma()

        # --- Concept handling ---
        self.concept_to_subjects: Dict[str, Set[str]] = defaultdict(set)
        self.concept_aliases = {
            "critical": "failure",
            "error": "failure",
            "refused": "failure",
            "offline": "failure",
            "latency": "degradation",
            "slow": "degradation",
            "warn": "degradation",
        }

        # --- Reward system (must exist before any load/persist) ---
        self.reward_total: float = 0.0
        self.reward_history: List[Tuple[float, float, str, Optional[Dict[str, Any]]]] = []
        self.recent_rewards: Deque[Tuple[float, float, str, Dict[str, Any]]] = deque(maxlen=200)
        self.recent_actions: Deque[Tuple[float, str, Dict[str, Any]]] = deque(maxlen=200)
        self.policy_cooldowns: Dict[str, float] = defaultdict(float)  # action -> earliest ts

        # --- Healing state ---
        self.healing_queue: List[str] = []
        self._healing_in_progress: Set[str] = set()
        self._pending_review: Set[str] = set()
        self._conflict_set: Set[str] = set()
        self._junk_concepts: Set[str] = set()
        self._retry_counters: Dict[str, int] = defaultdict(int)
        self._max_retries: int = 5
        self._cooldown_after_pause: float = 120.0
        self._review_eta: Dict[str, float] = {}
        self._last_heal_attempt: Dict[str, float] = {}
        self._learn_count: int = 0
        self._evaluate_every: int = 3
        self._healing_interval: float = 3.0
        self._stop_healing_worker: bool = False
        self._extra_healing_depth: int = 4

        # --- Goals ---
        self.goals: Dict[str, Goal] = {}

        # --- Thresholds ---
        self.PREDICTION_THRESHOLD = 0.85
        self.SIMILARITY_THRESHOLD = 0.85
        self.CLUSTER_THRESHOLD = 0.85

        # 🟢 NEW: Database Startup
        self._init_db()

        # --- Persistence (after rewards/goals are initialized) ---
        self.load_memory()
        self._ensure_default_goals()
        self.load_reasoning_memory()

        self.rebuild_causal_graph()

        # 🟢 UPGRADE: SQLite Long-Term Memory
        self.db_path = "sentinel_events.db"
        self.conn = None
        self.init_event_database()

        # 🟢 UPGRADE: Threshold configuration
        self.detector_config = {
            'BRUTE_FORCE_THRESHOLD': 5,
            'BRUTE_FORCE_WINDOW': 60,
            'SCAN_THRESHOLD': 3,
            'LATERAL_MOVE_THRESHOLD': 5
        }

        # Apply config to detector
        for key, value in self.detector_config.items():
            self.anomaly_detector.set_threshold(key, value)

        # --- Worker thread (optional) ---
        if start_worker:
            self._healing_thread = threading.Thread(
                target=self._self_healing_worker, daemon=True
            )
            self._healing_thread.start()

    def _init_db(self):
        """Initialize SQLite tables for Knowledge and Goals."""
        with self.lock:
            self.conn = sqlite3.connect("brain.db", check_same_thread=False)
            self.cursor = self.conn.cursor()

            # 1. Knowledge Table (The Triplets)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS knowledge (
                    subject TEXT,
                    relation TEXT,
                    object TEXT,
                    score REAL,
                    concept TEXT,
                    last_updated REAL,
                    PRIMARY KEY (subject, relation, object)
                )
            ''')

            # 2. Goals Table
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS goals (
                    name TEXT PRIMARY KEY,
                    data TEXT  -- JSON blob of the goal attributes
                )
            ''')

            # 🟢 NEW: Reasoning Table (Replaces reasoning_memory.json)
            self.cursor.execute('''
                CREATE TABLE IF NOT EXISTS reasoning (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    subject TEXT,
                    concept TEXT,
                    explanation TEXT,
                    score REAL,
                    last_updated REAL
                )
            ''')

            self.conn.commit()

    def _canonicalize_relation(self, rel: str) -> str:
        r = (rel or "").strip().lower()
        return INFRA_RELATIONS.get(r, r)

    def get_snapshot(self):
        with self.lock:
            return copy.deepcopy(self.knowledge)

    def _safe_update_knowledge(self, subject: str, relation: str, obj: str, entry: Dict[str, Any]) -> None:
        with self.lock:
            cur_entry = (
                self.knowledge
                .setdefault(subject, {})
                .setdefault(relation, {})
                .get(obj)
            )
            if cur_entry and isinstance(cur_entry, dict):
                # ✅ keep explicit user tag if present
                val = cur_entry.get("concept")
                if isinstance(val, str) and val.strip():
                    entry["concept"] = val

            # store/update
            self.knowledge[subject][relation][obj] = entry

        # --- Goal helpers ---

    def _ensure_default_goals(self):
        defaults = [
            Goal(
                name="detect_anomaly",
                description="Identify and correlate critical system failures and security events.",
                priority=1.5,
                target=1.0,
                progress=0.1,
                reward_weight=1.5,
            ),
            Goal(
                name="map_dependencies",
                description="Build a high-confidence graph of service dependencies and causal links.",
                priority=1.3,
                target=1.0,
                progress=0.0,
                reward_weight=1.2,
            ),
            Goal(
                name="reduce_latency_noise",
                description="Filter out minor fluctuations to focus on persistent performance degradation.",
                priority=1.1,
                target=1.0,
                progress=0.0,
                reward_weight=1.0,
            ),
            Goal(
                name="verify_system_integrity",
                description="Ensure knowledge graph matches current server status logs.",
                priority=1.2,
                target=1.0,
                progress=0.5,
                reward_weight=1.1,
            )
        ]
        for g in defaults:
            if g.name not in self.goals:
                self.goals[g.name] = g

    def _estimate_goal_progress(self):
        """Recompute rough progress signals from current state."""
        try:
            # Reduce uncertainty: fewer uncertainty logs in recent window
            recent_unc = (
                len(self.uncertainty_memory[-100:]) if self.uncertainty_memory else 0
            )
            unc_progress = max(0.0, 1.0 - min(1.0, recent_unc / 100.0))
            self._set_goal_progress("reduce_uncertainty", unc_progress)

            # Increase consistency: fewer conflicts
            conflicts = len(self._conflict_set) if hasattr(self, "_conflict_set") else 0
            cons_progress = max(0.0, 1.0 - min(1.0, conflicts / 50.0))
            self._set_goal_progress("increase_consistency", cons_progress)

            # Expand knowledge: edges with score >= 1 over a nominal size
            snapshot = self.get_snapshot()
            high_score_edges = 0
            total_edges = 0
            for _, rels in snapshot.items():
                for _, objs in rels.items():
                    for _, data in objs.items():
                        if isinstance(data, dict):
                            total_edges += 1
                            if float(data.get("score", 0)) >= 1.0:
                                high_score_edges += 1
            exp_progress = (
                (high_score_edges / max(1, total_edges)) if total_edges else 0.0
            )
            self._set_goal_progress("expand_knowledge", exp_progress)

            # Prediction accuracy: average of last accepted prediction scores
            preds = [
                e.get("score", 0)
                for e in self.reasoning_memory[-200:]
                if isinstance(e, dict)
                and any(
                    "Learned concept mapping via prediction." in (x or "")
                    for x in e.get("explanation", [])
                )
            ]
            avg_pred = sum(preds) / len(preds) if preds else 0.0
            self._set_goal_progress("improve_prediction_accuracy", min(1.0, avg_pred))

        except (KeyError, ValueError, TypeError) as e:
            logger.error("Error while estimating goal progress: %s", e, exc_info=True)

    def _set_goal_progress(self, name, value):
        g = self.goals.get(name)
        if g:
            g.progress = float(max(0.0, min(1.0, value)))
            g.updated_at = time.time()

    def add_goal(
        self,
        name,
        description=None,
        priority=1.0,
        target=1.0,
        reward_weight=1.0,
        active=True,
    ):
        """
        Create or update a goal. Description is optional.
        Falls back to a default description (if known) or the goal name.
        """
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Goal name must be a non-empty string.")
        name = name.strip()

        # Default description if not provided
        if (
            description is None
            or not isinstance(description, str)
            or not description.strip()
        ):
            description = getattr(self, "_default_goal_descs", {}).get(name, name)

        g = Goal(
            name=name,
            description=description,
            priority=float(priority),
            target=float(target),
            reward_weight=float(reward_weight),
            active=bool(active),
        )

        with self.lock:
            self.goals[name] = g

        # Persist just the goals into the memory blob (non-fatal if it fails)
        try:
            self.save_memory()
        except (OSError, IOError, ValueError) as e:
            logger.warning(
                "Failed to persist goals after add_goal('%s'): %s", name, e, exc_info=True
            )

        return g

    def set_goal_active(self, name, active=True):
        if name in self.goals:
            self.goals[name].active = bool(active)
            self.goals[name].updated_at = time.time()
            self.save_memory()

        # --- Goal persistence ---
    def _ensure_model(self):
        # Disabled local PyTorch loading to save 1GB RAM.
        # We now rely on Ollama for embeddings.
        pass

    def normalize_concept(self, concept: Optional[str]) -> str:
        if not concept:
            return ""
        concept = concept.strip().lower()
        if concept in self.concept_aliases:
            return self.concept_aliases[concept].lower()
        for entry in self.reasoning_memory:
            known = entry.get("concept")
            alias = entry.get("alias")
            if isinstance(alias, str) and alias.strip().lower() == concept:
                if isinstance(known, str):
                    return known.strip().lower()
        return concept

    def init_event_database(self):
        """Initialize SQLite database for event storage with Multi-Tenancy."""
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)

        # Create events table with workspace_id
        self.conn.execute('''
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workspace_id TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                severity TEXT NOT NULL,
                service TEXT NOT NULL,
                message TEXT NOT NULL,
                source_ip TEXT,
                user TEXT,
                error_code TEXT,
                raw_data TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        # Indexes for speed
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_workspace ON events(workspace_id)')
        self.conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
        self.conn.commit()

    def store_event(self, event: LogEvent, workspace_id: str = "default"):
        """Store parsed event in SQLite assigned to a specific workspace."""
        try:
            self.conn.execute('''
                INSERT INTO events (workspace_id, timestamp, severity, service, message, source_ip, user, error_code, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                workspace_id,
                event.timestamp, event.severity, event.service, event.message,
                event.source_ip, event.user, event.error_code, event.raw
            ))
            self.conn.commit()
        except Exception as e:
            logger.error(f"Failed to store event: {e}")

    def query_events(self, workspace_id: str = "default", filters: dict = None, limit: int = 1000) -> list:
        """Query historical events scoped to a workspace."""
        query = 'SELECT * FROM events WHERE workspace_id = ?'
        params = [workspace_id]

        if filters:
            if 'start_time' in filters:
                query += ' AND timestamp >= ?'
                params.append(filters['start_time'])

        query += ' ORDER BY timestamp DESC LIMIT ?'
        params.append(limit)

        try:
            self.conn.row_factory = sqlite3.Row
            cursor = self.conn.execute(query, params)
            return [dict(row) for row in cursor.fetchall()]
        except Exception as e:
            logger.error(f"Query failed: {e}")
            return []

    def _learn_from_logs(self, raw_log_data):
        """
        PHASE 3 PIPELINE: Parse -> Store -> Detect -> Alert -> Deduplicate -> Learn.
        """
        parser = LogParser()
        count = 0
        new_knowledge_count = 0

        for line in raw_log_data.split('\n'):
            event = parser.parse(line)
            if not event: continue

            # 🟢 NEW: Store in Long-Term Memory (Database)
            # We do this first so we never lose data, even if it's a duplicate
            self.store_event(event)

            # 🟢 1. DETECT ANOMALIES (Before deduplication!)
            # We want to catch Brute Force even if the logs are identical
            anomalies = self.anomaly_detector.check(event)

            # 🟢 2. FIRE ALERTS
            if anomalies:
                self.alert_engine.fire(anomalies)

                # 🟢 NEW: AUTO-RESPOND (The "Active Defense")
                for anomaly in anomalies:
                    # We only auto-respond to CRITICAL/HIGH threats
                    if anomaly.get('severity') in ['CRITICAL', 'HIGH']:
                        # Assuming 'default' workspace for now. In real multi-tenant,
                        # you'd pass the actual workspace_id from the API call.
                        self.response_automation.respond_to_alert(anomaly, "default")

            # 🟢 3. DEDUPLICATION
            # Stop the Graph from learning the same error 1000 times
            # Key = Service + Message (e.g., "ssh-server failed login")
            fingerprint = (event.service, event.message)
            now = time.time()
            is_new = False

            with self.lock:
                if fingerprint not in self.event_fingerprints:
                    self.event_fingerprints[fingerprint] = {"count": 1, "last_seen": now}
                    is_new = True
                else:
                    data = self.event_fingerprints[fingerprint]
                    data["count"] += 1
                    # Only re-learn if it's been a while (e.g., 1 hour)
                    if now - data["last_seen"] > 3600:
                        is_new = True
                    data["last_seen"] = now

            # 🟢 4. LEARN (Only if it's new information)
            if is_new:
                concept = "failure" if event.severity in ["CRITICAL", "ERROR"] else "degradation"
                if event.severity == "INFO": concept = "info"

                # A. Service Status
                self.learn(event.service, "has_status", event.message, concept=concept)

                # B. Bridge Node
                if concept in ["failure", "degradation"]:
                    failure_node = f"{event.service} {event.message}"
                    self.learn(event.service, "is_experiencing", failure_node, concept="state_link")

                # C. Security Context
                if event.source_ip:
                    self.learn(event.source_ip, "connected_to", event.service, concept="network_activity")

                if event.user:
                    self.learn(event.user, "accessed", event.service, concept="user_activity")

                new_knowledge_count += 1

            count += 1

        if count > 0:
            logger.info(f"🧠 Log Sentinel: Processed {count} events. Learned {new_knowledge_count} new patterns.")
            return True
        return False

    def process_query(self, query, pre_decided_tool=None, pre_decided_args=None):
        if pre_decided_tool:
            tool_name, tool_args = pre_decided_tool, pre_decided_args
        else:
            tool_name, tool_args = self.decide_tool(query)

        if tool_name:
            logger.info(f"🤖 Planner chose tool: {tool_name}")

            # 🟢 LOG ANALYSIS
            if tool_name == "read_file":
                raw_data = self._read_local_file(tool_args['file_path'])
                if "Error" in raw_data and len(raw_data) < 100: return raw_data

                # 🟢 CHECK STATUS: Don't lie if it fails
                success = self._learn_from_logs(raw_data)
                if success:
                    return f"✅ Analyzed {tool_args['file_path']}. Mapped system events to graph."
                else:
                    return f"❌ Failed to analyze {tool_args['file_path']}. The LLM timed out or crashed."

            # 🟢 SEARCH
            if tool_name == "search":
                res = self.tools.run(tool_name, **tool_args)
                return f"Search Result: {res[:500]}..."

            # 🟢 GENERAL
            return self.tools.run(tool_name, **tool_args)

        # MEMORY RETRIEVAL
        facts = self.retrieve_context(query)
        if not facts: return "I don't recall anything about that."
        return self.generate_answer(query, facts)

    def _read_local_file(self, file_path):
        """
        Reads a local log file or code file.
        Simulates the 'Input Stream' of a server.
        """
        import os
        if not os.path.exists(file_path):
            return f"Error: File '{file_path}' not found."

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                # Read last 2000 chars (focus on recent errors)
                # or read line by line. Let's grab a chunk.
                content = f.read()
                if len(content) > 3000:
                    return content[-3000:] # Focus on the tail (latest logs)
                return content
        except Exception as e:
            return f"Error reading file: {e}"

    def _summarize_search(self, query, raw_text):
        """
        Directly calls local Ollama to summarize search results.
        """
        import requests
        import json

        # 1. Prepare the Prompt
        # We give Ollama the raw text and tell it to be a smart assistant.
        prompt = (
            f"Context from internet search:\n{raw_text}\n\n"
            f"User Question: {query}\n"
            f"Task: Answer the question directly and concisely based on the context. "
            f"Do not mention 'snippets' or 'sources' in your answer, just give the facts."
        )

        try:
            # 2. Call Ollama (Direct API)
            # This hits your local Llama 3.2 1B model
            url = "http://localhost:11434/api/generate"
            payload = {
                "model": "llama3.2:1b",  # Make sure this matches your downloaded model name
                "prompt": prompt,
                "stream": False
            }

            response = requests.post(url, json=payload, timeout=30)

            if response.status_code == 200:
                result = response.json().get('response', '').strip()
                return f"🌐 ULTRON: {result}"
            else:
                return f"⚠️ Ollama Error ({response.status_code})"

        except Exception as e:
            # Fallback if Ollama is off
            return f"⚠️ Ollama Unreachable: {e}\n\nRaw Results:\n{raw_text[:200]}..."

    def get_recent_alerts(self, limit: int = 10) -> List[Dict]:
        """
        Wrapper to get recent alerts from the engine.
        """
        return self.alert_engine.get_recent_alerts(limit=limit)

    def decide_tool(self, query):
        """
        SENTINEL ROUTER (Lean Version)
        Only routes to Log Analysis or Learning. No chatbot features.
        """
        q = query.lower().strip()
        import re

        # 1. LOG ANALYSIS
        if "read" in q or "analyze" in q or "scan" in q:
            match = re.search(r'[\w\-\./\\]+\.(log|txt|py|json)', q)
            if match:
                filename = match.group(0)
                logger.info(f"⚡ Reflex: Log Analysis -> '{filename}'")
                return "read_file", {"file_path": filename}

        # 2. INNATE LEARNING (Rule Detection)
        causal_keywords = ["causes", "leads to", "implies", "resulted in", "triggers", "depends on"]
        if any(f" {word} " in f" {q} " for word in causal_keywords):
             logger.info(f"⚡ Reflex: Rule Detected -> Learning Mode")
             return "learn", {}

        # 3. FALLBACK
        # If it's not a log command, assume it's a fact/statement to learn.
        return "learn", {}

    def generate_answer(self, query, facts):
        """
        Takes the user's question and the retrieved facts.
        Asks Llama 3.2 to write a natural language answer.
        """
        if not facts:
            return "I don't know the answer to that."

        # 1. Prepare the Prompt (The "Muzzle")
        # We tell the LLM: "You are a reporter. Here is the data. Don't make stuff up."
        context_str = "\n".join([f"- {f}" for f in facts])

        prompt = (
            f"You are ULTRON, a helpful AI assistant. "
            f"Answer the query using ONLY the provided facts. "
            f"If the facts are empty or irrelevant, simply say 'I don't know' or 'I need to search for that'. "
            f"Do not make up stories or sci-fi personas.\n\n"
            f"Facts: {context_str}\n"
            f"Query: {query}\n"
            f"Answer:"
        )

        try:
            url = "http://localhost:11434/api/generate"
            data = {
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False
            }

            # 2. Call the Voice
            response = requests.post(url, json=data, timeout=30)
            if response.status_code == 200:
                return response.json().get("response", "").strip()

        except Exception as e:
            return f"Error generating answer: {e}"

        return "I am speechless."

    def _safe_embed(self, texts, normalize=True):
        """
        Uses Ollama to get embeddings.
        Increased timeout for i3 laptops.
        """
        if not texts:
            return []

        if isinstance(texts, str):
            texts = [texts]

        embeddings = []
        model_name = "llama3.2:1b"
        url = "http://localhost:11434/api/embeddings"

        import torch  # Ensure torch is imported

        for i, text in enumerate(texts):
            try:
                # 🟢 DEBUG: Print what we are embedding
                # print(f"   (Embedding: '{text[:20]}...')")

                response = requests.post(url, json={
                    "model": model_name,
                    "prompt": text
                }, timeout=30)  # 🟢 INCREASED TIMEOUT to 30s

                if response.status_code == 200:
                    val = response.json().get("embedding")
                    if val:
                        embeddings.append(val)
                    else:
                        # logger.warning("Ollama returned empty embedding.")
                        embeddings.append([0.0] * 2048)
                else:
                    logger.error(f"Ollama Error {response.status_code}: {response.text}")
                    embeddings.append([0.0] * 2048)

            except Exception as e:
                logger.error(f"Embedding Failed for '{text[:10]}': {e}")
                embeddings.append([0.0] * 2048)

        # Handle case where everything failed
        if not embeddings:
            return torch.zeros((len(texts), 2048))

        # Convert to tensor safely
        try:
            return torch.tensor(embeddings)
        except Exception:
            return torch.zeros((len(texts), 2048))

    def _encode_cached(self, phrases, normalize=True):
        self._ensure_model()

        if isinstance(phrases, str):
            phrases = [phrases]

        with self.lock:
            if not hasattr(self, "_embedding_cache"):
                self._embedding_cache = {}

            new_phrases = [p for p in phrases if p not in self._embedding_cache]
            if new_phrases:
                embs = self._safe_embed(new_phrases, normalize=normalize)
                if embs.dim() == 1:
                    embs = embs.unsqueeze(0)
                for p, e in zip(new_phrases, embs):
                    self._embedding_cache[p] = e.detach().cpu()

            cached_embs = [self._embedding_cache[p] for p in phrases]

        normalized = []
        for e in cached_embs:
            if e.dim() == 1:
                normalized.append(e)
            elif e.dim() == 2 and e.size(0) == 1:
                normalized.append(e.squeeze(0))
            else:
                normalized.append(e.view(-1))

        return torch.stack(normalized)

    def get_concept_for_subject(self, subject):
        if not subject:
            return None

        subject = self._norm_subject(subject)
        for entry in reversed(self.reasoning_memory):
            if self._norm(entry.get("subject")) == subject:
                return self._norm(entry.get("concept")) or None
        return None

    def _find_by_concept(self, concept_tag):
        concept_tag = self._norm(concept_tag)
        with self.lock:
            subjects = (
                set(self.concept_to_subjects[concept_tag])
                if concept_tag in self.concept_to_subjects
                else set()
            )
            snapshot = copy.deepcopy(self.knowledge)

        results = []
        for subject in subjects:
            for relation, objs in snapshot.get(subject, {}).items():
                for obj, data in objs.items():
                    known_concept = self._norm(data.get("concept"))
                    if known_concept == concept_tag:
                        results.append((subject, relation, obj))
        return results

        # --- Persistence helpers ---

    def load_memory(self):
        """Load all knowledge from SQLite into RAM."""
        with self.lock:
            self.knowledge = {}
            self.goals = {}

            # 1. Load Knowledge
            self.cursor.execute("SELECT * FROM knowledge")
            rows = self.cursor.fetchall()
            for r in rows:
                s, rel, o, score, concept, ts = r
                if s not in self.knowledge: self.knowledge[s] = {}
                if rel not in self.knowledge[s]: self.knowledge[s][rel] = {}

                self.knowledge[s][rel][o] = {
                    "score": score,
                    "concept": concept,
                    "last_updated": ts
                }

            # 2. Load Goals
            self.cursor.execute("SELECT * FROM goals")
            g_rows = self.cursor.fetchall()
            for r in g_rows:
                name, data_str = r
                try:
                    g_dict = json.loads(data_str)
                    self.goals[name] = Goal.from_dict(g_dict)
                except:
                    pass

            # Rebuild index
            self._rebuild_concept_index()

    def _reset_memory(self):
        """Reset knowledge and goals when no memory file exists."""
        with self.lock:
            self.knowledge = {}
            self.goals = {}

    def _load_blob(self) -> dict:
        """Safely load full JSON blob from memory file."""
        return self._load_memory_blob() or {}

    def _clean_knowledge(
        self, knowledge_data: Dict[str, Any], now: float
    ) -> Dict[str, Dict[str, Dict[str, Dict[str, Any]]]]:
        """Normalize raw knowledge into consistent internal structure."""
        cleaned: Dict[str, Dict[str, Dict[str, Dict[str, Any]]]] = {}
        for subj, rels in knowledge_data.items():
            cleaned[subj] = {}
            for rel, objs in rels.items():
                cleaned[subj][rel] = {}
                for obj, val in objs.items():
                    if not isinstance(val, dict):
                        cleaned[subj][rel][obj] = {
                            "score": float(val),
                            "last_updated": now,
                        }
                    else:
                        score = float(val.get("score", 1.0))
                        last_updated = val.get("last_updated", now)
                        concept = (
                            val.get("concept") if isinstance(val.get("concept"), str) else None
                        )
                        cleaned[subj][rel][obj] = {
                            "score": score,
                            "last_updated": last_updated,
                            "concept": concept,
                        }
        return cleaned

    def _load_goals(self, goals_blob: Dict[str, Any]) -> Dict[str, Goal]:
        """Safely load goals from a blob into Goal objects."""
        goals: Dict[str, Goal] = {}
        try:
            for _, d in goals_blob.items():
                g = Goal.from_dict(d)
                goals[g.name] = g
        except (OSError, IOError, ValueError, json.JSONDecodeError) as e:
            logger.warning("⚠️ Failed to load goals from memory: %s", e)
            goals = {}
        return goals

    def _handle_load_failure(self, e: Exception):
        """Handle persistence failure gracefully."""
        logger.error("❌ Failed to load memory: %s", e, exc_info=True)
        with self.lock:
            self.knowledge = {}
            self.goals = {}
        self._reward_for_event(
            "persistence_fail", meta={"file": self.memory_file, "error": str(e)}
        )

    def _rebuild_concept_index(self):
        """Rebuild concept_to_subjects mapping after memory load."""
        with self.lock:
            self.concept_to_subjects.clear()
            for subj, rels in self.knowledge.items():
                for _rel, objs in rels.items():
                    for _obj, data in objs.items():
                        if isinstance(data, dict):
                            concept = self._norm(data.get("concept"))
                            if concept:
                                self.concept_to_subjects[concept].add(subj)

    def load_reasoning_memory(self, file_path=None):
        """Load reasoning chains from SQLite."""
        self.reasoning_memory = []
        try:
            with self.lock:
                # Select from DB
                rows = self.cursor.execute("SELECT subject, concept, explanation, score, last_updated FROM reasoning").fetchall()

                for r in rows:
                    subj, conc, expl_json, score, ts = r

                    # Parse the JSON explanation back into a list
                    try:
                        expl = json.loads(expl_json)
                    except:
                        expl = [expl_json] # Fallback for plain text

                    self.reasoning_memory.append({
                        "subject": subj,
                        "concept": conc,
                        "explanation": expl,
                        "score": score,
                        "last_updated": ts
                    })

            logger.info(f"✅ Loaded {len(self.reasoning_memory)} reasoning chains from SQL.")

        except Exception as e:
            logger.error(f"Failed to load reasoning from SQL: {e}")

    def save_memory(self):
        """Persist goals to SQL. (Knowledge is already saved atomically)."""
        with self.lock:
            for name, g in self.goals.items():
                self.cursor.execute('''
                    INSERT OR REPLACE INTO goals (name, data) VALUES (?, ?)
                ''', (name, json.dumps(g.to_dict())))
            self.conn.commit()

    def log_turn(self, user_input, thought=None, response=None, context=None):
        """Log a conversation turn into the rolling buffer."""
        turn = ConversationTurn(
            timestamp=time.time(),
            user_input=user_input,
            agent_thought=thought,
            agent_response=response,
            context_state=context
        )
        with self.lock:
            self.episodic_buffer.append(turn)

    def llm_extract(self, text):
        """
        Uses local Llama 3.2 to extract structured logic.
        Updated: Regex now explicitly IGNORES tags (#tag).
        """
        text = text.strip()
        import re
        import json

        # Helper to force-clean "The", "A", "An"
        def _clean_article(val):
            if not val: return ""
            return re.sub(r'^(the|a|an)\s+', '', val.strip(), flags=re.IGNORECASE)

        # 🟢 LAYER 1: REGEX REFLEX
        # Matches: "The car is blue", "A bird has wings"
        # FIX: The object group `([^#]*)` stops before any '#' character.
        simple_pattern = r'^(?:the\s+|a\s+|an\s+)?(.*?)\s+(is|are|was|were|has|have|contains?|includes?|causes?|leads\s+to|triggers?|implies?|resulted\s+in|depends\s+on)\s+([^#]*)(?:#.*)?[.]?$'

        match = re.match(simple_pattern, text, re.IGNORECASE)

        if match:
            s, r, o = match.groups()

            # Normalize 'is/are' to 'be'
            norm_r = "be" if r.lower() in ["is", "are", "was", "were"] else r.lower()

            # Force Clean
            s_clean = _clean_article(s)
            o_clean = _clean_article(o)

            logger.info(f"⚡ Extraction: '{text}' -> ({s_clean}, {norm_r}, {o_clean}) [Regex]")
            return {"subject": s_clean, "relation": norm_r, "object": o_clean}

        # 🟢 LAYER 2: LLM FALLBACK
        prompt = (
            f"Analyze this sentence strictly: '{text}'\n"
            f"Task: Extract the Subject (Actor), Relation (Action), and Object (Receiver).\n"
            f"Ignore any text starting with #.\n"  # Added instruction
            f"Output JSON only."
        )

        try:
            url = "http://localhost:11434/api/generate"
            data = {
                "model": "llama3.2:1b",
                "prompt": prompt,
                "stream": False,
                "format": "json",
                "options": {"temperature": 0.0}
            }

            response = requests.post(url, json=data, timeout=10)

            if response.status_code == 200:
                result_text = response.json().get("response", "")
                data = json.loads(result_text)

                if data and "subject" in data:
                    s_clean = _clean_article(data["subject"])
                    o_clean = _clean_article(data.get("object", ""))
                    return {"subject": s_clean, "relation": data["relation"], "object": o_clean}

        except Exception as e:
            logger.debug(f"LLM Extraction failed: {e}")
            pass

        return None

    # --- 1. THE GATEKEEPER (New Sanitizer) ---
    def _sanitize(self, text):
        """
        SIMPLE STANDARDIZATION
        1. Remove leading articles ("The car" -> "car")
        2. Remove punctuation (Fixes "accidents?" -> "accident")
        3. Lowercase (rain = Rain)
        4. NO LEMMATIZATION (Fixes "Mars" -> "Mar")
        """
        if not isinstance(text, str) or not text:
            return ""

        import re
        text = text.strip()

        # 🟢 1. STRIP ARTICLES (The/A/An)
        # We do this FIRST so "The car" becomes "car".
        # Anchored to start (^) with a space after (\s+)
        text = re.sub(r'^(the|a|an)\s+', '', text, flags=re.IGNORECASE)

        # 2. Remove punctuation (Keep only letters, numbers, spaces)
        text = re.sub(r'[^\w\s\.\-]', '', text)

        # 3. Lowercase and strip
        text = text.strip().lower()

        return text

    # --- 2. REDIRECTS (Force all logic to use Sanitizer) ---
    def _norm_subject(self, subject: Optional[str]) -> str:
        return self._sanitize(subject)

    def _norm(self, concept: Optional[str]) -> str:
        if not concept:
            return ""
        clean = self._sanitize(concept)
        return self.normalize_concept(clean)

    # --- 3. THE LEARNER (Updated to use Sanitizer) ---
    def learn(self, subject, relation, obj, concept=None, source_weight=1.0):
        # 🟢 0. INNATE DEVOPS RULES (The "Physics" of the System)
        # If the user doesn't provide a concept tag, we infer it from the relation/object.
        if not concept:
            r_lower = relation.lower()
            o_lower = obj.lower()

            # Rule 1: Latency/Timeout is ALWAYS Degradation
            if "latency" in r_lower or "latency" in o_lower or "timeout" in o_lower or "slow" in o_lower:
                concept = "degradation"

            # Rule 2: Refused/Down/500/Crash is ALWAYS Failure
            elif "refused" in o_lower or "down" in o_lower or "crash" in o_lower or "critical" in o_lower or "failed" in o_lower:
                concept = "failure"

            # Rule 3: Dependencies
            elif "depends" in r_lower or "requires" in r_lower:
                concept = "dependency"

        # 🟢 STEP 1: SANITIZE
        subject = self._sanitize(subject)
        obj = self._sanitize(obj)
        # Note: Ensure _canonicalize_relation exists or remove this line if you deleted that helper too.
        # For the simplified brain, you can often just use: relation = relation.lower().strip()
        relation = self._canonicalize_relation(relation)

        if not subject or not obj or not relation:
            return None

        # 🟢 STEP 2: SOURCE AUTHORITY CHECK
        with self.lock:
            existing = self.knowledge.get(subject, {}).get(relation, {}).get(obj)
            if existing:
                current_weight = existing.get("weight", 1.0)
                if source_weight < current_weight:
                    logger.info(f"🛡️ Firewall: Rejected '{subject} {relation} {obj}'")
                    return {"status": "rejected", "reason": "low_authority"}

        # 🟢 STEP 3: STATE UPDATE PROTOCOL (Log-Optimized)
        # We removed the 'resolve_conflict' LLM judge.
        # Instead, we use a simple rule: If the relation defines state (is, status),
        # new values automatically archive old values.

        # Added "status" and "state" to catch server logs
        if relation in ["be", "is", "are", "was", "were", "status", "state"]:
            existing_entry = self.knowledge.get(subject, {}).get(relation, {})
            to_archive = []

            if existing_entry:
                for existing_obj in list(existing_entry.keys()):
                    # If the value is different, archive it (e.g. status 'ok' -> 'error')
                    if existing_obj != obj:
                        to_archive.append(existing_obj)

            # Apply the Archiving
            if to_archive:
                logger.info(f"🔄 State Change: Moving {to_archive} to history ('was').")
                with self.lock:
                    for item in to_archive:
                        # 1. Remove from current relation
                        if item in self.knowledge[subject][relation]:
                            del self.knowledge[subject][relation][item]

                        # 2. Add to 'was' relation (History)
                        self._update_knowledge_entry(subject, "was", item, "archived_state", time.time(), weight=0.5)
                        self._remember(f"Update: {subject} {relation} WAS {item}, but now IS {obj}")

        # 🟢 STEP 4: [REMOVED LOGIC FALLACY CHECK]
        # (Deleted as requested)

        now = time.time()

        # 🟢 STEP 5: STORAGE
        self._update_knowledge_entry(subject, relation, obj, concept, now, weight=source_weight)
        self._update_causal_graph(subject, relation, obj)

        # Handle prediction
        final_concept = concept
        if final_concept is None:
            final_concept = self._handle_concept_prediction(subject, relation, obj)

        self._remember(f"Learned: {subject} {relation} {obj}")

        # Healing triggers
        with self.lock:
            last_pred = dict(getattr(self, "_last_prediction", {}) or {})

        pred_score = float(last_pred.get("score", 1.0))
        self._handle_low_confidence(subject, relation, obj, final_concept, pred_score, last_pred)

        related_concepts = self._discover_related_concepts(subject, obj, final_concept)
        self._auto_multi_hop_reasoning(subject, final_concept, related_concepts)
        self._periodic_evaluation()

        return {"status": "success", "subject": subject, "concept": final_concept}

    def _update_knowledge_entry(self, subject, relation, obj, concept_norm, now, weight=1.0):
        with self.lock:
            if subject not in self.knowledge: self.knowledge[subject] = {}
            if relation not in self.knowledge[subject]: self.knowledge[subject][relation] = {}

            # Update RAM
            # We use setdefault to init, then update values
            if obj not in self.knowledge[subject][relation]:
                self.knowledge[subject][relation][obj] = {
                    "score": 1.0,
                    "last_updated": now,
                    "concept": concept_norm,
                    "weight": weight # 🟢 Save Weight in RAM
                }
            else:
                entry = self.knowledge[subject][relation][obj]
                entry["score"] = float(entry.get("score", 1.0)) + 1.0
                entry["last_updated"] = now
                entry["weight"] = weight # 🟢 Update Weight
                if concept_norm:
                    entry["concept"] = concept_norm

            # Reward logic
            if concept_norm:
                self.concept_to_subjects[concept_norm].add(subject)
                self._reward_for_event("explicit_tag_respected", meta={"tag": concept_norm, "subject": subject})

            self._reward_for_event("knowledge_growth", meta={"subject": subject, "relation": relation, "object": obj})

            # 🟢 SQL Update (Standard Schema)
            entry = self.knowledge[subject][relation][obj]
            self.cursor.execute('''
                INSERT OR REPLACE INTO knowledge
                (subject, relation, object, score, concept, last_updated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (subject, relation, obj, entry["score"], entry.get("concept"), now))
            self.conn.commit()

    def _update_causal_graph(self, subject, relation, obj):
        causal_verbs = {"cause", "lead", "result", "trigger", "produce", "be", "prevent"}
        if any(verb in relation for verb in causal_verbs):
            with self.lock:
                if (relation, obj) not in self.causal_graph[subject]:
                    self.causal_graph[subject].append((relation, obj))
                if (relation, subject) not in self.reverse_causal_graph[obj]:
                    self.reverse_causal_graph[obj].append((relation, subject))

    def _handle_concept_prediction(self, subject, relation, obj):
        predicted_concept = self.predict_concept(subject, relation, obj)
        if not predicted_concept:
            return None

        with self.lock:
            score = float(getattr(self, "_last_prediction", {}).get("score", 1.0))
            self.knowledge[subject][relation][obj]["concept"] = predicted_concept
            self.concept_to_subjects[predicted_concept].add(subject)

        if predicted_concept not in self.concept_aliases:
            self._remember_reasoning(
                subject,
                predicted_concept,
                explanation="Learned concept mapping via prediction.",
                score=score,
            )

        try:
            self.save_memory()
        except OSError as e:
            path = getattr(self, "memory_file", "<unknown path>")
            logger.error("Save error at %s: %s", path, e)
        except (ValueError, RuntimeError, json.JSONDecodeError) as e:
            logger.error("Unexpected save error during learn(): %s", e, exc_info=True)

        logger.info("Auto-tagged as [%s] based on similarity.", predicted_concept)
        return predicted_concept

    def _handle_low_confidence(self, subject, relation, obj, final_concept, pred_score, last_pred):
        if final_concept and pred_score < AUTO_TAG_THRESHOLD:
            self._remember_reasoning(
                subject,
                final_concept,
                explanation=(
                    f"Explicit tag kept; auto-prediction low (score={pred_score:.3f})."
                ),
            )
            self._log_uncertainty(subject, relation, obj, pred_score, top_concept=final_concept)
            with self.lock:
                if final_concept not in self.healing_queue:
                    self._enqueue_healing(final_concept)
            logger.warning(
                "Low-confidence prediction (%.3f); explicit tag '%s' retained and queued for healing.",
                pred_score,
                final_concept,
            )

        elif not final_concept and last_pred.get("concept") and pred_score < AUTO_TAG_THRESHOLD:
            candidate = self._norm(last_pred["concept"])
            logger.info(
                "Low-confidence candidate '%s' (score=%.3f) — queueing for healing.",
                candidate,
                pred_score,
            )
            self._remember_reasoning(
                subject,
                candidate,
                explanation=(f"Low-confidence candidate discovered (score={pred_score:.3f})."),
                score=pred_score,
            )
            self._log_uncertainty(subject, relation, obj, pred_score, top_concept=candidate)
            with self.lock:
                if candidate not in self.healing_queue:
                    self._enqueue_healing(candidate)
                    logger.debug(
                        "Added '%s' to healing_queue (size now %d)",
                        candidate,
                        len(self.healing_queue),
                    )

    def _discover_related_concepts(self, subject, obj, final_concept):
        related_concepts = set()
        with self.lock:
            subj_map = dict(self.knowledge.get(subject, {}))
            obj_map = copy.deepcopy(self.knowledge.get(obj, {}))

        for _rel, obj_map_inner in subj_map.items():
            for _obj, data in obj_map_inner.items():
                c = data.get("concept")
                if isinstance(c, str) and c.strip():
                    c_clean = self._norm(c)
                    if c_clean != (final_concept or "").lower():
                        related_concepts.add(c_clean)

        for _rel, obj_map_inner in obj_map.items():
            for _obj, data in obj_map_inner.items():
                c = data.get("concept")
                if isinstance(c, str) and c.strip():
                    c_clean = self._norm(c)
                    if c_clean != (final_concept or "").lower():
                        related_concepts.add(c_clean)

        return related_concepts

    def _auto_multi_hop_reasoning(self, subject, final_concept, related_concepts):
        seen_chains = set()
        if final_concept:
            logger.info("Auto Multi-Hop Reasoning for concept '%s':", final_concept)
            chains = self.multi_hop_reason(final_concept, max_hops=4, starting_subject=subject)
            for chain in chains:
                chain_str = " → ".join(f"{s} {r} {o}" for s, r, o in chain)
                if chain_str not in seen_chains:
                    seen_chains.add(chain_str)
                    logger.debug(" - %s", chain_str)

        for rc in sorted(related_concepts):
            logger.debug("Auto Multi-Hop Reasoning for related concept '%s':", rc)
            chains = self.multi_hop_reason(rc, max_hops=4, starting_subject=subject)
            for chain in chains:
                chain_str = " → ".join(f"{s} {r} {o}" for s, r, o in chain)
                if chain_str not in seen_chains:
                    seen_chains.add(chain_str)
                    logger.debug(" - %s", chain_str)

    def _periodic_evaluation(self):
        with self.lock:
            self._learn_count += 1
            do_eval = self._learn_count % self._evaluate_every == 0

        if not do_eval:
            return

        try:
            eval_summary = self._evaluate_recent_reasoning()
            if eval_summary and eval_summary.get("weaknesses"):
                with self.lock:
                    for weak_concept in eval_summary["weaknesses"]:
                        if weak_concept not in self.healing_queue:
                            self._enqueue_healing(weak_concept)
        except (ValueError, KeyError, RuntimeError) as e:
            logger.warning("Evaluation error in learn(): %s", e, exc_info=True)

    def process_feedback(self, user_input):
        """
        Handles 'Yes'/'No' answers with DEBUGGING enabled.
        """
        u = user_input.lower().strip()

        if not self.active_thought or not getattr(self, 'active_context', None):
            print("   [DEBUG] ❌ FAILURE: Brain has no active question in memory.")
            return False

        ctx = self.active_context
        subj = ctx.get('subject')
        rel = ctx.get('relation')
        obj = ctx.get('object')
        concept = ctx.get('concept')

        # 🟢 1. POSITIVE MATCHING
        positive_starts = ["yes", "yeah", "yep", "sure", "correct", "right", "ok"]
        is_positive = u in positive_starts or any(u.startswith(x + " ") for x in positive_starts)

        if is_positive:
            print(f"\n✅ CONFIRMED: Learning that {subj} {rel} {obj}...")
            self.learn(subj, rel, obj, concept=concept)

            # Clear memory
            self.active_thought = None
            self.active_context = None
            return True

        # 🟢 2. NEGATIVE MATCHING
        negative_starts = ["no", "nope", "nah", "wrong", "incorrect"]
        is_negative = u in negative_starts or any(u.startswith(x + " ") for x in negative_starts)

        if is_negative:
            neg_rel = f"not_{rel}"
            print(f"\n❌ REJECTED: Noting that {subj} {neg_rel} {obj}...")
            self.learn(subj, neg_rel, obj, concept=concept)

            # Clear memory
            self.active_thought = None
            self.active_context = None
            return True

        print("   [DEBUG] ❌ FAILURE: Input did not match 'yes' or 'no' list.")
        return False

    def render_graph(self, central_node=None, depth=2, filename="brain_map"):
        """
        Visualizes the Knowledge Graph using Graphviz.
        - central_node: If set, only draws neighbors within 'depth' hops.
        - filename: Output file prefix.
        """
        try:
            from graphviz import Digraph
        except ImportError:
            logger.error("Graphviz not installed. Run: pip install graphviz")
            return None

        dot = Digraph(comment='Ultron Knowledge Graph')
        dot.attr(rankdir='LR', size='10,10')  # Left-to-Right layout
        dot.attr('node', shape='box', style='rounded,filled', fillcolor='#FFFFDD', fontname="Helvetica")
        dot.attr('edge', fontname="Helvetica", fontsize="10")

        # 1. Collect relevant nodes (BFS if centered, else all)
        relevant_nodes = set()
        if central_node:
            central_node = self._norm_subject(central_node)
            relevant_nodes.add(central_node)
            queue = [(central_node, 0)]
            visited = {central_node}

            while queue:
                curr, d = queue.pop(0)
                if d >= depth: continue

                # Add neighbors from Knowledge Graph
                if curr in self.knowledge:
                    for rel, objs in self.knowledge[curr].items():
                        for obj in objs:
                            relevant_nodes.add(obj)
                            if obj not in visited:
                                visited.add(obj)
                                queue.append((obj, d+1))
        else:
            # If no center, grab EVERYTHING (Careful with huge DBs)
            for subj in self.knowledge:
                relevant_nodes.add(subj)
                for rel in self.knowledge[subj]:
                    for obj in self.knowledge[subj][rel]:
                        relevant_nodes.add(obj)

        # 2. Draw Nodes & Edges
        added_edges = set()

        with self.lock:
            snapshot = copy.deepcopy(self.knowledge)

        for subj, rels in snapshot.items():
            if subj not in relevant_nodes: continue

            for rel, objs in rels.items():
                for obj, data in objs.items():
                    if obj not in relevant_nodes: continue

                    # Color Logic
                    color = "black"
                    style = "solid"
                    weight = "1"

                    if rel in ["is", "are", "be", "was"]:
                        color = "blue"; weight="2" # Definitions
                    elif rel in ["cause", "leads to", "implies"]:
                        color = "red"; style="bold" # Logic
                    elif "has" in rel or "contain" in rel:
                        color = "darkgreen" # Properties
                    elif "not" in rel:
                        color = "red"; style="dashed" # Negation (The "No" answers)

                    edge_key = (subj, rel, obj)
                    if edge_key not in added_edges:
                        # Label includes score if it's interesting
                        label = rel
                        if data.get("score", 1.0) > 1.0:
                            label += f" ({int(data['score'])})"

                        dot.edge(subj, obj, label=label, color=color, style=style)
                        added_edges.add(edge_key)

        try:
            output_path = dot.render(filename, format='png', cleanup=True)
            logger.info(f"🎨 Graph rendered to {output_path}")
            return filename
        except Exception as e:
            logger.error(f"Graphviz render failed: {e}")
            return None

    def recall(self, subject, relation):
        subject = self._norm_subject(subject)
        relation = self.lemmatizer.lemmatize(relation.lower(), pos="v")
        relation = self._canonicalize_relation(relation)

        with self.lock:
            relation_data = copy.deepcopy(
                self.knowledge.get(subject, {}).get(relation, {})
            )

        result = []
        if isinstance(relation_data, dict):
            sorted_objs = sorted(relation_data.items(), key=lambda x: -x[1]["score"])
            result = [obj for obj, _ in sorted_objs]

        if result:
            self._remember(f"Recalled: {subject} {relation} → {', '.join(result)}")
        else:
            self._remember(f"Tried to recall: {subject} {relation} → ❌ Unknown")

        return result

    def semantic_recall(self, subject, relation, similarity_threshold=0.8):
        subject = self._norm_subject(subject)
        relation = self.lemmatizer.lemmatize(relation.lower(), pos="v")
        relation = self._canonicalize_relation(relation)

        with self.lock:
            subject_rels = copy.deepcopy(self.knowledge.get(subject, {}))
        if not subject_rels:
            return []

        query_phrase = f"{subject} {relation}"
        query_vec = self._encode_cached([query_phrase])

        known_phrases, known_map = self._build_known_phrases(subject, subject_rels)
        if not known_phrases:
            return []

        known_vecs = self._encode_cached(known_phrases)
        return self._match_similarities(
            query_phrase, query_vec, known_phrases, known_map,
            subject_rels, similarity_threshold, known_vecs
        )

    def find_reasoning_chains(self, query_text):
        """
        Logic Engine: Scans the query for known concepts and tries to connect them.
        Returns a list of logical proofs (chains).
        """
        # 1. Normalize query for matching
        q = self._norm_subject(query_text)

        # 2. Gather all unique concepts we know (Subjects & Objects)
        # We need to know what to look for in the user's sentence.
        nodes = set(self.knowledge.keys())
        for rels in self.knowledge.values():
            for objs in rels.values():
                nodes.update(objs.keys())

        # 3. Find which concepts appear in the query
        # We search for " distinct " words to avoid partial matches (like 'rain' in 'brain')
        hits = [n for n in nodes if f" {n} " in f" {q} "]

        chains = []
        if len(hits) < 2:
            return []

        # 4. Try to connect every pair found
        # If user asks "Does lack of sleep cause sickness?" -> We check Path(lack of sleep -> sickness)
        import itertools
        for start in hits:
            for end in hits:
                if start == end: continue

                # Use our existing pathfinder
                path = self.trace_path_from_to(start, end, max_depth=3)
                if path:
                    # format readable string
                    # e.g. "lack of sleep cause fatigue, which leads to sickness"
                    steps = []
                    for s, r, o in path:
                         steps.append(f"{s} {r} {o}")

                    chain_text = " -> ".join(steps)
                    logger.info(f"🔗 Logic Found: {chain_text}")
                    chains.append(f"Logic Chain: {chain_text}")

        return list(set(chains)) # Remove duplicates

    def retrieve_context(self, query_text, top_k=3):
        """
        Smart Retrieval + Deep Reasoning.
        """
        final_facts = []

        # --- 🧠 NEW: Deep Reasoning Check ---
        # Before we search for keywords, let's look for Logic Chains.
        chains = self.find_reasoning_chains(query_text)
        if chains:
            # If we find a logic chain, add it first!
            final_facts.extend(chains)

        # --- Standard Vector Search (Existing Code) ---
        query_vec = self._safe_embed([query_text])[0]
        snapshot = self.get_snapshot()
        memories = []
        for subj, rels in snapshot.items():
            for rel, objs in rels.items():
                for obj, data in objs.items():
                    text = f"{subj} {rel} {obj}"
                    concept = data.get("concept", "")
                    if concept:
                        text += f" ({concept})"
                    memories.append(text)

        if not memories:
            return final_facts # Return chains if we have them

        memory_vecs = self._safe_embed(memories)
        scores = cos_sim(query_vec, memory_vecs)[0]
        scored_memories = list(zip(memories, scores.tolist()))
        scored_memories.sort(key=lambda x: x[1], reverse=True)

        # Standard Filtering
        if not scored_memories:
            return final_facts

        best_score = scored_memories[0][1]

        # We only accept memories that are ACTUALLY relevant.
        if best_score >= 0.75:
            for fact, score in scored_memories[:top_k]:
                # Dynamic range: must be above 0.75 AND close to the best score
                if score >= 0.75 and score >= (best_score - 0.1):
                    final_facts.append(fact)

        return final_facts

    def _build_known_phrases(self, subject, subject_rels):
        known_phrases, known_map = [], {}
        for known_rel in subject_rels:
            phrase = f"{subject} {known_rel}"
            known_phrases.append(phrase)
            known_map[phrase] = known_rel
        return known_phrases, known_map

    def _match_similarities(
        self, query_phrase, query_vec, known_phrases,
        known_map, subject_rels, threshold, known_vecs=None
    ):
        if known_vecs is None:
            known_vecs = self._encode_cached(known_phrases)

        result, match_scores = [], []
        similarities = cos_sim(query_vec, known_vecs)[0]

        for phrase, sim in zip(known_phrases, similarities):
            score = sim.item()
            known_rel = known_map[phrase]
            logger.debug(
                "Comparing '%s' with '%s' → similarity: %.3f",
                query_phrase, phrase, score
            )

            if score >= threshold:
                for obj in subject_rels[known_rel]:
                    result.append(obj)
                    match_scores.append((obj, score))

        if result:
            result = [obj for obj, _ in sorted(match_scores, key=lambda x: -x[1])]
            self._remember(f"Recalled (fuzzy): {query_phrase} → {', '.join(result)}")
        else:
            self._remember(f"Tried fuzzy recall: {query_phrase} → ❌ Unknown")

        return result

    def reinforce(self, feedback):
        if not self.short_term_memory:
            logger.info("No recent activity to reinforce.")
            return

        last = self.short_term_memory[-1]
        if "Recalled" not in last:
            logger.info("Last memory was not a recall action, skipping reinforcement.")
            return

        try:
            text = last.split("→")[0]
            text = text.replace("Recalled (fuzzy):", "").replace("Recalled:", "").strip()
            parts = text.split(maxsplit=2)
        except (AttributeError, IndexError, ValueError):
            parts = []

        if len(parts) < 2:
            logger.warning("Could not parse recall memory for reinforcement.")
            return

        subject, relation = self._norm_subject(parts[0]), parts[1]

        with self.lock:
            relation_data = (
                self.knowledge
                .get(subject, {})
                .get(relation, {})
            )

            for _, data in relation_data.items():
                if not isinstance(data, dict):
                    continue
                if feedback == "positive":
                    data["score"] = float(data.get("score", 0)) + 1.0
                elif feedback == "negative" and data.get("score", 0) > 1.0:
                    data["score"] -= 1.0
                data["last_updated"] = time.time()

            try:
                self.save_memory()
            except (OSError, ValueError, json.JSONDecodeError, RuntimeError) as e:
                logger.error("Unexpected save error during reinforce(): %s", e, exc_info=True)

        tag = "Correct" if feedback == "positive" else "Incorrect"
        self._remember(f"{last} → {tag}")
        logger.info("Feedback noted: %s", self.short_term_memory[-1])

    def _decay_entry_healing(self, entry, now, decay_constant, healing_set, min_score):
        """Apply exponential decay to a single memory entry."""
        try:
            elapsed = now - entry.get("last_updated", now)
            old_score = float(entry.get("score", 1.0))
            concept = self._norm(entry.get("concept"))

            # Healing-aware decay rate
            effective_decay = decay_constant * (0.25 if concept in healing_set else 1.0)
            new_score = old_score * exp(-effective_decay * elapsed)

            if new_score >= min_score:
                return {
                    **entry,
                    "score": new_score,
                    "last_updated": now,
                }
        except (TypeError, ValueError, OverflowError):
            return None
        return None

    def _decay_relation(self, relation_data, now, decay_constant, _healing_set, min_score):
        """Process all objects for a relation and return updated relation data + count removed."""
        new_relation_data = {}
        removed_count = 0

        for obj, entry in relation_data.items():
            if not isinstance(entry, dict):
                continue

            ts, new_score = self._decay_entry(entry, now, decay_constant)
            if new_score >= min_score:
                updated_entry = dict(entry)
                updated_entry["score"] = new_score
                updated_entry["last_updated"] = ts
                new_relation_data[obj] = updated_entry
            else:
                removed_count += 1

        return new_relation_data, removed_count

    def decay_memory(self, half_life_minutes=10, min_score=0.05, verbose=True):
        """
        Decays memory scores exponentially over time.
        Entries in healing_queue decay slower to give healing a chance.
        """
        if not isinstance(self.knowledge, dict):
            logger.warning("Knowledge base corrupted — resetting to {}")
            with self.lock:
                self.knowledge = {}
            return

        now = time.time()
        decay_constant = log(2) / (half_life_minutes * 60)

        with self.lock:
            snapshot = copy.deepcopy(self.knowledge)
            healing_set = {self._norm(c) for c in self.healing_queue}

        # --- Step 1: collect decay changes
        updates, deletions, removed_total = self._collect_decay_changes(
            snapshot, now, decay_constant, healing_set, min_score
        )

        # --- Step 2: apply changes
        self._apply_decay_changes(updates, deletions)

        # --- Step 3: reward shaping
        self._reward_decay_cleanup(removed_total)

        if verbose:
            logger.info(
                "Memory decayed naturally (healing-aware). Removed %d entries.",
                removed_total,
            )


    def _collect_decay_changes(self, snapshot, now, decay_constant, healing_set, min_score):
        updates, deletions = {}, []
        removed_total = 0

        for subject, rels in snapshot.items():
            for relation, relation_data in rels.items():
                new_relation_data, removed = self._decay_relation(
                    relation_data, now, decay_constant, healing_set, min_score
                )
                removed_total += removed
                if new_relation_data:
                    updates.setdefault(subject, {})[relation] = new_relation_data
                else:
                    deletions.append((subject, relation))

        return updates, deletions, removed_total

    def _apply_decay_changes(self, updates, deletions):
        with self.lock:
            # 1. Apply Updates (Score changes)
            for subj, rels in updates.items():
                self.knowledge.setdefault(subj, {}).update(rels)
                # 🟢 SQL Update
                for rel, objs in rels.items():
                    for obj, data in objs.items():
                        self.cursor.execute('''
                            UPDATE knowledge
                            SET score=?, last_updated=?
                            WHERE subject=? AND relation=? AND object=?
                        ''', (data['score'], data['last_updated'], subj, rel, obj))

            # 2. Apply Deletions (Removal)
            for subject, relation in deletions:
                # Remove from RAM
                if subject in self.knowledge and relation in self.knowledge[subject]:
                    del self.knowledge[subject][relation]
                    if not self.knowledge[subject]:
                        del self.knowledge[subject]

                # 🟢 SQL Delete
                self.cursor.execute(
                    "DELETE FROM knowledge WHERE subject=? AND relation=?",
                    (subject, relation)
                )

            self.conn.commit()


    def _reward_decay_cleanup(self, removed_total):
        try:
            self._reward_for_event(
                "decay_cleanup", meta={"removed": removed_total, "type": "knowledge"}
            )
            if removed_total >= 20:
                self._reward(-0.3, reason="massive_decay_loss", meta={"removed": removed_total})
        except (KeyError, RuntimeError) as e:
            logger.error("Reward failure during decay_memory: %s", e)


    def _remember_reasoning(self, subject, concept_tag, explanation, score=1.0):
        should_save = False
        now = time.time()

        # --- normalize explanation into list of strings ---
        if isinstance(explanation, str):
            explanation_list = [explanation]
        elif isinstance(explanation, list):
            explanation_list = [str(e) for e in explanation if e]
        else:
            explanation_list = [str(explanation)]

        with self.lock:
            merged = False
            for entry in self.reasoning_memory:
                if (
                    self._norm_subject(entry.get("subject"))
                    == self._norm_subject(subject)
                    and self._norm(entry.get("concept")) == self._norm(concept_tag)
                ):
                    # --- merge explanations instead of overwriting ---
                    if isinstance(entry.get("explanation"), list):
                        for e in explanation_list:
                            if e not in entry["explanation"]:
                                entry["explanation"].append(e)
                    else:
                        existing = entry.get("explanation")
                        if existing not in explanation_list:
                            entry["explanation"] = [existing] + explanation_list
                        else:
                            entry["explanation"] = [existing]

                    # --- keep strongest score, always refresh timestamp ---
                    entry["score"] = max(entry.get("score", 0.0), float(score))
                    entry["last_updated"] = now
                    entry["timestamp"] = now
                    should_save = True
                    merged = True
                    break

            if not merged:
                self.reasoning_memory.append(
                    {
                        "subject": subject,
                        "concept": concept_tag,
                        "explanation": explanation_list,  # always stored as list
                        "score": float(score),
                        "last_updated": now,
                        "timestamp": now,
                    }
                )
                should_save = True

        if should_save:
            # 🟢 NEW: Save directly to SQL
            try:
                # Convert list explanations to JSON string for storage
                if isinstance(explanation, list):
                    expl_json = json.dumps(explanation)
                else:
                    expl_json = json.dumps([explanation])

                self.cursor.execute('''
                    INSERT INTO reasoning (subject, concept, explanation, score, last_updated)
                    VALUES (?, ?, ?, ?, ?)
                ''', (subject, concept_tag, expl_json, float(score), now))
                self.conn.commit()
            except Exception as e:
                logger.error(f"Failed to save reasoning to SQL: {e}")

    def _log_uncertainty(self, subject, relation, obj, score, top_concept=None):
        entry = {
            "subject": self._norm_subject(subject),
            "relation": (
                self.lemmatizer.lemmatize(relation.lower(), pos="v")
                if relation
                else relation
            ),
            "object": self._norm(obj),
            "similarity_score": float(score),
            "top_concept": self._norm(top_concept) if top_concept else None,
            "timestamp": time.time(),
        }
        with self.lock:
            self.uncertainty_memory.append(entry)

        # --- Planner / Policy ---

    def plan_next_action(self):
        """Policy: pick next action based on goal gaps and cooldowns (with rewards)."""
        self._estimate_goal_progress()

        # Score actions by weighted sum of (priority * (target - progress))
        deficits = {
            name: max(0.0, g.target - g.progress) * (g.priority * g.reward_weight)
            for name, g in self.goals.items()
            if g.active
        }

        # Force Fixes (Existing code...)
        if self.uncertainty_memory:
            deficits["reduce_uncertainty"] = max(deficits.get("reduce_uncertainty", 0), 1.0)

        if not deficits:
            return None, {}

        candidates = []
        now = time.time()
        for name, score in deficits.items():
            if name == "reduce_uncertainty":
                candidates.append(("attempt_heal_tick", score, {}))
                candidates.append(("slightly_lower_thresholds", score * 0.5, {}))
                if self.uncertainty_memory:
                     candidates.append(("ask_user_validation", 50.0, {}))

            elif name == "increase_consistency":
                candidates.append(("scan_conflicts_and_enqueue", score, {}))

            elif name == "expand_knowledge":
                candidates.append(("probe_related_edges", score, {}))

            # 🟢 NEW: The Free Will Logic
            elif name == "exercise_free_will":
                # High score to compete with validation
                candidates.append(("explore_knowledge_gaps", score * 1.2, {}))

            elif name == "improve_prediction_accuracy":
                candidates.append(("slightly_raise_thresholds", score * 0.6, {}))

        # Pick highest-utility action respecting cooldown
        candidates.sort(key=lambda x: -x[1])

        if candidates:
            action, score, meta = candidates[0]
            if now >= self.policy_cooldowns.get(action, 0):
                return action, meta

        # reward: planner idle
        self._reward(-0.05, reason="planner_idle", meta={"deficits": deficits})
        return None, {}

    def act(self, action, meta=None):
        """Execute an action, enforce cooldown, record action + reward outcome."""
        meta = meta or {}
        now = time.time()

        # cooldown table
        cooldowns = {
            "attempt_heal_tick": 1.0,
            "scan_conflicts_and_enqueue": 5.0,
            "probe_related_edges": 2.0,
            "slightly_raise_thresholds": 10.0,
            "slightly_lower_thresholds": 10.0,
            "ask_user_validation": 30.0,
            "explore_knowledge_gaps": 5.0, # 🟢 FAST MODE: Check every 5s for testing
        }
        self.policy_cooldowns[action] = now + cooldowns.get(action, 1.0)

        with self.lock:
            self.recent_actions.append((now, action, meta))

        try:
            if action == "attempt_heal_tick":
                with self.lock:
                    q = getattr(self, "healing_queue", [])
                    concept = q.pop(0) if q else None
                if concept:
                    healed = self._attempt_heal(concept)
                    if healed:
                        self._reward(+0.3, reason="heal_attempt_success", meta={"concept": concept})
                    else:
                        self._reward(-0.1, reason="heal_attempt_failed", meta={"concept": concept})

            elif action == "ask_user_validation":
                with self.lock:
                    if not self.uncertainty_memory:
                        return False

                    item = self.uncertainty_memory[-1]
                    subj = item.get("subject")
                    concept = item.get("top_concept")
                    score = item.get("similarity_score", 0)

                    if subj and concept:
                        context_data = {
                            "subject": subj,
                            "relation": item.get("relation"),
                            "object": item.get("object"),
                            "concept": concept
                        }

                        question = (
                            f"I am only {int(score*100)}% sure that '{subj}' is '{concept}'. "
                            f"Is this correct? (yes/no)"
                        )

                        self.log_turn(
                            user_input="",
                            thought="Seeking validation.",
                            response=question,
                            context=context_data
                        )
                        self.active_thought = question
                        self.active_context = context_data
                        self.uncertainty_memory.pop()
                        return True
                    return False

            elif action == "scan_conflicts_and_enqueue":
                with self.lock:
                    for c in list(getattr(self, "_conflict_set", set()))[:3]:
                        self._enqueue_healing(c)
                self._reward_for_event("conflict_detected", meta={"rescan": True})

            elif action == "probe_related_edges":
                snap = self.get_snapshot()
                for s, rels in list(snap.items())[:1]:
                    for r, objs in rels.items():
                        for o in objs:
                            self._remember(f"Probe touched: {s} {r} {o}")
                            self._reward_for_event("knowledge_growth", magnitude=0.05, meta={"subject": s})

            elif action == "slightly_raise_thresholds":
                self.PREDICTION_THRESHOLD = min(0.9, self.PREDICTION_THRESHOLD + 0.01)
                self.SIMILARITY_THRESHOLD = min(0.9, self.SIMILARITY_THRESHOLD + 0.005)
                self._reward(+0.05, reason="threshold_adjust", meta={"direction": "raise"})

            elif action == "slightly_lower_thresholds":
                self.PREDICTION_THRESHOLD = max(0.05, self.PREDICTION_THRESHOLD - 0.05)
                self.SIMILARITY_THRESHOLD = max(0.05, self.SIMILARITY_THRESHOLD - 0.05)
                self._reward(+0.05, reason="threshold_adjust", meta={"direction": "lower"})

            return True

        except (RuntimeError, ValueError, KeyError) as e:
            logger.error("Action execution failed for %s: %s", action, e)
            self._reward(-0.2, reason="action_exception", meta={"action": action, "error": str(e)})
            return False

    def step(self):
        """One policy step: plan → act → reward outcome."""
        action, meta = self.plan_next_action()
        if not action:
            logger.debug("No action taken this cycle.")
            return None

        success = self.act(action, meta)

        # ✅ small reward shaping for planner control loop
        if success:
            self._reward(+0.1, reason="planner_step_success", meta={"action": action})
        else:
            self._reward(-0.1, reason="planner_step_failure", meta={"action": action})

        return action

    def decay_reasoning_memory(
        self, half_life_minutes=10, max_entries=500, score_threshold=0.5, verbose=True
    ):
        """
        Decays reasoning memory scores over time, removes low-score entries,
        deduplicates by (subject, relation, object) if present, else by (subject, concept),
        and keeps only top-N most recent.
        """
        if not isinstance(self.reasoning_memory, list):
            logger.warning("Reasoning memory corrupted — resetting to []")
            with self.lock:
                self.reasoning_memory = []
            return

        now = time.time()
        decay_constant = log(2) / (half_life_minutes * 60)

        with self.lock:
            entry_map, removed = self._process_reasoning_entries(
                now, decay_constant, score_threshold
            )

            # --- Keep only top-N most recent ---
            new_memory = sorted(
                entry_map.values(),
                key=lambda e: e.get("timestamp", 0),
                reverse=True,
            )[:max_entries]

            self.reasoning_memory = new_memory

        # ✅ reward shaping
        self._handle_decay_rewards(removed)

        if verbose:
            logger.info(
                "Reasoning memory decayed and cleaned. %d entries remain (removed %d).",
                len(new_memory),
                removed,
            )


    # -------------------------------------------------------------------
    # 🔹 Helpers
    # -------------------------------------------------------------------

    def _process_reasoning_entries(self, now: float, decay_constant: float, score_threshold: float):
        """Process reasoning memory entries with decay, deduplication, and merging."""
        entry_map: dict[tuple, dict[str, object]] = {}
        removed = 0

        for entry in list(self.reasoning_memory):
            try:
                ts, new_score = self._decay_entry(entry, now, decay_constant)
                if new_score < score_threshold:
                    removed += 1
                    continue

                key = self._dedup_key(entry)
                self._merge_entry(entry_map, key, entry, ts, new_score, now)

            except (ValueError, KeyError, TypeError) as e:
                logger.debug("Skipping bad reasoning entry: %s", e)
                continue

        return entry_map, removed


    def _decay_entry(self, entry: dict, now: float, decay_constant: float) -> tuple[float, float]:
        """Compute decayed score for a reasoning entry."""
        ts = float(entry.get("timestamp", entry.get("last_updated", now)))
        elapsed = now - ts
        old_score = float(entry.get("score", 0))
        new_score = old_score * exp(-decay_constant * elapsed)
        return ts, new_score

    def _dedup_key(self, entry: dict) -> tuple:
        """Build deduplication key for reasoning entry."""
        if "relation" in entry and "object" in entry:
            return (
                self._norm_subject(entry.get("subject")),
                entry.get("relation"),
                entry.get("object"),
            )
        return (
            self._norm_subject(entry.get("subject")),
            self._norm(entry.get("concept")),
        )


    def _merge_entry(
        self, entry_map: dict, key: tuple, entry: dict, ts: float, new_score: float, now: float
    ):
        """Merge or replace reasoning entries into entry_map."""
        if key not in entry_map or ts > entry_map[key].get("timestamp", 0):
            new_entry = entry.copy()
            new_entry["score"] = new_score
            new_entry["last_updated"] = now
            new_entry.setdefault("timestamp", ts)

            # Always normalize explanation to list
            if not isinstance(new_entry.get("explanation"), list):
                new_entry["explanation"] = [new_entry.get("explanation")]

            entry_map[key] = new_entry
        else:
            existing = entry_map[key]
            if not isinstance(existing.get("explanation"), list):
                existing["explanation"] = [existing.get("explanation")]

            exp_list = entry.get("explanation")
            if isinstance(exp_list, list):
                for e_item in exp_list:
                    if e_item and e_item not in existing["explanation"]:
                        existing["explanation"].append(e_item)
            elif exp_list and exp_list not in existing["explanation"]:
                existing["explanation"].append(exp_list)

            existing["score"] = max(existing["score"], new_score)
            existing["last_updated"] = now


    def _handle_decay_rewards(self, removed: int):
        """Handle reward shaping after decay cleanup."""
        try:
            self._reward_for_event(
                "decay_cleanup", meta={"removed": removed, "type": "reasoning"}
            )
            if removed >= 50:
                self._reward(
                    -0.4,
                    reason="massive_reasoning_decay_loss",
                    meta={"removed": removed},
                )
        except (RuntimeError, ValueError, KeyError) as e:
            logger.error("Reward failure during decay_reasoning_memory: %s", e, exc_info=True)

    def forget(self, subject):
        """
        Permanently deletes a subject from Memory AND Database.
        """
        # Normalization
        subject = self._sanitize(subject) # Use _sanitize or _norm_subject, whichever your class uses
        if not subject:
            return

        with self.lock:
            # 1. RAM: Remove Subject
            self.knowledge.pop(subject, None)
            self.causal_graph.pop(subject, None)

            # 2. RAM: Clean up references in the reverse graph
            # (Your logic here was good, keeping it)
            for obj in list(self.reverse_causal_graph.keys()):
                updated = [
                    (rel, src)
                    for rel, src in self.reverse_causal_graph[obj]
                    if src != subject
                ]
                if updated:
                    self.reverse_causal_graph[obj] = updated
                else:
                    del self.reverse_causal_graph[obj]

            # 3. SQL: Permanent Wipe (Subject AND Object)
            try:
                # Delete where it is the Subject
                self.cursor.execute("DELETE FROM knowledge WHERE subject = ?", (subject,))

                # 🟢 EXTRA SAFETY: Delete where it is the Object too
                self.cursor.execute("DELETE FROM knowledge WHERE object = ?", (subject,))

                # 🟢 CRITICAL: Save changes to hard drive
                self.conn.commit()

                logger.info(f"Forget complete: '{subject}' wiped from DB.")
                print(f"🗑 Forgot '{subject}'.")
            except Exception as e:
                logger.error(f"SQL Error during forget: {e}")

    def show_recent_memory(self):
        logger.info("Recent Interactions (Short-Term Memory):")
        for i, entry in enumerate(self.short_term_memory[-10:], start=1):
            logger.info("%s. %s", i, entry)
        logger.info("")

    def show_reasoning_memory(self, limit=10):
        logger.info("Reasoning Memory:")
        with self.lock:
            data = list(self.reasoning_memory)
        if not data:
            logger.info("No stored reasoning explanations yet.")
            return
        sorted_entries = sorted(data, key=lambda x: -x.get("score", 0))
        for i, entry in enumerate(sorted_entries[:limit], 1):
            subject = entry.get("subject", "❓")
            concept = entry.get("concept", "❓")
            explanation = entry.get("explanation", "❓")
            score = round(entry.get("score", 0), 2)
            logger.info("%s. %s → %s (%.2f): %s", i, subject, concept, score, explanation)

    def _remember(self, entry: str | dict):
        """Store a short-term memory entry (with timestamp), pruned to limit."""
        ts = time.time()
        if isinstance(entry, str):
            entry = {"ts": ts, "text": entry}
        else:
            entry = dict(entry)
            entry.setdefault("ts", ts)

        with self.lock:
            self.short_term_memory.append(entry)
            if len(self.short_term_memory) > self.short_term_limit:
                self.short_term_memory.pop(0)

    def get_subjects_by_concept(self, concept_tag):
        concept = self._norm(concept_tag)
        with self.lock:
            if concept in self.concept_to_subjects:
                return sorted(self.concept_to_subjects[concept])
            return []

    def get_by_concept(self, concept_tag):
        triplets = self._find_by_concept(concept_tag)
        return [f"{s} {r} {o}" for s, r, o in triplets]

    def list_known_concepts(self, sort=True):
        snapshot = self.get_snapshot()
        concepts = set()
        for _, rels in snapshot.items():
            for _, objs in rels.items():
                for _, data in objs.items():
                    if isinstance(data, dict):
                        concept = self._get_clean_concept(data)
                        if concept:
                            concepts.add(concept)

        result = sorted(concepts) if sort else list(concepts)
        logger.info("\nKnown Concepts (%d):", len(result))
        for i, c in enumerate(result, 1):
            logger.info("%s. %s", i, c)
        return result

    def query_by_concept(self, concept_tag):
        """
        Public API to query all (subject, relation, object)
        triples tagged with a concept.

        Note:
        - We normalize here to handle raw user input
          (e.g. "Harmful", " harmful ", etc.)
        - _find_by_concept also normalizes internally for safety,
          so normalization happens twice.
          This redundancy ensures robustness at the public API layer (CLI, scripts)
          and internally (if other methods call _find_by_concept directly).
        """
        return self._find_by_concept(self._norm(concept_tag))

    def reason_by_concept(self, concept_tag, threshold=0.5):
        """
        High-level wrapper: normalize concept, gather inferred/tagged facts,
        log them and print relevant causal chains. Returns the inferred list.
        """
        concept_tag = self._norm(concept_tag)
        snapshot = self.get_snapshot()

        inferred = self._collect_inferred_for_concept(snapshot, concept_tag, threshold)

        self._log_inferred_reasoning(concept_tag, inferred)
        self._log_reasoning_paths(snapshot, concept_tag)

        return inferred

    def _collect_inferred_for_concept(self, snapshot: dict, concept_tag: str, threshold: float):
        """
        Walk snapshot and return list of tuples (subject, relation, object, mode)
        where mode is "tagged" (explicit tag matched) or "inferred" (predicted).
        """
        inferred = []
        for subject, relations in snapshot.items():
            for relation, objects in relations.items():
                for obj, data in objects.items():
                    # Keep same filtering logic as original
                    concept_val = data.get("concept")
                    if not (isinstance(concept_val, str) and concept_val.strip()):
                        continue

                    known_concept = self._norm(concept_val)
                    if known_concept == concept_tag:
                        inferred.append((subject, relation, obj, "tagged"))
                    else:
                        predicted = self.predict_concept(subject, relation, obj, threshold=threshold)
                        if predicted == concept_tag:
                            inferred.append((subject, relation, obj, "inferred"))

        return inferred


    def _log_inferred_reasoning(self, concept_tag: str, inferred: list):
        """
        Log the inferred/tagged items in the same format as original.
        """
        logger.info("\nInferred Reasoning for Concept '%s':", concept_tag)
        for s, r, o, mode in inferred:
            label = "✓ Learned" if mode == "tagged" else "🤔 Inferred"
            logger.info("%s: %s %s %s", label, s, r, o)


    def _log_reasoning_paths(self, snapshot: dict, concept_tag: str):
        """
        Print causal chains found by multi_hop_reason(concept_tag) if the last
        tuple's stored data (as str) contains the concept_tag (case-insensitive),
        preserving original behavior and deduplicating printed chains.
        """
        reasoning_paths = self.multi_hop_reason(concept_tag)
        printed_paths = set()

        for path in reasoning_paths:
            s, r, o = path[-1]
            d = snapshot.get(s, {}).get(r, {}).get(o, {})
            if str(d).lower().find(concept_tag) != -1:
                chain_str = " → ".join(f"{s} {r} {o}" for s, r, o in path)
                if chain_str not in printed_paths:
                    logger.info("Causal Chain: %s", chain_str)
                    printed_paths.add(chain_str)

    def multi_hop_reason(
        self, concept_tag, max_hops=4, starting_subject=None, propagate_tags=False
    ):
        concept_tag = self._norm(concept_tag)
        starting_subject = self._norm_subject(starting_subject) if starting_subject else None
        snapshot = self.get_snapshot()

        results = self._dfs_multi_hop(snapshot, concept_tag, max_hops, starting_subject)

        unique = self._filter_unique_chains(results)

        if not unique:
            self._log_multi_hop_warning(concept_tag, starting_subject)
            self._reward(-0.1, reason="multi_hop_fail", meta={"concept": concept_tag})
        else:
            self._log_multi_hop_info(unique, concept_tag, starting_subject)
            self._reward_for_event(
                "multi_hop_success", meta={"concept": concept_tag, "chains_found": len(unique)}
            )

        if propagate_tags:
            logger.warning(
                "'propagate_tags' is deprecated. Use propagate_concept_tags(chains, '%s') explicitly.",
                concept_tag,
            )

        return unique


    def _dfs_multi_hop(self, snapshot, concept_tag, max_hops, starting_subject):
        results = []

        def dfs(path, depth):
            if depth > max_hops:
                return

            subject, relation, obj = path[-1]
            data = snapshot.get(subject, {}).get(relation, {}).get(obj, {})
            known_concept = self._norm(data.get("concept"))

            if known_concept == concept_tag:
                results.append(path)

            for next_rel, next_objs in snapshot.get(obj, {}).items():
                for next_obj in next_objs:
                    next_triplet = (obj, next_rel, next_obj)
                    if next_triplet not in path:
                        dfs(path + [next_triplet], depth + 1)

        for subj, rels in snapshot.items():
            if starting_subject and subj != starting_subject:
                continue
            for rel, objs in rels.items():
                for obj in objs:
                    dfs([(subj, rel, obj)], depth=1)

        return results


    def _filter_unique_chains(self, chains):
        unique, seen = [], set()
        for path in chains:
            chain_str = " → ".join(f"{s} {r} {o}" for s, r, o in path)
            if chain_str not in seen:
                unique.append(path)
                seen.add(chain_str)
        return unique


    def _log_multi_hop_warning(self, concept_tag, starting_subject):
        if starting_subject:
            logger.warning(
                "No multi-hop reasoning chains found for '%s' from '%s'.",
                concept_tag,
                starting_subject,
            )
        else:
            logger.warning("No multi-hop reasoning chains found for '%s'.", concept_tag)


    def _log_multi_hop_info(self, chains, concept_tag, starting_subject):
        if starting_subject:
            logger.info(
                "Multi-Hop Reasoning Chains for concept '%s' from '%s':",
                concept_tag,
                starting_subject,
            )
        else:
            logger.info("Multi-Hop Reasoning Chains for concept '%s':", concept_tag)

        for chain in chains:
            logger.info(" → ".join(f"{s} {r} {o}" for s, r, o in chain))

    def propagate_concept_tags(self, chains, concept_tag):
        concept_tag = self._norm(concept_tag)

        with self.lock:
            snapshot = copy.deepcopy(self.knowledge)

        updates = self._collect_updates_from_chains(chains, concept_tag, snapshot)

        improved = self._apply_concept_updates(updates, concept_tag)

        return improved

    def _collect_updates_from_chains(self, chains, concept_tag, snapshot):
        updates = []
        for chain in chains:
            for s, r, o in chain[:-1]:
                entry = snapshot.get(s, {}).get(r, {}).get(o)
                if not entry:
                    continue
                existing = self._norm(entry.get("concept"))
                score = entry.get("score", 0)

                # only update if no concept or concept is very weak
                if not existing or (score < 0.4 and existing != concept_tag):
                    updates.append((s, r, o, score))
        return updates


    def _apply_concept_updates(self, updates, concept_tag):
        improved = False
        with self.lock:
            for s, r, o, score in updates:
                if (
                    s not in self.knowledge
                    or r not in self.knowledge[s]
                    or o not in self.knowledge[s][r]
                ):
                    continue
                entry = self.knowledge[s][r][o]

                # don’t overwrite explicit user concept
                if isinstance(entry.get("concept"), str) and entry.get("concept").strip() and score >= 0.4:
                    continue

                entry["concept"] = concept_tag
                self.concept_to_subjects[concept_tag].add(s)
                entry["score"] = max(score, 0.5)
                entry["last_updated"] = time.time()
                logger.debug("Propagated '%s' tag to: %s %s %s", concept_tag, s, r, o)
                improved = True
        return improved

    def infer_and_explain(self, subject, concept_tag, threshold=0.5, max_hops=4):
        subject = self._norm_subject(subject)
        concept_tag = self._norm(concept_tag)

        with self.lock:
            subj_map = copy.deepcopy(self.knowledge.get(subject, {}))

        # Try different strategies in order
        result = (
            self._explain_via_multi_hop(subject, concept_tag, max_hops)
            or self._explain_via_direct_match(subject, concept_tag, subj_map)
            or self._explain_via_prediction(subject, concept_tag, subj_map, threshold)
            or self._explain_via_causal_path(subject, concept_tag)
        )

        if result:
            self._remember(result)
            return True, result

        return False, f"I could not determine if '{subject}' is '{concept_tag}'."

    # ----------------- Helpers -----------------

    def _explain_via_multi_hop(self, subject, concept_tag, max_hops):
        """Try multi-hop reasoning + paraphrase."""
        paths = self.multi_hop_reason(concept_tag, max_hops=max_hops)
        matching_paths = [p for p in paths if any(s == subject for s, _, _ in p)]
        if not matching_paths:
            return None

        preferred = [c for c in matching_paths if c[0][0] == subject]
        best_path = max(preferred or matching_paths, key=len)

        paraphrased = self.paraphrase_reasoning_chain(
            subject, concept_tag, chains=[best_path], max_hops=max_hops
        )
        return paraphrased.strip() if paraphrased else None


    def _explain_via_direct_match(self, subject, concept_tag, subj_map):
        """Check direct subject–concept matches in knowledge graph."""
        for rel, objs in subj_map.items():
            for obj, data in objs.items():
                concept = data.get("concept")
                if isinstance(concept, str) and self._norm(concept) == concept_tag:
                    return f"{subject} {rel} {obj} (predicted to be '{concept_tag}')"
        return None


    def _explain_via_prediction(self, subject, concept_tag, subj_map, threshold):
        """Predict concept when no direct match exists."""
        for rel, objs in subj_map.items():
            for obj in objs:
                predicted = self.predict_concept(subject, rel, obj, threshold=threshold)
                if predicted == concept_tag:
                    return f"{subject} {rel} {obj} (predicted to be '{concept_tag}')"
        return None


    def _explain_via_causal_path(self, subject, concept_tag):
        """Last resort: traverse causal graph for explanation."""
        causal_path = self.traverse_causal_path(subject, concept_tag)
        if causal_path:
            steps = " → ".join(f"{s} {r} {o}" for s, r, o in causal_path)
            return f"Because {steps}, it is considered '{concept_tag}'."
        return None

    def paraphrase_reasoning_chain(self, subject, concept, chains=None, max_hops=4):
        if not chains:
            chains = self.multi_hop_reason(concept, max_hops=max_hops)
        if not chains:
            return None

        chains = [chain for chain in chains if any(s == subject for s, _, _ in chain)]
        if not chains:
            return None

        preferred_chains = [c for c in chains if c[0][0] == subject]
        best_chain = (
            max(preferred_chains, key=len) if preferred_chains else max(chains, key=len)
        )

        phrases = [f"{subj} {rel} {obj}" for subj, rel, obj in best_chain]
        if not phrases:
            return None

        if len(phrases) == 1:
            return f"{phrases[0]}, it is considered '{concept}'."

        joined = ", then ".join(phrases)
        return f"Because {joined}, it is considered '{concept}'."

    def traverse_causal_path(self, subject, target_concept, max_depth=5):
        """
        Try to find a causal path from `subject` to `target_concept`
        up to `max_depth` steps.
        """
        subject = self._norm_subject(subject)
        target_concept = self._norm(target_concept)

        with self.lock:
            cg = copy.deepcopy(self.causal_graph)
            kg = copy.deepcopy(self.knowledge)

        return self._search_causal_graph(subject, target_concept, cg, kg, max_depth)

    def _search_causal_graph(self, subject, target_concept, cg, kg, max_depth):
        """Breadth-first search in the causal graph."""
        visited = set()
        queue = [(subject, [])]

        for _ in range(max_depth):
            next_queue = []
            for current, path in queue:
                if current in visited:
                    continue
                visited.add(current)

                found_path, expansions = self._expand_path(
                    current, path, cg, kg, target_concept
                )
                if found_path is not None:
                    return found_path

                next_queue.extend(expansions)
            queue = next_queue

        return None

    def _expand_path(self, current, path, cg, kg, target_concept):
        """
        Expand one node in the causal graph.
        Returns (found_path, expansions).
        """
        expansions = []
        for rel, obj in cg.get(current, []):
            new_path = path + [(current, rel, obj)]

            # Check knowledge graph for concept alignment
            for rel2, objs in kg.get(obj, {}).items():
                for obj2, data in objs.items():
                    concept = data.get("concept")
                    if self._norm(concept) == target_concept:
                        return new_path + [(obj, rel2, obj2)], []

            # Direct match with target concept
            if obj == target_concept:
                return new_path, []

            expansions.append((obj, new_path))

        return None, expansions

    def check_conceptual_inference(self, subject, concept_tag):
        concept_tag = self._norm(concept_tag)
        subject = self._norm_subject(subject)

        with self.lock:
            subj_map = copy.deepcopy(self.knowledge.get(subject, {}))

        for rel, objs in subj_map.items():
            for obj, data in objs.items():
                if not isinstance(data, dict):  # safety check
                    continue
                concept = data.get("concept")
                if not isinstance(concept, str) or not concept.strip():
                    continue
                if self._norm(concept) == concept_tag:
                    explanation = f"{subject} {rel} {obj}"
                    return True, explanation

        return False, None

    def _find_closest_causal_node(self, text, threshold=0.8):
        """
        Finds the closest matching node in the causal graph using semantic similarity.
        Useful when the user asks for 'water' but the memory is 'fresh water'.
        """
        text = self._norm_subject(text)

        # 1. Gather all unique nodes currently in the causal graph
        candidates = set(self.causal_graph.keys())
        with self.lock:
            for _, edges in self.causal_graph.items():
                for _, obj in edges:
                    candidates.add(obj)

        candidates = list(candidates)
        if not candidates:
            return None

        # 2. Embed the user's query and all graph nodes
        # (This uses the cache, so it's fast after the first run)
        query_vec = self._encode_cached([text])
        candidate_vecs = self._encode_cached(candidates)

        # 3. Find the best match
        sims = cos_sim(query_vec, candidate_vecs)[0]
        best_idx = sims.argmax().item()
        best_score = sims[best_idx].item()

        # 4. Return match if it's good enough
        if best_score >= threshold:
            match = candidates[best_idx]
            if match != text:
                logger.info(f"Fuzzy match: '{text}' ≈ '{match}' (score={best_score:.2f})")
            return match

        return None

    def predict_concept(self, subject, relation, obj, top_n=1, threshold=None):
        """
        Predict the most likely concept tag.
        UPDATED: Now filters out 'web_fact', 'archived_state' and silences weak matches (<0.80).
        """
        subject, relation, obj = self._prep_predict_inputs(subject, relation, obj)
        if not relation or not obj:
            logger.warning("predict_concept: missing relation or object")
            return None

        query_phrase = f"{relation} {obj}"
        query_matrix = self._safe_encode([query_phrase])
        if query_matrix is None:
            return None

        snapshot = self.get_snapshot()
        candidate_phrases, concepts = self._gather_candidates(snapshot)
        if not candidate_phrases:
            logger.warning("predict_concept: no candidate concepts available")
            return None

        similarities = self._compute_matrix_similarities(query_matrix, candidate_phrases)
        if similarities is None:
            return None

        best_similarity, best_concept, matched_phrase = self._rank_candidates(
            similarities, concepts, candidate_phrases, top_n
        )

        if best_similarity is None:
            logger.warning("predict_concept: empty candidate scoring")
            return None

        # 🟢 FIX 1: THE JUNK FILTER
        # If the AI suggests 'web_fact', 'misc', or 'archived_state', reject it immediately.
        if best_concept in ["web_fact", "unknown", "misc", "archived_state"]:
            logger.info(f"🚫 Ignoring system tag suggestion: {best_concept} ({best_similarity:.2f})")
            return None

        # 🟢 FIX 2: THE SILENCE FILTER
        # If the confidence is below 80%, stay silent.
        if best_similarity < 0.80:
             logger.info(f"🤫 Silencing weak match: {best_concept} ({best_similarity:.2f})")
             return None

        # If we survive the filters, record it and proceed
        self._record_last_prediction(subject, relation, obj, best_concept, best_similarity)
        thr = self.PREDICTION_THRESHOLD if threshold is None else float(threshold)

        logger.info(
            "Closest match: '%s' ≈ '%s' → score: %.3f, concept: %s",
            query_phrase, matched_phrase, best_similarity, best_concept
        )

        return self._handle_prediction_confidence(
            subject, relation, obj, best_concept, best_similarity, thr
        )

    # --- Helpers ---

    def _prep_predict_inputs(self, subject, relation, obj):
        subject = self._norm_subject(subject)
        relation = self.lemmatizer.lemmatize(relation.lower(), pos="v") if relation else ""
        relation = self._canonicalize_relation(relation)
        obj = self._norm(obj)
        return subject, relation, obj

    def _safe_encode(self, phrases):
        try:
            return self._encode_cached(phrases)
        except (RuntimeError, ValueError, TypeError) as e:
            logger.error("Encoding failure for '%s': %s", phrases, e, exc_info=True)
            return None

    def _gather_candidates(self, snapshot):
        candidate_phrases, concepts = [], []
        for _, rels in snapshot.items():
            for rel, objs in rels.items():
                for o, data in objs.items():
                    c = data.get("concept") if isinstance(data, dict) else None
                    if isinstance(c, str):
                        candidate_phrases.append(f"{rel.strip().lower()} {o.strip().lower()}")
                        concepts.append(self._norm(c))
        return candidate_phrases, concepts

    def _compute_matrix_similarities(self, query_matrix, candidate_phrases):
        try:
            candidate_matrix = self._encode_cached(candidate_phrases)
            return cos_sim(query_matrix, candidate_matrix)[0]
        except (RuntimeError, ValueError, TypeError) as e:
            logger.error("Similarity computation failed: %s", e, exc_info=True)
            return None

    def _rank_candidates(self, similarities, concepts, candidate_phrases, top_n):
        scored = list(zip(similarities.tolist(), concepts, candidate_phrases))
        scored.sort(key=lambda x: -x[0])
        if top_n > 0:
            scored = scored[:top_n]
        if not scored:
            return None, None, None
        return float(scored[0][0]), scored[0][1], scored[0][2]

    def _record_last_prediction(self, subject, relation, obj, concept, score):
        with self.lock:
            self._last_prediction = {
                "subject": subject,
                "relation": relation,
                "object": obj,
                "concept": concept if isinstance(concept, str) else None,
                "score": score,
            }

    def _handle_prediction_confidence(self, subject, relation, obj, concept, score, threshold):
        if concept and score >= threshold:
            self._reward_for_event(
                "high_conf_prediction",
                magnitude=score,
                meta={"score": score, "concept": concept, "phrase": f"{relation} {obj}"}
            )
            return self._norm(concept)

        self._reward_for_event(
            "low_conf_prediction",
            magnitude=score,
            meta={"score": score, "concept": concept, "phrase": f"{relation} {obj}"}
        )
        self._log_uncertainty(subject, relation, obj, score, concept)
        logger.warning(
            "predict_concept: similarity %.3f below threshold (%.2f)",
            score,
            threshold,
        )
        return None

    def form_concept_clusters(self, cross_concepts=True):
        with self.lock:
            snapshot = copy.deepcopy(self.knowledge)

        triplets, concept_map = self._collect_triplets_and_map(snapshot)

        if not concept_map:
            logger.warning("No tagged knowledge available to cluster.")
            return {}

        phrases = [p for p, _ in concept_map]
        embeddings = self._encode_cached(phrases)

        clusters = self._build_clusters(
            phrases, embeddings, concept_map, triplets, cross_concepts
        )

        if not clusters:
            logger.info("No strong concept clusters found.")
            return {}

        self._log_clusters(clusters, cross_concepts)
        return clusters


    def _collect_triplets_and_map(self, snapshot):
        triplets, concept_map = [], []
        for subject, rels in snapshot.items():
            for relation, objs in rels.items():
                for obj, data in objs.items():
                    concept = data.get("concept")
                    if isinstance(concept, str) and concept.strip():
                        c_norm = self._norm(concept)
                        phrase = f"{relation.strip().lower()} {obj.strip().lower()}"
                        triplets.append((subject, relation, obj, c_norm))
                        concept_map.append((phrase, c_norm))
        return triplets, concept_map


    def _build_clusters(self, phrases, embeddings, concept_map, triplets, cross_concepts):
        clusters = defaultdict(set)
        for i in range(len(phrases)):
            for j in range(i + 1, len(phrases)):
                sim = float(cos_sim(embeddings[i], embeddings[j]).item())
                concept_i, concept_j = concept_map[i][1], concept_map[j][1]
                if sim >= self.CLUSTER_THRESHOLD and (
                    not cross_concepts or concept_i == concept_j
                ):
                    key = concept_i if concept_i == concept_j else f"{concept_i}|{concept_j}"
                    clusters[key].add((triplets[i][0], triplets[i][1], triplets[i][2]))
                    clusters[key].add((triplets[j][0], triplets[j][1], triplets[j][2]))
        return clusters


    def _log_clusters(self, clusters, cross_concepts):
        logger.info(
            "\n🧠 Concept Clusters (threshold=%s, cross_concepts=%s):",
            self.CLUSTER_THRESHOLD,
            cross_concepts,
        )
        for concept, items in clusters.items():
            logger.info("\n Cluster '%s':", concept)
            for s, r, o in sorted(items):
                logger.info("  - %s %s %s", s, r, o)


    def summarize_concept_clusters(self):
        clusters = self.form_concept_clusters(cross_concepts=True)
        summaries = {}
        for concept, items in clusters.items():
            summaries[concept] = [f"{s} {r} {o}" for s, r, o in sorted(items)]

        logger.info("\nConcept Cluster Summaries:")
        for concept, lines in summaries.items():
            logger.info("\n%s:", concept)
            for line in lines:
                logger.info("  - %s", line)
        return summaries

    def is_query(self, subject, concept, max_hops=4):
        concept = self._norm(concept)
        subject = self._norm_subject(subject)

        with self.lock:
            subj_map = copy.deepcopy(self.knowledge.get(subject, {}))

        for rel, objs in subj_map.items():
            for obj, data in objs.items():
                if isinstance(data, dict):
                    known_concept = self._norm(data.get("concept"))
                    if known_concept == concept:
                        explanation = f"{subject} {rel} {obj}"
                        logger.info(
                            "Yes, '%s' is '%s' (directly tagged via: %s).",
                            subject, concept, explanation
                        )
                        return True, explanation

        for rel, objs in subj_map.items():
            for obj in objs:
                predicted = self.predict_concept(subject, rel, obj)
                if predicted == concept:
                    explanation = f"{subject} {rel} {obj}"
                    logger.info(
                        "Yes, '%s' is '%s' (predicted via: %s).",
                        subject, concept, explanation
                    )
                    return True, explanation

        logger.debug(
            "No direct or predicted tag found. Triggering reasoning for concept '%s'...",
            concept
        )

        success, explanation = self.infer_and_explain(
            subject, concept, max_hops=max_hops
        )

        if success:
            logger.info("Yes, %s", explanation)
            return True, explanation

        logger.warning("I could not determine if '%s' is '%s'.", subject, concept)
        return False, None

    def get_effects_of(self, subject, depth=2):
        subject = self._norm_subject(subject)
        results = []

        with self.lock:
            graph = copy.deepcopy(self.causal_graph)

        def dfs(current, path, d):
            if d == 0:
                return
            for rel, obj in graph.get(current, []):
                new_path = path + [(current, rel, obj)]
                results.append(new_path)
                dfs(obj, new_path, d - 1)

        dfs(subject, [], depth)
        return results

    def get_causes_of(self, target, depth=2):
        target = self._norm_subject(target)

        with self.lock:
            reverse_graph = copy.deepcopy(self.reverse_causal_graph)

        results = []

        def dfs(current, path, d):
            if d == 0:
                return
            for rel, src in reverse_graph.get(current, []):
                new_path = [(src, rel, current)] + path
                results.append(new_path)
                dfs(src, new_path, d - 1)

        dfs(target, [], depth)

        seen = set()
        unique_results = []
        for path in results:
            key = tuple(path)
            if key not in seen:
                seen.add(key)
                unique_results.append(path)

        return unique_results

    def trace_path_from_to(self, start, end, max_depth=5):
        # 1. Try to fuzzy-match the start and end nodes
        # If the user says "water", we map it to "drinking fresh water"
        resolved_start = self._find_closest_causal_node(start) or self._norm_subject(start)
        resolved_end = self._find_closest_causal_node(end) or self._norm_subject(end)

        with self.lock:
            graph = copy.deepcopy(self.causal_graph)

        visited = set([resolved_start])
        queue = [(resolved_start, [])]

        for _ in range(max_depth):
            next_queue = []
            for current, path in queue:
                # Get neighbors
                for rel, obj in graph.get(current, []):
                    if obj in visited:
                        continue

                    new_path = path + [(current, rel, obj)]

                    # Check if we reached the target (fuzzy matched)
                    if obj == resolved_end:
                        return new_path

                    visited.add(obj)
                    next_queue.append((obj, new_path))
            queue = next_queue

        return None

    def _get_clean_concept(self, data):
        c = self._norm(data.get("concept"))
        return c or None

    def show_uncertainty_log(self, limit=10):
        """Show the most recent uncertain predictions for debugging/audit."""
        logger.info("\nUncertain Predictions Log:")
        with self.lock:
            data = list(self.uncertainty_memory)

        if not data:
            logger.info("No uncertain predictions recorded.")
            return

        recent = sorted(data, key=lambda x: -float(x.get("timestamp", 0)))[:limit]
        for i, entry in enumerate(recent, 1):
            concept = entry.get("top_concept", "?")
            logger.debug(
                "[%d] No direct or predicted tag found. "
                "Triggering reasoning for concept '%s'...",
                i,
                concept,
            )

    def _evaluate_recent_reasoning(self):
        strong_threshold = 0.9
        now = time.time()
        window_secs = 5 * 60

        with self.lock:
            recent_reasoning = list(self.reasoning_memory[-50:])
            concept_to_subjects = {k: set(v) for k, v in self.concept_to_subjects.items()}
            kg = copy.deepcopy(self.knowledge)
            total_reasoned = len(self.reasoning_memory)
            total_uncertain = len(self.uncertainty_memory)

        weaknesses, strengths = self._gather_recent_stats(
            recent_reasoning, now, window_secs, strong_threshold
        )
        self._score_concepts(kg, concept_to_subjects, weaknesses, strengths, strong_threshold)
        self._apply_healing_queue(weaknesses)

        return {
            "weaknesses": weaknesses,
            "strengths": strengths,
            "total_reasoned": total_reasoned,
            "total_uncertain": total_uncertain,
        }


    def _gather_recent_stats(self, recent_reasoning, now, window_secs, strong_threshold):
        weaknesses = {}
        strengths = {}

        for entry in recent_reasoning:
            concept = self._norm(entry.get("concept"))
            score = float(entry.get("score", 0) or 0)
            ts = float(entry.get("last_updated", 0) or 0)
            if not concept or (ts and (now - ts) > window_secs):
                continue
            if score < strong_threshold:
                weaknesses[concept] = weaknesses.get(concept, 0) + 1
            else:
                strengths[concept] = strengths.get(concept, 0) + 1

        return weaknesses, strengths


    def _score_concepts(self, kg, concept_to_subjects, weaknesses, strengths, strong_threshold):
        for concept, subjects in concept_to_subjects.items():
            all_scores = []
            for subj in subjects:
                for _, objs in kg.get(subj, {}).items():
                    for _, data in objs.items():
                        if not isinstance(data, dict):
                            continue
                        if self._norm(data.get("concept")) == concept:
                            all_scores.append(float(data.get("score", 0) or 0))

            if all_scores:
                low = sum(1 for s in all_scores if s < strong_threshold)
                high = sum(1 for s in all_scores if s >= strong_threshold)
                if low > max(1, high):
                    weaknesses[concept] = weaknesses.get(concept, 0) + 1

        # filter out non-weak if strengths >= weaknesses
        for c in list(weaknesses.keys()):
            if strengths.get(c, 0) >= weaknesses[c]:
                weaknesses.pop(c, None)


    def _apply_healing_queue(self, weaknesses):
        with self.lock:
            for concept in weaknesses:
                if (
                    concept in getattr(self, "_pending_review", set())
                    or concept in getattr(self, "_junk_concepts", set())
                    or concept in getattr(self, "_conflict_set", set())
                    or concept in self._healing_in_progress
                ):
                    self._retry_counters.pop(concept, None)
                    continue
                if self._enqueue_healing(concept):
                    logger.info("ULTRON: Auto-queued weak concept '%s' for healing.", concept)

            for concept in list(self._retry_counters.keys()):
                if concept not in weaknesses:
                    self._retry_counters.pop(concept, None)

    def rebuild_causal_graph(self) -> int:
        """Rebuild forward and reverse causal graphs from self.knowledge."""
        count = 0
        with self.lock:
            self.causal_graph.clear()
            self.reverse_causal_graph.clear()

            # 🟢 FIX: Use stems so "causes", "leads to", "triggers" all work
            CAUSAL_VERBS = {"cause", "lead", "result", "trigger", "produce", "prevent", "implies"}

            for subj, rels in self.knowledge.items():
                for rel, objs in rels.items():
                    # Check if relation contains ANY causal verb (e.g. "causes" contains "cause")
                    if any(verb in rel.lower() for verb in CAUSAL_VERBS) and isinstance(objs, dict):
                        for obj in objs.keys():
                            self.causal_graph[subj].append((rel, obj))
                            self.reverse_causal_graph[obj].append((rel, subj))
                            count += 1

        logger.info("Rebuilt causal graphs with %d edges", count)
        return count

    def export_causal_graph_dot(self, path: str, reverse: bool = False, include_scores: bool = False) -> int:
        """
        Export the causal graph (forward or reverse) to a Graphviz DOT file.
        - reverse=False exports subject -> object using self.causal_graph.
        - reverse=True exports object -> subject using self.reverse_causal_graph.
        - include_scores=True annotates edge labels with knowledge scores when available.
        Returns the number of unique edges written.
        """
        lines = []
        lines.append("digraph Causal {")
        lines.append("  rankdir=LR;")
        lines.append("  graph [splines=true, overlap=false];")
        lines.append("  node [shape=box];")

        graph = self.reverse_causal_graph if reverse else self.causal_graph
        seen = set()

        with self.lock:
            for src, edges in graph.items():
                s = (src or "").replace('"', r'\"')
                for rel, dst in edges:
                    d = (dst or "").replace('"', r'\"')
                    label = (rel or "").replace('"', r'\"')

                    # Optional: annotate with score when exporting forward graph
                    if include_scores and not reverse:
                        try:
                            score = (
                                self.knowledge
                                .get(src, {})
                                .get(rel, {})
                                .get(dst, {})
                                .get("score", None)
                            )
                            if isinstance(score, (int, float)):
                                label = f"{label} ({score:.2f})"
                        except Exception:
                            pass

                    key = (s, label, d)
                    if key in seen:
                        continue
                    seen.add(key)
                    lines.append(f'  "{s}" -> "{d}" [label="{label}"];')

        lines.append("}")
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return len(seen)

    def _self_healing_worker(self):
        """Background loop that attempts to heal weak concepts from the queue."""
        with self.lock:
            self._retry_counters = defaultdict(int)

        while not getattr(self, "_stop_healing_worker", False):
            concept = None
            try:
                concept = self._pick_concept_from_queue()
                if not concept:
                    time.sleep(getattr(self, "_healing_interval", 1.0))
                    continue

                retries, delay = self._compute_retry_params(concept)
                time.sleep(delay)

                healed = self._attempt_heal(concept)
                still_weak = self._post_heal_maintenance(concept)

                self._finalize_healing(concept, healed, still_weak, retries, delay)

                self._safe_save_memory()

            except Exception as e:  # pylint: disable=broad-except
                logger.error("Healing worker loop error for '%s': %s", concept or "N/A", e, exc_info=True)
                with self.lock:
                    if concept:
                        self._healing_in_progress.discard(concept)
                        self._retry_counters.pop(concept, None)

            time.sleep(0.05)  # prevent tight loops

    def _pick_concept_from_queue(self):
        with self.lock:
            if not self.healing_queue:
                return None
            candidate = self._norm(self.healing_queue.pop(0))
            if candidate in self._healing_in_progress:
                logger.debug("'%s' skipped — already in progress", candidate)
                return None
            self._healing_in_progress.add(candidate)
            logger.debug("Healing worker picked '%s'", candidate)
            return candidate

    def _compute_retry_params(self, concept):
        with self.lock:
            retries = self._retry_counters.get(concept, 0)
            self._extra_healing_depth = min(6, 4 + retries // 2)
            delay = max(0.5, 3.0 - min(retries * 0.3, 2.5))
        return retries, delay

    def _post_heal_maintenance(self, concept):
        try:
            self.decay_reasoning_memory(10, 1000, 0.2, verbose=False)
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Reasoning memory decay failed: %s", e, exc_info=True)

        try:
            summary = self._evaluate_recent_reasoning() or {}
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Reasoning evaluation failed: %s", e, exc_info=True)
            return False

        return summary.get("weaknesses", {}).get(concept, 0) > 0

    def _finalize_healing(self, concept, healed, still_weak, retries, _delay):
        with self.lock:
            if healed and not still_weak:
                logger.info("'%s' healed after %d retries", concept, retries)
                self._retry_counters.pop(concept, None)
            elif still_weak:
                retries = self._retry_counters.get(concept, 0) + 1
                self._retry_counters[concept] = retries
                if retries <= getattr(self, "_max_retries", 5):
                    logger.debug("'%s' still weak — retrying (attempt %d)", concept, retries)
                    self._enqueue_healing(concept)
                else:
                    logger.warning("'%s' paused — waiting for more data", concept)
                    self._pending_review.add(concept)
                    self._retry_counters.pop(concept, None)
            self._healing_in_progress.discard(concept)

    def _safe_save_memory(self):
        try:
            self.save_memory()
        except Exception as e:  # pylint: disable=broad-except
            logger.error("Save error in healing worker: %s", e, exc_info=True)

    def _attempt_heal(self, concept: str) -> bool:
        """
        Try to heal a weak concept by reasoning propagation or semantic similarity.
        Returns True if improved, False otherwise.
        """
        concept = self._norm(concept)
        if not concept:
            return False

        if self._is_junk_concept(concept):
            return False

        chains = self._find_healing_chains(concept)
        improved = self._propagate_if_possible(concept, chains)

        if improved:
            self._reward_and_save(concept)
            return True

        if self._detect_conflict(concept):
            return False

        self._penalize_failure(concept)
        return False

    # ----------------- helpers -----------------

    def _is_junk_concept(self, concept: str) -> bool:
        if len(concept) < 3 or concept.isdigit():
            logger.warning("'%s' flagged as junk — ignored until new data.", concept)
            with self.lock:
                self._junk_concepts.add(concept)
            return True
        return False

    def _find_healing_chains(self, concept: str) -> list:
        max_depth = getattr(self, "_extra_healing_depth", 4)
        try:
            chains = self.multi_hop_reason(concept, max_hops=max_depth, propagate_tags=False)
            logger.debug("Attempting to heal '%s' — %d chains found", concept, len(chains))
        except (RuntimeError, ValueError, KeyError) as e:
            logger.error("multi_hop_reason failed for '%s': %s", concept, e, exc_info=True)
            chains = []

        if not chains:
            chains = self._similarity_fallback(concept)

        return chains

    def _similarity_fallback(self, concept: str) -> list:
        logger.info("No reasoning chains for '%s', searching for related knowledge...", concept)
        snapshot = self.get_snapshot()

        text_pieces, subj_rel_obj_map = self._collect_text_pieces(snapshot)
        sims = self._compute_concept_similarities(concept, text_pieces)
        chains = self._select_related_entries(subj_rel_obj_map, sims)

        if not chains:
            chains = self._last_resort_fallback(concept, snapshot)

        return chains


    # ----------------- helpers -----------------

    def _collect_text_pieces(self, snapshot: dict) -> tuple[list[str], list[tuple]]:
        text_pieces = []
        subj_rel_obj_map = []
        for subj, rels in snapshot.items():
            for rel, objs in rels.items():
                for obj, data in objs.items():
                    if isinstance(data, dict):
                        text_pieces.append(f"{subj} {rel} {obj}")
                        subj_rel_obj_map.append((subj, rel, obj))
        return text_pieces, subj_rel_obj_map

    def _compute_concept_similarities(self, concept: str, text_pieces: list[str]) -> list[float]:
        try:
            q_emb = self._encode_cached([concept])
        except (RuntimeError, ValueError, TypeError) as e:
            logger.warning("Embedding failed for healing of '%s': %s", concept, e)
            return [0.0] * len(text_pieces)

        if not text_pieces:
            return []

        try:
            candidate_embs = self._encode_cached(text_pieces)
            sims = cos_sim(q_emb, candidate_embs)[0].tolist()
        except (RuntimeError, ValueError, TypeError) as e:
            logger.warning("Embedding failed for candidates during healing of '%s': %s", concept, e)
            sims = [0.0] * len(text_pieces)

        return sims

    def _select_related_entries(self, subj_rel_obj_map: list[tuple], sims: list[float]) -> list[list[tuple]]:
        related_entries = [
            (subj, rel, obj, float(sim))
            for (subj, rel, obj), sim in zip(subj_rel_obj_map, sims)
            if float(sim) > getattr(self, "SIMILARITY_THRESHOLD", 0.5)
        ]
        related_entries.sort(key=lambda x: x[3], reverse=True)
        chains = [[(subj, rel, obj)] for subj, rel, obj, _ in related_entries[:5]]
        return chains

    def _last_resort_fallback(self, concept: str, snapshot: dict) -> list:
        logger.warning("No semantically similar knowledge found for '%s'. Trying fallback...", concept)
        for subj, rels in snapshot.items():
            for rel, objs in rels.items():
                for obj, data in objs.items():
                    if isinstance(data, dict) and float(data.get("score", 0) or 0) >= 0.8:
                        return [[(subj, rel, obj)]]
        return []

    def _propagate_if_possible(self, concept: str, chains: list) -> bool:
        if not chains:
            return False
        improved = False
        try:
            with self.lock:
                if self.propagate_concept_tags(chains, concept):
                    improved = True
                for chain in chains:
                    for s, r, o in chain:
                        entry = self.knowledge.get(s, {}).get(r, {}).get(o)
                        if isinstance(entry, dict) and self._norm(entry.get("concept")) == concept:
                            self._remember_reasoning(
                                s,
                                concept,
                                explanation=f"Self-healed by propagating '{concept}' from reasoning chain.",
                                score=entry.get("score", 0),
                            )
        except (RuntimeError, ValueError) as e:
            logger.error("Error while propagating healing for '%s': %s", concept, e, exc_info=True)
        return improved

    def _reward_and_save(self, concept: str) -> None:
        logger.info("'%s' successfully strengthened.", concept)
        self._reward_for_event("healed_concept", meta={"concept": concept})
        try:
            self.save_memory()
        except (OSError, IOError, ValueError, json.JSONDecodeError, RuntimeError) as e:
            logger.error("Save error in _attempt_heal for '%s': %s", concept, e)

    def _detect_conflict(self, concept: str) -> bool:
        snapshot = self.get_snapshot()
        scores = []
        with self.lock:
            subjects = set(self.concept_to_subjects.get(concept, set()))

        for subj in subjects:
            for _, objs in snapshot.get(subj, {}).items():  # rel → _
                for _, data in objs.items():  # obj → _
                    if isinstance(data, dict) and self._norm(data.get("concept")) == concept:
                        scores.append(float(data.get("score", 0) or 0))

        if scores:
            weak = sum(1 for s in scores if s < 0.4)
            strong = sum(1 for s in scores if s > 0.8)
            if weak / len(scores) >= 0.3 and strong / len(scores) >= 0.3:
                logger.warning("'%s' has conflicting evidence — moved to conflict set.", concept)
                with self.lock:
                    self._conflict_set.add(concept)
                self._reward_for_event("conflict_detected", meta={"concept": concept})
                return True
        return False

    def _penalize_failure(self, concept: str) -> None:
        logger.warning("No improvements made for '%s'.", concept)
        self._reward(-0.2, reason="heal_failed", meta={"concept": concept})

    def _enqueue_healing(self, concept) -> bool:
        c = self._norm(concept)
        with self.lock:
            if (
                c in self._pending_review
                or c in self._junk_concepts
                or c in self._conflict_set
            ):
                return False

            if c in self._healing_in_progress:
                return False

            # ✅ Avoid race-condition dupes in healing_queue
            if c not in self.healing_queue:
                self.healing_queue.append(c)
                return True
        return False

    def enqueue_concept_for_healing(self, concept: str) -> bool:
        return self._enqueue_healing(concept)

    def stop(self, timeout=None):
        self._stop_healing_worker = True
        t = getattr(self, "_healing_thread", None)
        if t and t.is_alive():
            t.join(timeout=timeout)

        # --- Reward shaping ---
    def _reward(self, value, reason: str = "", meta: Optional[Dict[str, Any]] = None) -> None:
        """Safely apply a reward signal (thread-safe + defensive)."""
        try:
            v = float(value)
        except (ValueError, TypeError):
            v = 0.0

        ts = time.time()
        with self.lock:
            self.reward_total += v
            # ✅ include reason + meta so it matches Deque[Tuple[float, float, str, Dict[str, Any]]]
            self.recent_rewards.append((ts, v, reason, meta or {}))
            self.recent_actions.append(
                (ts, "reward", {"value": v, "reason": reason, **(meta or {})})
            )

        # small adaptive nudge: adjust thresholds a bit
        try:
            self._adaptive_threshold_tweak(v)
        except (ValueError, RuntimeError) as e:
            logger.debug("⚠️ Adaptive tweak skipped: %s", e)

    def _adaptive_threshold_tweak(self, value):
        """Tiny automatic tuning: good rewards nudge thresholds up (be pickier),
        bad rewards nudge down (be more exploratory)."""
        try:
            # clamp delta
            delta = max(-0.01, min(0.01, value * 0.001))
            self.PREDICTION_THRESHOLD = max(
                0.2, min(0.9, self.PREDICTION_THRESHOLD + delta)
            )
            self.SIMILARITY_THRESHOLD = max(
                0.3, min(0.9, self.SIMILARITY_THRESHOLD + delta / 2)
            )
        except (ValueError, RuntimeError):
            pass

    def _reward_for_event(self, event: str, magnitude: float = 1.0, meta=None):
        """Centralized reward table. Thread-safe wrapper around _reward."""
        meta = meta or {}
        gain = 0.0

        if event == "high_conf_prediction":
            gain = +1.0 * magnitude
        elif event == "low_conf_prediction":
            gain = -0.6 * magnitude
        elif event == "explicit_tag_respected":
            gain = +0.4 * magnitude
        elif event == "healed_concept":
            gain = +1.2 * magnitude
        elif event == "conflict_detected":
            gain = -0.8 * magnitude
        elif event == "knowledge_growth":
            gain = +0.3 * magnitude
        elif event == "persistence_ok":
            gain = +0.2 * magnitude
        elif event == "persistence_fail":
            gain = -0.5 * magnitude
        elif event == "decay_cleanup":
            gain = +0.1 * magnitude

        if gain != 0.0:
            try:
                self._reward(gain, reason=event, meta=meta)
            except (RuntimeError, ValueError) as e:
                logger.error("Reward event '%s' failed: %s", event, e, exc_info=True)

    def migrate_relations_to_canonical(self) -> int:
        """Rewrite existing knowledge relations to canonical keys in-place and persist."""
        changed = 0
        with self.lock:
            for subj, rels in list(self.knowledge.items()):
                # 1) Remap relation buckets to canonical keys
                for rel in list(rels.keys()):
                    canon = self._canonicalize_relation(rel)
                    if canon != rel:
                        if canon not in rels:
                            rels[canon] = {}
                        # Move/merge objects under the canonical relation
                        for obj, data in list(rels[rel].items()):
                            new_obj = obj
                            # Fix artifacts like "lead": {"to explosion": ...} → "lead to": {"explosion": ...}
                            if canon == "lead to" and isinstance(obj, str) and obj.lower().startswith("to "):
                                new_obj = obj[3:].strip()
                            if new_obj in rels[canon]:
                                cur = rels[canon][new_obj]
                                cur["score"] = max(cur.get("score", 0.0), data.get("score", 0.0))
                                cur["last_updated"] = max(cur.get("last_updated", 0.0), data.get("last_updated", 0.0))
                                if cur.get("concept") is None and data.get("concept") is not None:
                                    cur["concept"] = data.get("concept")
                            else:
                                rels[canon][new_obj] = dict(data)
                        del rels[rel]
                        changed += 1

                # 2) Clean existing 'lead to' buckets where object keys start with 'to '
                if "lead to" in rels:
                    for obj in list(rels["lead to"].keys()):
                        if isinstance(obj, str) and obj.lower().startswith("to "):
                            data = rels["lead to"].pop(obj)
                            new_obj = obj[3:].strip()
                            if new_obj in rels["lead to"]:
                                cur = rels["lead to"][new_obj]
                                cur["score"] = max(cur.get("score", 0.0), data.get("score", 0.0))
                                cur["last_updated"] = max(cur.get("last_updated", 0.0), data.get("last_updated", 0.0))
                                if cur.get("concept") is None and data.get("concept") is not None:
                                    cur["concept"] = data.get("concept")
                            else:
                                rels["lead to"][new_obj] = data
                            changed += 1

            # 3) Optional cleanup of command-like artifacts
            if "multihop" in self.knowledge:
                del self.knowledge["multihop"]
                changed += 1

        # 4) 🟢 NEW: Persist changes to SQL
        try:
            with self.lock:
                # Clear the table to remove old messy keys
                self.cursor.execute("DELETE FROM knowledge")

                # Re-insert the clean data from RAM
                for subj, rels in self.knowledge.items():
                    for rel, objs in rels.items():
                        for obj, data in objs.items():
                             self.cursor.execute('''
                                INSERT INTO knowledge (subject, relation, object, score, concept, last_updated)
                                VALUES (?, ?, ?, ?, ?, ?)
                            ''', (subj, rel, obj, data['score'], data.get('concept'), data['last_updated']))

                self.conn.commit()

            logger.info(f"Migration complete; changed relations={changed}. SQL Table synchronized.")
        except Exception as e:
            logger.error("Migration save failed: %s", e, exc_info=True)
        return changed

    def _migrate_json_to_sql(self):
        """One-time migration: If DB is empty but JSON exists, import it."""
        # Check if DB is empty
        self.cursor.execute("SELECT count(*) FROM knowledge")
        count = self.cursor.fetchone()[0]

        if count == 0 and os.path.exists(self.memory_file):
            logger.info("⚡ Migration: Moving data from JSON to SQLite...")
            blob = self._load_memory_blob() # Uses your old JSON loader

            # Migrate Knowledge
            k_data = blob.get("knowledge", {})
            for subj, rels in k_data.items():
                for rel, objs in rels.items():
                    for obj, meta in objs.items():
                        # Extract fields
                        score = meta.get("score", 1.0) if isinstance(meta, dict) else meta
                        concept = meta.get("concept") if isinstance(meta, dict) else None
                        ts = meta.get("last_updated", time.time()) if isinstance(meta, dict) else time.time()

                        self.cursor.execute('''
                            INSERT OR REPLACE INTO knowledge
                            (subject, relation, object, score, concept, last_updated)
                            VALUES (?, ?, ?, ?, ?, ?)
                        ''', (subj, rel, obj, float(score), concept, float(ts)))

            # Migrate Goals
            g_data = blob.get("goals", {})
            for name, g_dict in g_data.items():
                self.cursor.execute('''
                    INSERT OR REPLACE INTO goals (name, data) VALUES (?, ?)
                ''', (name, json.dumps(g_dict)))

            self.conn.commit()
            logger.info("✅ Migration Complete. JSON is now obsolete.")

    def detect_temporal_patterns(self) -> list:
        """
        Detect patterns in event timing (e.g., Error Spikes, Brute Force Clusters).
        Returns: List of pattern findings
        """
        patterns = []
        try:
            # 🟢 FIX: Import locally to avoid scope errors
            from datetime import timedelta

            # Get events from last 24 hours
            start_time = datetime.now() - timedelta(hours=24)
            recent_events = self.query_events(filters={'start_time': start_time}, limit=10000)

            if len(recent_events) < 5: # Lowered limit for testing
                return []

            # 1. Detect Error Rate Spike
            error_events = [e for e in recent_events if e.get('severity') in ['CRITICAL', 'ERROR']]

            # 2. Detect "Machine Gun" Attacks (5 errors in < 5 mins)
            timestamps = []
            for e in error_events:
                ts_str = e['timestamp']
                try:
                    # 🟢 FIX: Handle SQLite default format (Space separator)
                    if 'T' in ts_str:
                        ts = datetime.fromisoformat(ts_str)
                    else:
                        # Handle '2026-02-03 22:00:00' format
                        # Split off microseconds if present
                        main_ts = ts_str.split('.')[0]
                        ts = datetime.strptime(main_ts, "%Y-%m-%d %H:%M:%S")
                    timestamps.append(ts)
                except ValueError:
                    continue

            timestamps.sort()

            if len(timestamps) >= 5:
                for i in range(len(timestamps) - 5):
                    # Check the time difference between Error #1 and Error #5
                    time_span = (timestamps[i+4] - timestamps[i]).total_seconds() # i+4 is the 5th item
                    if time_span < 300:  # 300 seconds = 5 minutes
                        patterns.append({
                            'type': 'ERROR_CLUSTERING',
                            'severity': 'CRITICAL',
                            'description': f'Attack Detected: 5+ critical errors within {int(time_span)} seconds.',
                            'count': 5
                        })
                        break # Found one cluster, stop

            return patterns

        except Exception as e:
            logger.error(f"Pattern detection failed: {e}")
            return []

    def generate_daily_report(self) -> dict:
        """Generate a summary of the last 24 hours."""
        start_time = datetime.now() - timedelta(hours=24)
        events = self.query_events(filters={'start_time': start_time}, limit=10000)

        if not events:
            return {"status": "No events recorded in last 24h"}

        # Calculate Stats
        total = len(events)
        critical = len([e for e in events if e['severity'] == 'CRITICAL'])

        # Top Attacker IP
        from collections import Counter
        ips = [e['source_ip'] for e in events if e['source_ip']]
        top_ip = Counter(ips).most_common(1)
        top_ip_str = top_ip[0][0] if top_ip else "None"

        return {
            "date": datetime.now().strftime("%Y-%m-%d"),
            "total_events": total,
            "critical_events": critical,
            "top_attacker_ip": top_ip_str,
            "status": "Under Attack" if critical > 10 else "Stable"
        }

    # 🟢 BATCH 3: CONFIGURATION & EXPORT METHODS

    def configure_detector(self, **kwargs):
        """
        Configure anomaly detector thresholds.
        Example: brain.configure_detector(brute_force_threshold=3)
        """
        for key, value in kwargs.items():
            threshold_name = key.upper()
            self.anomaly_detector.set_threshold(threshold_name, value)
            self.detector_config[threshold_name] = value

        logger.info(f"🔧 Detector reconfigured")

    def get_detector_config(self) -> dict:
        """Return current detector configuration"""
        return self.detector_config.copy()

    def export_events_to_csv(self, filename: str = "events_export.csv", filters: dict = None) -> bool:
        """Export events to CSV for analysis in Excel/Splunk"""
        try:
            import csv

            events = self.query_events(filters=filters, limit=100000)

            if not events:
                logger.warning("No events to export")
                return False

            with open(filename, 'w', newline='', encoding='utf-8') as f:
                if not events: return False
                # Use keys from the first event as headers
                writer = csv.DictWriter(f, fieldnames=events[0].keys())
                writer.writeheader()
                writer.writerows(events)

            logger.info(f"✅ Exported {len(events)} events to {filename}")
            return True

        except Exception as e:
            logger.error(f"CSV export failed: {e}")
            return False

    def export_alerts_to_csv(self, filename: str = "alerts_export.csv") -> bool:
        """Export alerts to CSV"""
        try:
            import csv

            alerts = self.alert_engine.alert_history

            if not alerts:
                logger.warning("No alerts to export")
                return False

            with open(filename, 'w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=alerts[0].keys())
                writer.writeheader()
                writer.writerows(alerts)

            logger.info(f"✅ Exported {len(alerts)} alerts to {filename}")
            return True

        except Exception as e:
            logger.error(f"Alert export failed: {e}")
            return False

    def shutdown(self, wait: bool = True):
        """
        Gracefully stop background worker threads.

        Args:
            wait (bool): If True, block until threads are fully stopped.
        """
        with self.lock:
            self._stop_healing_worker = True

        if hasattr(self, "_healing_thread") and self._healing_thread.is_alive():
            if wait:
                self._healing_thread.join(timeout=5.0)

# ============================================================================
# 🟢 PHASE 4: SLACK WEBHOOK INTEGRATION
# ============================================================================

class SlackNotifier:
    """
    Sends alerts to Slack via webhooks.
    Simple, no dependencies needed.
    """

    def __init__(self, webhook_url: str = None):
        """
        Initialize Slack notifier.
        webhook_url: Get from Slack -> Your Workspace -> Apps -> Incoming Webhooks
        """
        self.webhook_url = webhook_url
        self.enabled = webhook_url is not None

    def send_alert(self, alert: dict) -> bool:
        """
        Send alert to Slack.
        Returns True if successful.
        """
        if not self.enabled:
            return False

        try:
            import requests

            severity = alert.get('severity', 'UNKNOWN')
            alert_type = alert.get('type', 'UNKNOWN')
            source = alert.get('source', 'unknown')
            message = alert.get('message', '')

            # Color code based on severity
            color_map = {
                'CRITICAL': '#FF0000',  # Red
                'HIGH': '#FF9900',      # Orange
                'WARNING': '#FFFF00',   # Yellow
                'INFO': '#0099FF'       # Blue
            }
            color = color_map.get(severity, '#999999')

            # Build Slack message
            slack_message = {
                "attachments": [
                    {
                        "color": color,
                        "title": f"🚨 {severity} ALERT: {alert_type}",
                        "text": message,
                        "fields": [
                            {
                                "title": "Source",
                                "value": source,
                                "short": True
                            },
                            {
                                "title": "Type",
                                "value": alert_type,
                                "short": True
                            },
                            {
                                "title": "Time",
                                "value": str(alert.get('timestamp', '')),
                                "short": False
                            }
                        ],
                        "footer": "Sentinel Security Platform"
                    }
                ]
            }

            # Send to Slack
            response = requests.post(self.webhook_url, json=slack_message)
            return response.status_code == 200

        except Exception as e:
            logger.error(f"❌ Slack notifier error: {e}")
            return False

    def send_test_message(self) -> bool:
        """Send test message to verify webhook works"""
        if not self.enabled:
            return False

        try:
            import requests
            test_message = {
                "text": "✅ Sentinel is connected! Alerts will appear here."
            }
            response = requests.post(self.webhook_url, json=test_message)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Test message failed: {e}")
            return False



# 🟢 PHASE 4: REST API USING FLASK

def create_api(brain_instance):
    """Create Flask REST API."""
    from flask import Flask, jsonify, request
    from flask_cors import CORS
    from functools import wraps
    import jwt
    from datetime import datetime, timedelta

    app = Flask(__name__)
    app.config['SECRET_KEY'] = 'sentinel-secret-key-change-me'
    CORS(app)

    brain = brain_instance

    # --- AUTH DECORATOR ---
    def token_required(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            if not token:
                return jsonify({'error': 'No token provided'}), 401
            try:
                jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            except:
                return jsonify({'error': 'Invalid token'}), 401
            return f(*args, **kwargs)
        return decorated

    def require_permission(permission: str):
        """Decorator to check if user has permission."""
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                token = request.headers.get('Authorization', '').replace('Bearer ', '')
                if not token:
                    return jsonify({'error': 'No token'}), 401
                try:
                    decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
                    role = decoded.get('role', 'viewer')
                    if not has_permission(role, permission):
                        return jsonify({
                            'error': 'Insufficient permissions',
                            'required': permission,
                            'role': role
                        }), 403
                    return f(*args, **kwargs)
                except jwt.ExpiredSignatureError:
                    return jsonify({'error': 'Token expired'}), 401
                except jwt.InvalidTokenError:
                    return jsonify({'error': 'Invalid token'}), 401
            return decorated_function
        return decorator

    # --- ENDPOINTS ---

    @app.route('/api/stats', methods=['GET'])
    @token_required
    def get_stats():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        workspace_id = decoded.get('workspace_id', 'default')

        events = brain.query_events(workspace_id=workspace_id, limit=5000)
        total_events = len(events)
        service_counts = {}
        for event in events:
            svc = event.get('service', 'unknown')
            service_counts[svc] = service_counts.get(svc, 0) + 1

        return jsonify({
            "total_events": total_events,
            "top_services": service_counts,
            "status": "online"
        })

    @app.route('/api/alerts/summary', methods=['GET'])
    @token_required
    def get_alerts_summary():
        """Returns alert counts by severity."""
        all_alerts = brain.alert_engine.get_recent_alerts(1000)
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "WARNING": 0, "INFO": 0}

        for alert in all_alerts:
            sev = alert.get('severity', 'INFO')
            if sev in severity_counts:
                severity_counts[sev] += 1

        return jsonify({
            "total": len(all_alerts),
            "by_severity": severity_counts,
            "by_type": {}
        })

    @app.route('/api/alerts', methods=['GET'])
    @token_required
    def get_recent_alerts():
        limit = int(request.args.get('limit', 20))
        recent = brain.alert_engine.get_recent_alerts(limit)
        return jsonify({"alerts": recent})

    @app.route('/api/patterns', methods=['GET'])
    @token_required
    def get_patterns():
        patterns_list = []
        if hasattr(brain, 'reasoning_chains'):
            for key, chain in brain.reasoning_chains.items():
                patterns_list.append({
                    "type": "Chain Analysis",
                    "description": f"Linked events for {key}",
                    "count": len(chain),
                    "severity": "HIGH"
                })
        return jsonify({"patterns": patterns_list})

    @app.route('/api/auth/login', methods=['POST'])
    def login():
        data = request.json or {}
        username = data.get('username')
        password = data.get('password')

        # 1. Check Lockout
        status = brain.workspace_manager.check_login_attempts(username)
        if status['locked']:
            return jsonify({'error': 'Account locked', 'message': status['message']}), 429

        # 2. Verify
        user = brain.workspace_manager.verify_user(username, password)

        if user:
            brain.workspace_manager.record_login_attempt(username, success=True)
            brain.workspace_manager.reset_login_attempts(username)

            token = jwt.encode({
                'user': user['username'],
                'workspace_id': user['workspace_id'],
                'role': user['role'],
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm='HS256')

            return jsonify({'token': token, 'workspace_id': user['workspace_id'], 'role': user['role']})
        else:
            brain.workspace_manager.record_login_attempt(username, success=False)
            status = brain.workspace_manager.check_login_attempts(username)
            return jsonify({'error': 'Invalid credentials', 'remaining_attempts': status.get('remaining_attempts')}), 401

    @app.route('/api/auth/forgot-password', methods=['POST'])
    def forgot_password():
        data = request.json or {}
        username = data.get('username')
        token = brain.workspace_manager.create_password_reset_token(username)
        if token:
            # In a real app, send email. For now, return token.
            return jsonify({'status': 'success', 'token': token, 'message': 'Token generated (check console/logs)'})
        return jsonify({'error': 'User not found or error'}), 400

    @app.route('/api/auth/reset-password', methods=['POST'])
    def reset_password_endpoint():
        data = request.json or {}
        if brain.workspace_manager.reset_password(data.get('token'), data.get('new_password')):
            return jsonify({'status': 'success', 'message': 'Password changed'})
        return jsonify({'error': 'Invalid or expired token'}), 400

    @app.route('/api/analyze', methods=['POST'])
    @token_required
    def analyze_logs():
        """Upload and analyze logs"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            role = decoded.get('role', 'viewer')
            workspace_id = decoded.get('workspace_id')

            if not has_permission(role, 'create:analysis'):
                return jsonify({'error': 'Permission denied: need analyst role or higher'}), 403

            if 'file' in request.files:
                file = request.files['file']
                raw_logs = file.read().decode('utf-8')
            elif request.json and 'logs' in request.json:
                raw_logs = request.json['logs']
            else:
                return jsonify({'error': 'No logs provided'}), 400

            result = brain._learn_from_logs(raw_logs, workspace_id=workspace_id)
            return jsonify({
                'status': 'success' if result else 'failed',
                'workspace_id': workspace_id
            }), 200
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return jsonify({'error': str(e)}), 500

    @app.route('/health', methods=['GET'])
    def health():
        return jsonify({'status': 'online', 'version': '1.0'})

    @app.route('/api/workspace/users', methods=['GET'])
    @require_permission('read:events')
    def get_workspace_users():
        """Get all users in workspace"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id')
            users = brain.workspace_manager.get_workspace_users(workspace_id)
            return jsonify({'users': users}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/workspace/invite', methods=['POST'])
    @require_permission('manage:users')
    def invite_user():
        """Invite new user to workspace"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id')
            data = request.json
            email = data.get('email')
            role = data.get('role', 'viewer')

            username = email.split('@')[0]
            temp_password = f"temp_{workspace_id}"
            success = brain.workspace_manager.create_user(
                username=username,
                password=temp_password,
                email=email,
                workspace_id=workspace_id,
                role=role
            )
            if success:
                return jsonify({
                    'status': 'success',
                    'message': f'User invited',
                    'username': username,
                    'temp_password': temp_password
                }), 200
            else:
                return jsonify({'error': 'Failed to invite user'}), 500
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/audit-log', methods=['GET'])
    @require_permission('read:events')
    def get_audit_log():
        """Get audit log for workspace"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id')
            limit = int(request.args.get('limit', 100))

            rows = brain.workspace_manager.conn.execute(
                'SELECT id, action, target_user, created_at FROM audit_log WHERE workspace_id = ? ORDER BY created_at DESC LIMIT ?',
                (workspace_id, limit)
            ).fetchall()

            audit = [{
                'id': row[0],
                'action': row[1],
                'target': row[2],
                'timestamp': row[3]
            } for row in rows]

            return jsonify({'audit_log': audit}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/blocklist', methods=['GET'])
    @token_required
    def get_blocklist():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        workspace_id = decoded.get('workspace_id', 'default')
        btype = request.args.get('type')
        items = brain.blocklist_manager.get_blocklist(workspace_id, btype)
        return jsonify({'blocklist': items})

    @app.route('/api/blocklist/add', methods=['POST'])
    @token_required
    @require_permission('manage:users')
    def manual_block():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        workspace_id = decoded.get('workspace_id', 'default')
        data = request.json
        success = brain.blocklist_manager.add_to_blocklist(
            workspace_id,
            data.get('type', 'ip'),
            data.get('value'),
            reason=data.get('reason', 'Manual block'),
            expires_hours=int(data.get('hours', 24))
        )
        return jsonify({'status': 'success' if success else 'failed'})

    @app.route('/api/response-history', methods=['GET'])
    @token_required
    def get_history():
        token = request.headers.get('Authorization', '').replace('Bearer ', '')
        decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        workspace_id = decoded.get('workspace_id', 'default')
        hist = brain.blocklist_manager.get_response_history(workspace_id)
        return jsonify({'history': hist})

    # 🟢 THREAT INTEL ENDPOINTS (Now safely inside)
    @app.route('/api/threat-intel/check-ip', methods=['GET'])
    @token_required
    def check_ip_threat():
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id', 'default')
            ip = request.args.get('ip')
            if not ip:
                return jsonify({'error': 'IP parameter required'}), 400
            result = brain.threat_intelligence.check_ip(ip, workspace_id)
            return jsonify(result), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/threat-intel/history', methods=['GET'])
    @token_required
    def get_threat_intel_history():
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id', 'default')
            limit = int(request.args.get('limit', 100))
            history = brain.threat_intelligence.get_lookup_history(workspace_id, limit)
            return jsonify({'history': history}), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/forensics/timeline', methods=['GET'])
    @token_required
    def get_forensics_timeline():
        """Get event timeline for investigation"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id', 'default')

            alert_id = request.args.get('alert_id')
            # Note: We allow generating a timeline even without a specific alert ID for general view

            # Get events from database
            events = brain.query_events(workspace_id, limit=1000)

            # Create timeline
            timeline = brain.forensics_engine.create_timeline(workspace_id, events)

            return jsonify(timeline), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    @app.route('/api/forensics/investigation', methods=['GET'])
    @token_required
    def get_forensics_investigation():
        """Get complete forensic investigation"""
        try:
            token = request.headers.get('Authorization', '').replace('Bearer ', '')
            decoded = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            workspace_id = decoded.get('workspace_id', 'default')

            alert_id = request.args.get('alert_id')
            if not alert_id:
                return jsonify({'error': 'alert_id parameter required'}), 400

            # Get events and alerts
            events = brain.query_events(workspace_id, limit=1000)
            alerts = brain.alert_engine.get_recent_alerts(1000)

            # Create investigation
            investigation = brain.forensics_engine.create_investigation(
                workspace_id,
                alert_id,
                events,
                alerts
            )

            return jsonify(investigation), 200
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    return app  # 🔴 THIS MUST BE THE LAST LINE OF create_api

def run_sentinel_api(brain_instance, slack_webhook_url: str = None, port: int = 5000):
    """Run the API Server"""
    brain_instance.slack_notifier = SlackNotifier(webhook_url=slack_webhook_url)
    if slack_webhook_url:
        logger.info("🔔 Testing Slack connection...")
        if brain_instance.slack_notifier.send_test_message():
            logger.info("✅ Slack Connected!")
        else:
            logger.warning("⚠️ Slack connection failed.")

    original_fire = brain_instance.alert_engine.fire
    def fire_with_slack(anomalies):
        original_fire(anomalies)
        if brain_instance.slack_notifier.enabled:
            for a in anomalies:
                brain_instance.slack_notifier.send_alert(a)
    brain_instance.alert_engine.fire = fire_with_slack

    logger.info(f"🚀 Sentinel API active on port {port}")
    app = create_api(brain_instance)
    app.run(host='0.0.0.0', port=port, debug=False)
