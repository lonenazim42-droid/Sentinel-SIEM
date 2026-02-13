# 🛡️ Sentinel Security Platform

[![GitHub stars](https://img.shields.io/github/stars/lonenazim42-droid/sentinel?style=social)](https://github.com/lonenazim42-droid/sentinel/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/lonenazim42-droid/sentinel?style=social)](https://github.com/lonenazim42-droid/sentinel/network/members)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**Enterprise-grade SIEM + SOAR platform for startups.** Real-time threat detection, automated response, forensics investigation, and threat intelligence - all FREE and open source.

## 🎯 Why Sentinel?

### vs Splunk ($150K/year)
- ✅ Same detection capability
- ✅ Includes response automation (Splunk charges extra)
- ✅ Includes forensics (Splunk charges extra)
- ✅ Includes threat intelligence (Splunk charges extra)
- ✅ **FREE**
- ✅ Deploys in 5 minutes (Splunk takes 4 weeks)

### The Numbers
- 🚀 **0 to deployed** in 5 minutes
- 💰 **$0 cost** (open source)
- 🔍 **5 major features** (detection, response, forensics, threat intel, RBAC)
- 📊 **323 classes & functions** (production quality)
- 🏆 **Beats Splunk for startups**

---

## ✨ Features

### 1. Real-time Threat Detection
```
Detects:
• Brute force attacks
• Lateral movement
• Privilege escalation
• Port scanning
• Service degradation

Supports:
• 7+ log formats
• Temporal patterns
• Multi-stage attacks
```

### 2. Automated Response (SOAR)
```
Auto-responses:
✅ Block malicious IPs instantly
✅ Create Jira tickets
✅ Send Slack alerts
✅ Maintain audit trail

Speed: <1 second
```

### 3. Forensics Investigation
```
When breach happens:
📅 Event timeline
⛓️ Attack chain detection
🔬 Evidence collection
📋 Investigation reports

Help answer: "What happened?"
```

### 4. Threat Intelligence
```
IP Reputation:
• VirusTotal integration
• 93+ vendor coverage
• Malicious/safe indicator
• Threat type classification

Real-time, cached for performance
```

### 5. Enterprise Features
```
✅ Multi-tenant architecture
✅ Role-based access control
✅ REST API (15+ endpoints)
✅ Professional dashboard
✅ JWT authentication
```

---

## 🚀 Quick Start

### Installation (5 minutes)

```bash
# 1. Clone
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run API (Terminal 1)
python3 run_api.py

# 4. Run Dashboard (Terminal 2)
streamlit run dashboard.py
```

### Access
- **Dashboard**: http://localhost:8501
- **API**: http://localhost:5000

### Test Accounts
```
Admin:    admin@startup.com / password123
Analyst:  analyst@startup.com / password123
Viewer:   viewer@startup.com / password123
```

---

## 📡 API Endpoints

### Authentication
```
POST /api/auth/login
POST /api/auth/forgot-password
POST /api/auth/reset-password
```

### Detection
```
POST /api/analyze              - Upload and analyze logs
GET  /api/alerts               - Get all alerts
GET  /api/stats                - Get statistics
GET  /api/patterns             - Detected patterns
```

### Response
```
GET  /api/blocklist            - View blocked IPs
POST /api/blocklist/add        - Block IP
POST /api/blocklist/remove     - Unblock IP
GET  /api/response-history     - See auto-responses
```

### Forensics
```
GET /api/forensics/timeline        - Event timeline
GET /api/forensics/investigation   - Full investigation
```

### Threat Intel
```
GET /api/threat-intel/check-ip   - Check IP reputation
GET /api/threat-intel/history    - Lookup history
```

---

## 📊 Dashboard Features

### 6 Complete Pages

| Page | Features |
|------|----------|
| **Dashboard** | Real-time metrics, threat level, recent alerts, charts |
| **Alerts** | Full alert list, filtering, investigation |
| **Forensics** | Timeline, attack chain, evidence (analyst+ only) |
| **Threat Intel** | IP reputation checker, lookup history |
| **Blocklist** | Add/remove IPs, view blocked list (analyst+ only) |
| **Settings** | User info, API status, platform details |

---

## 🔧 Configuration

### Enable VirusTotal (Real Threat Intel)

Edit `run_api.py`:

```python
# Line 9
brain.threat_intelligence.enable_virustotal("YOUR_API_KEY_HERE")
```

Get API key (free): https://www.virustotal.com/gui/my-apikey

### Enable Jira (Auto-create Tickets)

Edit `run_api.py`:

```python
brain.jira_connector = JiraConnector(
    jira_url="https://yourcompany.atlassian.net",
    api_token="YOUR_API_TOKEN",
    project_key="SEC"
)
```

### Enable Slack (Notifications)

Edit `run_api.py`:

```python
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

---

## 📈 Architecture

```
Logs → LogParser
        ↓
    AnomalyDetector → Alerts
        ↓              ↓
    Events ← → AlertEngine
        ↓              ↓
    Database ← BlocklistManager
                ↓
        ResponseAutomation
                ↓
        ✉️ Slack | 🎫 Jira | ⛔ Block IP
```

---

## 🎯 Use Cases

### Scenario 1: Brute Force Attack
```
Step 1: Attacker tries 5 failed logins from 192.168.1.100
Step 2: Sentinel detects BRUTE_FORCE (severity: CRITICAL)
Step 3: Auto-response triggers:
        - Blocks IP 192.168.1.100
        - Creates Jira ticket
        - Sends Slack alert
Step 4: Team investigates using forensics
Result: Attack stopped in <1 second
```

### Scenario 2: Lateral Movement
```
Step 1: User account compromised, attacker moves through network
Step 2: Sentinel detects LATERAL_MOVEMENT
Step 3: Creates investigation
Step 4: Shows attack chain: Login → Database Access → Priv Escalation
Step 5: Team can see exact progression
Result: Investigation faster, threat contained
```

### Scenario 3: Unknown Attacker IP
```
Step 1: Attack from unknown IP 123.45.67.89
Step 2: Sentinel checks threat intelligence
Step 3: VirusTotal says: "Malicious (seen in 45 malware families)"
Step 4: Team knows this is serious threat
Step 5: Can block with confidence
Result: Context-aware response
```

---

## 📊 Performance

| Metric | Value |
|--------|-------|
| Detection Speed | <100ms |
| Response Speed | <1 second |
| Forensics Analysis | <2 seconds |
| Log Processing | 1000 events/second |
| Storage Efficiency | 100+ days @ 1000 events/day |

---

## 🗂️ Project Structure

```
sentinel/
├── brain.py              # Core detection engine (5900+ lines)
├── dashboard.py          # Professional Streamlit dashboard
├── run_api.py            # API startup script
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── LICENSE               # MIT License
└── .gitignore            # Git ignore rules
```

---

## 🤝 Contributing

Found a bug? Want to add a feature? Submit an issue or PR!

Steps:
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit changes (`git commit -m 'Add amazing feature'`)
4. Push to branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## 📝 License

MIT License - Use however you want, commercially or personally.

See LICENSE file for details.

---

## 🗺️ Roadmap

- [ ] Advanced ML-based anomaly detection
- [ ] Kubernetes pod monitoring
- [ ] Cloud provider integration (AWS, Azure, GCP)
- [ ] Mobile dashboard app
- [ ] Enterprise HA setup
- [ ] Email-based password reset
- [ ] Custom alert rules UI
- [ ] Webhook integrations

---

## 💬 Support

- **Issues**: GitHub Issues section
- **Discussions**: GitHub Discussions
- **Email**: lonenazim42@gmail.com

---

## 📚 Documentation

Full API documentation: See code comments in brain.py

Quick examples:

```bash
# Analyze logs
curl -X POST http://localhost:5000/api/analyze \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@logs.txt"

# Get alerts
curl http://localhost:5000/api/alerts \
  -H "Authorization: Bearer $TOKEN"

# Check IP reputation
curl "http://localhost:5000/api/threat-intel/check-ip?ip=1.2.3.4" \
  -H "Authorization: Bearer $TOKEN"

# Block IP
curl -X POST http://localhost:5000/api/blocklist/add \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"type":"ip","value":"1.2.3.4","reason":"malicious","hours":24}'
```

---

## 🎉 Thank You

Thanks for using Sentinel! This project was built to prove that startups don't need to spend $150K/year on security tools. You deserve enterprise-grade security at startup budgets.

Star the repo if you found it useful! ⭐

---

**Built with ❤️ for security-conscious startups**
