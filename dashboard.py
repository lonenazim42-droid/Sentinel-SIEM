import streamlit as st
import requests
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from datetime import datetime, timedelta
import json
from functools import wraps

# ============================================================================
# PAGE CONFIG
# ============================================================================

st.set_page_config(
    page_title="Sentinel Security Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================================
# STYLING
# ============================================================================

st.markdown("""
    <style>
    /* Main Layout */
    .main {
        padding-top: 2rem;
    }

    /* Cards */
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin: 10px 0;
    }

    /* Alert Severity Colors */
    .alert-critical {
        color: #FF0000;
        font-weight: bold;
    }

    .alert-high {
        color: #FF9900;
        font-weight: bold;
    }

    .alert-warning {
        color: #FFCC00;
        font-weight: bold;
    }

    .alert-info {
        color: #0099FF;
        font-weight: bold;
    }

    /* Threat Level */
    .threat-critical {
        background-color: #FFE0E0;
        border-left: 5px solid #FF0000;
        padding: 15px;
        border-radius: 5px;
    }

    .threat-high {
        background-color: #FFE8CC;
        border-left: 5px solid #FF9900;
        padding: 15px;
        border-radius: 5px;
    }

    .threat-medium {
        background-color: #FFFACD;
        border-left: 5px solid #FFCC00;
        padding: 15px;
        border-radius: 5px;
    }

    .threat-low {
        background-color: #E0FFE0;
        border-left: 5px solid #00CC00;
        padding: 15px;
        border-radius: 5px;
    }

    /* Timeline */
    .timeline-item {
        border-left: 3px solid #667eea;
        padding: 15px;
        margin: 10px 0;
    }

    /* Evidence Box */
    .evidence-box {
        background-color: #f0f2f6;
        padding: 15px;
        border-radius: 8px;
        margin: 10px 0;
    }
    </style>
""", unsafe_allow_html=True)

# ============================================================================
# SESSION STATE
# ============================================================================

if 'token' not in st.session_state:
    st.session_state.token = None

if 'api_url' not in st.session_state:
    st.session_state.api_url = "http://localhost:5000"

if 'user_role' not in st.session_state:
    st.session_state.user_role = None

if 'username' not in st.session_state:
    st.session_state.username = None

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def can_access(required_role):
    """Check if user has required role"""
    role_hierarchy = {'admin': 3, 'analyst': 2, 'viewer': 1}
    user_level = role_hierarchy.get(st.session_state.user_role, 0)
    required_level = role_hierarchy.get(required_role, 0)
    return user_level >= required_level

def get_threat_level_color(critical_count, high_count):
    """Determine threat level and color"""
    if critical_count > 5:
        return "🔴 CRITICAL", "#FF0000", "threat-critical"
    elif critical_count > 0 or high_count > 10:
        return "🟠 HIGH", "#FF9900", "threat-high"
    elif high_count > 0:
        return "🟡 MEDIUM", "#FFCC00", "threat-medium"
    else:
        return "🟢 LOW", "#00CC00", "threat-low"

def format_timestamp(ts):
    """Format timestamp for display"""
    try:
        if isinstance(ts, str):
            return ts[:19]  # Cut to YYYY-MM-DD HH:MM:SS
        return str(ts)[:19]
    except:
        return str(ts)

# ============================================================================
# SIDEBAR LOGIN & NAVIGATION
# ============================================================================

with st.sidebar:
    st.markdown("# 🛡️")
    st.title("Sentinel")
    st.divider()

    if not st.session_state.token:
        # LOGIN SECTION
        st.subheader("🔐 Login")

        username = st.text_input(
            "Username",
            value="admin@startup.com",
            placeholder="admin@startup.com"
        )

        password = st.text_input(
            "Password",
            type="password",
            value="password123",
            placeholder="password123"
        )

        if st.button("🔓 Login", use_container_width=True, type="primary"):
            try:
                response = requests.post(
                    f"{st.session_state.api_url}/api/auth/login",
                    json={"username": username, "password": password},
                    timeout=5
                )

                if response.status_code == 200:
                    data = response.json()
                    st.session_state.token = data['token']
                    st.session_state.username = username
                    st.session_state.user_role = 'admin'  # Will be extracted from token in future
                    st.success("✅ Logged in!")
                    st.rerun()
                elif response.status_code == 429:
                    # 🟢 NEW: Handle Lockout Message specifically
                    error_msg = response.json().get('message', 'Account locked')
                    st.error(f"⛔ {error_msg}")
                else:
                    # Handle generic errors
                    st.error("❌ Invalid credentials")
            except Exception as e:
                st.error(f"❌ Connection error: {e}")

    else:
        # LOGGED IN SECTION
        st.success(f"✅ Logged in as {st.session_state.username}")

        st.divider()

        # NAVIGATION
        st.subheader("📍 Navigation")
        page = st.radio(
            "Select Page",
            options=[
                "🏠 Dashboard",
                "🚨 Alerts",
                "🔎 Forensics",
                "🛡️ Threat Intel",
                "⛔ Blocklist",
                "⚙️ Settings"
            ],
            label_visibility="collapsed"
        )

        st.divider()

        # API CONFIG
        st.subheader("⚙️ API Configuration")
        api_url = st.text_input(
            "API URL",
            value=st.session_state.api_url,
            help="Base URL for Sentinel API"
        )
        if api_url != st.session_state.api_url:
            st.session_state.api_url = api_url

        st.divider()

        # USER INFO
        st.subheader("ℹ️ User Info")
        st.text(f"Role: {st.session_state.user_role or 'N/A'}")
        st.text(f"Status: 🟢 Connected")

        st.divider()

        # LOGOUT
        if st.button("🔒 Logout", use_container_width=True):
            st.session_state.token = None
            st.session_state.user_role = None
            st.session_state.username = None
            st.rerun()

        st.divider()

        st.caption("🛡️ Sentinel Security Platform v1.0")

# ============================================================================
# MAIN CONTENT - CHECK LOGIN
# ============================================================================

if not st.session_state.token:
    st.warning("⚠️ Please login to access Sentinel Dashboard")
    st.stop()

headers = {"Authorization": f"Bearer {st.session_state.token}"}

# ============================================================================
# PAGE ROUTING
# ============================================================================

if page == "🏠 Dashboard":
    # ========== DASHBOARD PAGE ==========

    st.title("🛡️ Sentinel Security Dashboard")

    col1, col2, col3 = st.columns([2, 1, 1])
    with col1:
        pass
    with col2:
        if st.button("🔄 Refresh"):
            st.rerun()
    with col3:
        if st.button("📊 Export"):
            st.info("Export feature coming soon")

    st.divider()

    try:
        # FETCH DATA
        stats_resp = requests.get(f"{st.session_state.api_url}/api/stats", headers=headers, timeout=5)
        alerts_resp = requests.get(f"{st.session_state.api_url}/api/alerts/summary", headers=headers, timeout=5)
        alerts_detail = requests.get(f"{st.session_state.api_url}/api/alerts?limit=100", headers=headers, timeout=5)

        if stats_resp.status_code == 200 and alerts_resp.status_code == 200:
            stats = stats_resp.json()
            alerts_stats = alerts_resp.json()
            alerts_list = alerts_detail.json().get('alerts', []) if alerts_detail.status_code == 200 else []

            # THREAT LEVEL CARD
            critical_count = alerts_stats.get('by_severity', {}).get('CRITICAL', 0)
            high_count = alerts_stats.get('by_severity', {}).get('HIGH', 0)

            threat_text, threat_color, threat_class = get_threat_level_color(critical_count, high_count)

            st.markdown(f'<div class="{threat_class}">', unsafe_allow_html=True)
            st.metric("🎯 Threat Level", threat_text)
            st.markdown('</div>', unsafe_allow_html=True)

            st.divider()

            # KEY METRICS
            col1, col2, col3, col4, col5 = st.columns(5)

            with col1:
                st.metric("📊 Total Events", stats.get('total_events', 0))

            with col2:
                st.metric("🚨 Critical Alerts", critical_count)

            with col3:
                st.metric("⚠️ High Alerts", high_count)

            with col4:
                st.metric("📋 Total Alerts", alerts_stats.get('total', 0))

            with col5:
                st.metric("🖥️ Services", len(stats.get('top_services', {})))

            st.divider()

            # RECENT ALERTS TABLE
            st.subheader("📋 Recent Alerts")

            if alerts_list:
                # Create dataframe
                df_alerts = pd.DataFrame(alerts_list[:20])

                # Custom display
                for idx, alert in enumerate(alerts_list[:10]):
                    col1, col2, col3, col4 = st.columns([1, 2, 2, 1])

                    severity = alert.get('severity', 'INFO')

                    with col1:
                        if severity == 'CRITICAL':
                            st.markdown('<span class="alert-critical">🔴 CRITICAL</span>', unsafe_allow_html=True)
                        elif severity == 'HIGH':
                            st.markdown('<span class="alert-high">🟠 HIGH</span>', unsafe_allow_html=True)
                        elif severity == 'WARNING':
                            st.markdown('<span class="alert-warning">🟡 WARNING</span>', unsafe_allow_html=True)
                        else:
                            st.markdown('<span class="alert-info">🔵 INFO</span>', unsafe_allow_html=True)

                    with col2:
                        st.write(f"**{alert.get('type', 'Unknown')}**")
                        st.caption(alert.get('message', '')[:80])

                    with col3:
                        st.caption(f"From: {alert.get('source_ip', 'N/A')}")
                        st.caption(f"Time: {format_timestamp(alert.get('timestamp', 'N/A'))}")

                    with col4:
                        if can_access('analyst'):
                            if st.button("🔎 Investigate", key=f"inv_{idx}"):
                                st.session_state.selected_alert = alert.get('id', str(idx))
                                st.rerun()

                    st.divider()
            else:
                st.info("✅ No recent alerts")

            st.divider()

            # CHARTS
            col1, col2 = st.columns(2)

            with col1:
                st.subheader("📊 Alerts by Severity")
                severity_data = alerts_stats.get('by_severity', {})

                if severity_data:
                    fig = go.Figure(data=[
                        go.Bar(
                            x=list(severity_data.keys()),
                            y=list(severity_data.values()),
                            marker_color=['#FF0000', '#FF9900', '#FFFF00', '#0099FF'][:len(severity_data)]
                        )
                    ])
                    fig.update_layout(
                        xaxis_title="Severity",
                        yaxis_title="Count",
                        height=300,
                        showlegend=False
                    )
                    st.plotly_chart(fig, use_container_width=True)

            with col2:
                st.subheader("🖥️ Top Services")
                services_data = stats.get('top_services', {})

                if services_data:
                    fig = go.Figure(data=[
                        go.Bar(
                            x=list(services_data.keys())[:5],
                            y=list(services_data.values())[:5],
                            marker_color='#667eea'
                        )
                    ])
                    fig.update_layout(
                        xaxis_title="Service",
                        yaxis_title="Event Count",
                        height=300,
                        showlegend=False
                    )
                    st.plotly_chart(fig, use_container_width=True)

        else:
            st.error("❌ Failed to fetch statistics")

    except Exception as e:
        st.error(f"❌ Error: {e}")

elif page == "🚨 Alerts":
    # ========== ALERTS PAGE ==========

    st.title("🚨 Alert Management")

    try:
        alerts_resp = requests.get(f"{st.session_state.api_url}/api/alerts?limit=200", headers=headers, timeout=5)

        if alerts_resp.status_code == 200:
            alerts_list = alerts_resp.json().get('alerts', [])

            # FILTER OPTIONS
            col1, col2, col3 = st.columns(3)
            with col1:
                severity_filter = st.selectbox("Filter by Severity", ["ALL", "CRITICAL", "HIGH", "WARNING", "INFO"])
            with col2:
                alert_type_filter = st.text_input("Filter by Type")
            with col3:
                limit = st.slider("Show", 10, 200, 50)

            st.divider()

            # DISPLAY ALERTS
            filtered_alerts = alerts_list[:limit]

            if severity_filter != "ALL":
                filtered_alerts = [a for a in filtered_alerts if a.get('severity') == severity_filter]

            if alert_type_filter:
                filtered_alerts = [a for a in filtered_alerts if alert_type_filter.lower() in a.get('type', '').lower()]

            st.info(f"📊 Showing {len(filtered_alerts)} alerts")

            for idx, alert in enumerate(filtered_alerts):
                with st.container():
                    col1, col2, col3, col4, col5 = st.columns([0.5, 1.5, 2, 1.5, 1])

                    severity = alert.get('severity', 'INFO')

                    with col1:
                        if severity == 'CRITICAL':
                            st.markdown('🔴')
                        elif severity == 'HIGH':
                            st.markdown('🟠')
                        elif severity == 'WARNING':
                            st.markdown('🟡')
                        else:
                            st.markdown('🔵')

                    with col2:
                        st.write(f"**{alert.get('type', 'Unknown')}**")
                        st.caption(severity)

                    with col3:
                        st.caption(alert.get('message', '')[:100])

                    with col4:
                        st.caption(f"{alert.get('source_ip', 'N/A')}")
                        st.caption(f"{format_timestamp(alert.get('timestamp', 'N/A'))}")

                    with col5:
                        if can_access('analyst'):
                            if st.button("🔎", key=f"alert_inv_{idx}", help="Investigate"):
                                st.session_state.selected_alert_id = alert.get('id', str(idx))

                    st.divider()
        else:
            st.error("Failed to fetch alerts")

    except Exception as e:
        st.error(f"Error: {e}")

elif page == "🔎 Forensics":
    # ========== FORENSICS PAGE ==========

    if not can_access('analyst'):
        st.error("🔒 Only analysts and admins can access forensics")
        st.stop()

    st.title("🔎 Forensics Investigation")

    # INVESTIGATION ID INPUT
    investigation_id = st.text_input("Enter Alert ID to investigate", "test_alert")

    if st.button("🔎 Start Investigation"):
        try:
            inv_resp = requests.get(
                f"{st.session_state.api_url}/api/forensics/investigation?alert_id={investigation_id}",
                headers=headers,
                timeout=5
            )

            if inv_resp.status_code == 200:
                investigation = inv_resp.json()

                # TIMELINE
                st.subheader("📅 Event Timeline")
                timeline = investigation.get('timeline', {})

                if timeline.get('timeline'):
                    for event in timeline['timeline']:
                        st.markdown(f'<div class="timeline-item">', unsafe_allow_html=True)
                        col1, col2 = st.columns([1, 3])

                        with col1:
                            st.caption(f"**{event.get('time')}**")

                        with col2:
                            st.write(f"**{event.get('type')}** ({event.get('severity')})")
                            st.caption(event.get('details', ''))

                        st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.info("No timeline data")

                st.divider()

                # ATTACK CHAIN
                st.subheader("⛓️ Attack Chain")
                attack_chain = investigation.get('attack_chain', {})

                if attack_chain.get('detected'):
                    st.success(f"🚨 Attack progression detected! Confidence: {attack_chain.get('confidence', 0)*100:.0f}%")

                    for stage in attack_chain.get('chain', []):
                        st.markdown(f'<div class="timeline-item">', unsafe_allow_html=True)
                        st.write(f"**Stage {stage.get('stage')}**: {stage.get('type')}")
                        st.caption(f"Severity: {stage.get('severity')} | Source: {stage.get('source_ip')}")
                        st.markdown('</div>', unsafe_allow_html=True)
                else:
                    st.info("No clear attack progression detected")

                st.divider()

                # EVIDENCE
                st.subheader("🔬 Evidence Collected")
                evidence = investigation.get('evidence', {})

                if evidence:
                    col1, col2, col3, col4 = st.columns(4)

                    with col1:
                        st.metric("Total Events", evidence.get('total_events', 0))
                    with col2:
                        st.metric("Total Alerts", evidence.get('total_alerts', 0))
                    with col3:
                        st.metric("Critical", evidence.get('critical_alerts', 0))
                    with col4:
                        st.metric("High", evidence.get('high_alerts', 0))

                    st.divider()

                    st.subheader("📍 Sources")
                    col1, col2 = st.columns(2)

                    with col1:
                        st.write("**Source IPs**")
                        for ip in evidence.get('unique_source_ips', [])[:5]:
                            st.caption(f"• {ip}")

                    with col2:
                        st.write("**Attack Types**")
                        for atype in evidence.get('attack_types', []):
                            st.caption(f"• {atype}")

                    st.divider()
                    st.info(f"**Evidence Strength**: {evidence.get('evidence_strength', 'UNKNOWN')}")

            else:
                st.error("Failed to get investigation")

        except Exception as e:
            st.error(f"Error: {e}")

elif page == "🛡️ Threat Intel":
    # ========== THREAT INTELLIGENCE PAGE ==========

    st.title("🛡️ Threat Intelligence")

    # IP CHECK
    st.subheader("🔍 Check IP Reputation")

    ip_to_check = st.text_input("Enter IP Address", "8.8.8.8")

    if st.button("🔎 Check IP"):
        try:
            ti_resp = requests.get(
                f"{st.session_state.api_url}/api/threat-intel/check-ip?ip={ip_to_check}",
                headers=headers,
                timeout=5
            )

            if ti_resp.status_code == 200:
                threat_data = ti_resp.json()

                st.divider()

                col1, col2, col3 = st.columns(3)

                with col1:
                    is_malicious = threat_data.get('is_malicious', False)
                    if is_malicious:
                        st.error("🔴 MALICIOUS")
                    else:
                        st.success("🟢 SAFE")

                with col2:
                    confidence = threat_data.get('confidence', 0)
                    st.metric("Confidence", f"{confidence*100:.0f}%")

                with col3:
                    st.metric("Vendors", threat_data.get('details', 'N/A'))

                st.divider()

                st.subheader("📊 Details")
                col1, col2 = st.columns(2)

                with col1:
                    st.write(f"**IP**: {threat_data.get('ip')}")
                    st.write(f"**Source**: {threat_data.get('source')}")

                with col2:
                    threat_types = threat_data.get('threat_types', [])
                    st.write(f"**Threat Types**: {', '.join(threat_types) if threat_types else 'None'}")

                st.info(threat_data.get('details', 'No additional details'))

            else:
                st.error("Failed to check IP")

        except Exception as e:
            st.error(f"Error: {e}")

    st.divider()

    # THREAT INTEL HISTORY
    st.subheader("📜 Lookup History")

    try:
        history_resp = requests.get(
            f"{st.session_state.api_url}/api/threat-intel/history?limit=50",
            headers=headers,
            timeout=5
        )

        if history_resp.status_code == 200:
            history = history_resp.json().get('history', [])

            if history:
                df_history = pd.DataFrame(history)
                st.dataframe(df_history, use_container_width=True)
            else:
                st.info("No lookup history")

        else:
            st.error("Failed to fetch history")

    except Exception as e:
        st.error(f"Error: {e}")

elif page == "⛔ Blocklist":
    # ========== BLOCKLIST PAGE ==========

    if not can_access('analyst'):
        st.error("🔒 Only analysts and admins can manage blocklist")
        st.stop()

    st.title("⛔ IP Blocklist Management")

    # ADD TO BLOCKLIST
    st.subheader("➕ Add to Blocklist")

    col1, col2, col3 = st.columns(3)

    with col1:
        block_type = st.selectbox("Type", ["ip", "user"])

    with col2:
        block_value = st.text_input("Value (IP or Username)")

    with col3:
        block_reason = st.text_input("Reason", "Security threat")

    if st.button("🚫 Block"):
        if block_value:
            try:
                resp = requests.post(
                    f"{st.session_state.api_url}/api/blocklist/add",
                    headers=headers,
                    json={
                        "type": block_type,
                        "value": block_value,
                        "reason": block_reason,
                        "hours": 24
                    },
                    timeout=5
                )

                if resp.status_code == 200:
                    st.success(f"✅ {block_value} blocked successfully")
                    st.rerun()
                else:
                    st.error("Failed to block")

            except Exception as e:
                st.error(f"Error: {e}")
        else:
            st.error("Enter a value to block")

    st.divider()

    # VIEW BLOCKLIST
    st.subheader("📋 Current Blocklist")

    try:
        resp = requests.get(f"{st.session_state.api_url}/api/blocklist", headers=headers, timeout=5)

        if resp.status_code == 200:
            blocklist = resp.json().get('blocklist', [])

            if blocklist:
                for idx, item in enumerate(blocklist):
                    col1, col2, col3, col4 = st.columns([1, 2, 2, 1])

                    with col1:
                        st.write(f"**{item.get('type')}**")

                    with col2:
                        st.write(item.get('value'))

                    with col3:
                        st.caption(item.get('reason', ''))

                    with col4:
                        if st.button("🔓 Unblock", key=f"unblock_{idx}"):
                            try:
                                requests.post(
                                    f"{st.session_state.api_url}/api/blocklist/remove",
                                    headers=headers,
                                    json={"type": item.get('type'), "value": item.get('value')},
                                    timeout=5
                                )
                                st.success("Unblocked")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error: {e}")

                    st.divider()
            else:
                st.info("✅ Blocklist is empty")

        else:
            st.error("Failed to fetch blocklist")

    except Exception as e:
        st.error(f"Error: {e}")

elif page == "⚙️ Settings":
    # ========== SETTINGS PAGE ==========

    st.title("⚙️ Settings")

    st.subheader("👤 User Information")
    st.info(f"Username: {st.session_state.username}")
    st.info(f"Role: {st.session_state.user_role or 'viewer'}")
    st.info(f"API URL: {st.session_state.api_url}")

    st.divider()

    st.subheader("📡 API Status")

    try:
        resp = requests.get(f"{st.session_state.api_url}/api/stats", headers=headers, timeout=5)

        if resp.status_code == 200:
            st.success("✅ API is connected and responding")
        else:
            st.error("❌ API returned an error")

    except Exception as e:
        st.error(f"❌ Cannot connect to API: {e}")

    st.divider()

    st.subheader("ℹ️ Platform Information")
    st.info("""
    **Sentinel Security Platform v1.0**

    Features:
    • Real-time threat detection
    • Automatic response automation
    • Forensics investigation
    • Threat intelligence integration
    • Multi-tenant architecture
    • Role-based access control

    For support, visit: https://github.com/yourrepo/sentinel
    """)

# ============================================================================
# FOOTER
# ============================================================================

st.divider()
st.caption("🛡️ Sentinel Security Platform | Enterprise-Grade SIEM for Startups")

