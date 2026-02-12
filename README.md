\# 🛡️ Sentinel: Automated SIEM \& SOAR for Startups



Sentinel is a lightweight, open-source security platform designed to bridge the gap between simple logging and expensive enterprise tools like Splunk. It combines \*\*Real-Time Threat Detection\*\* with \*\*Active Response Automation\*\*.



\## Key Features



1. Automated Detection: Identifies Brute Force attacks, Port Scans, and Lateral Movement in real-time.

2. Active Defense (SOAR):  Automatically bans malicious IPs and locks compromised user accounts (Brute Force Protection).

3. Forensics Engine:  Reconstructs attack timelines and visualizes "Attack Chains" for investigators.

4. Threat Intelligence: Integrated with VirusTotal API to validate suspicious IPs.

5. Professional Dashboard: A full UI built with Streamlit for monitoring alerts and managing blocklists.


///Integration: Slack Notifications
Sentinel supports real-time alerting via Slack Incoming Webhooks. When a threat is detected or an IP is automatically blocked, Sentinel pushes a notification to your designated security channel.

How to enable:

Create a Slack App: Go to the Slack API Dashboard and create a new app called "Sentinel".

Enable Webhooks: Under "Features", click "Incoming Webhooks" and toggle it to On.

Generate URL: Click "Add New Webhook to Workspace", choose your channel, and copy the Webhook URL.

Configure Sentinel: Open run_api.py and update the following line:

Python
# Replace 'YOUR_WEBHOOK_URL_HERE' with your actual Webhook URL
SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX"
What you'll get:

Instant Alerts: Notifications for Critical and High severity detections (Brute Force, Lateral Movement).

Action Receipts: Confirmation messages whenever the system automatically bans an IP or locks an account.

Contextual Data: Every alert includes the Attacker IP, Target User, and a direct link to the investigation timeline.



\## 🚀 Quick Start



\*\*1. Clone the Repository\*\*

```bash

git clone \[https://github.com/lonenazim42-droid/Sentinel-SIEM.git](https://github.com/lonenazim42-droidE/Sentinel-SIEM.git)

cd Sentinel-SIEM

