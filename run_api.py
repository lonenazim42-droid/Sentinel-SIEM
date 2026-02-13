from brain import Brain, run_sentinel_api
import os

if __name__ == '__main__':
    print("🛡️ SENTINEL - Starting REST API (RBAC Mode)...")

    brain = Brain()

    brain.threat_intelligence.enable_virustotal("YOUR_API_KEY_HERE")

    # Provision Test Users
    print("📦 Provisioning users...")

    ws_id = brain.workspace_manager.create_workspace("Startup Inc", owner_id=1)
    if ws_id:
        # 1. The Boss (Admin)
        brain.workspace_manager.create_user("admin@startup.com", "password123", "admin", ws_id, "admin")

        # 2. The Worker (Analyst)
        brain.workspace_manager.create_user("analyst@startup.com", "password123", "analyst", ws_id, "analyst")

        # 3. The Intern (Viewer)
        brain.workspace_manager.create_user("viewer@startup.com", "password123", "viewer", ws_id, "viewer")

        print("✅ Users Created:")
        print("   - admin@startup.com (Can do everything)")
        print("   - analyst@startup.com (Can upload logs, NO invites)")
        print("   - viewer@startup.com (Read only)")

    SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/YOUR_WEBHOOK_URL_HERE"
    run_sentinel_api(brain, slack_webhook_url=SLACK_WEBHOOK_URL, port=5000)

    run_sentinel_api(
        brain,
        slack_webhook_url=SLACK_WEBHOOK_URL,
        port=5000
    )
