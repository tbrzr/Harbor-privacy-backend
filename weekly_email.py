#!/usr/bin/env python3
import json, os, sys, requests
from datetime import datetime

sys.path.insert(0, '/home/ubuntu/harbor-backend')

CUSTOMERS_LOG = "/var/log/harbor-customers.json"
USERS_FILE = "/var/log/harbor-dashboard-users.json"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "Harbor2026!")

def get_client_stats(client_id):
    try:
        r = requests.get(f"{ADGUARD_URL}/control/stats", auth=(ADGUARD_USER, ADGUARD_PASS), timeout=5)
        data = r.json()
        clients = data.get("top_clients", [])
        for c in clients:
            if client_id in c:
                return c[client_id]
    except:
        pass
    return 0

def load_customers():
    customers = []
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                    if r.get("status") == "active":
                        customers.append(r)
                except:
                    pass
    except:
        pass
    return customers

def load_users():
    try:
        with open(USERS_FILE) as f:
            return json.load(f)
    except:
        return {}

def send_weekly_email(email, name, client_id, total, blocked, pct):
    html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Your Weekly Harbor Privacy Report</h1>
<p>Hi {name},</p>
<p>Here's what Harbor Privacy blocked for you this week.</p>
<div style="display:flex;gap:16px;margin:24px 0;flex-wrap:wrap;">
  <div style="background:#111618;border-left:3px solid #00e5c0;padding:16px 24px;flex:1;min-width:120px;">
    <div style="font-family:monospace;font-size:10px;color:#00e5c0;letter-spacing:0.2em;margin-bottom:8px;">TOTAL QUERIES</div>
    <div style="font-size:32px;font-weight:700;color:#e8f0ef;">{total:,}</div>
  </div>
  <div style="background:#111618;border-left:3px solid #00e5c0;padding:16px 24px;flex:1;min-width:120px;">
    <div style="font-family:monospace;font-size:10px;color:#00e5c0;letter-spacing:0.2em;margin-bottom:8px;">BLOCKED</div>
    <div style="font-size:32px;font-weight:700;color:#e8f0ef;">{blocked:,}</div>
  </div>
  <div style="background:#111618;border-left:3px solid #00e5c0;padding:16px 24px;flex:1;min-width:120px;">
    <div style="font-family:monospace;font-size:10px;color:#00e5c0;letter-spacing:0.2em;margin-bottom:8px;">BLOCK RATE</div>
    <div style="font-size:32px;font-weight:700;color:#00e5c0;">{pct}%</div>
  </div>
</div>
<p style="color:#6b8a87;font-size:13px;">These are aggregate statistics only. Harbor Privacy does not log your browsing history.</p>
<div style="border-top:1px solid #1e2a2d;padding-top:20px;margin-top:20px;">
  <a href="https://dashboard.harborprivacy.com" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">View Dashboard →</a>
</div>
<p style="padding-top:24px;color:#6b8a87;font-size:12px;">
  To unsubscribe from weekly emails, go to Dashboard → Settings → Weekly Stats Email → Off<br>
  - Tim | <a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a>
</p>
</div>'''

    requests.post("https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        json={"from": FROM_EMAIL, "to": [email], "subject": f"Your Harbor Privacy Weekly Report — {pct}% blocked", "html": html}
    )
    print(f"Sent weekly email to {email}")

if __name__ == "__main__":
    users = load_users()
    customers = load_customers()
    sent = 0
    for customer in customers:
        email = customer.get("email", "")
        user = users.get(email, {})
        if not user.get("weekly_email", False):
            continue
        name = customer.get("name", "Customer")
        client_id = customer.get("client_id", "")
        try:
            r = requests.get(f"{ADGUARD_URL}/control/stats", auth=(ADGUARD_USER, ADGUARD_PASS), timeout=5)
            data = r.json()
            total = data.get("num_dns_queries", 0)
            blocked = data.get("num_blocked_filtering", 0)
            pct = round(blocked / max(total, 1) * 100, 1)
            send_weekly_email(email, name, client_id, total, blocked, pct)
            sent += 1
        except Exception as e:
            print(f"Error for {email}: {e}")
    print(f"Weekly emails sent: {sent}")
