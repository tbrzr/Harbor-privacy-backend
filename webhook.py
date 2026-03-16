#!/usr/bin/env python3
“””
Harbor Privacy — Stripe Webhook Handler
Receives payment events, creates AdGuard clients, sends welcome emails, generates iOS profiles
“””

import os
import json
import hmac
import hashlib
import logging
import re
import random
import string
import uuid
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# ── CONFIG ─────────────────────────────────────────────────

STRIPE_WEBHOOK_SECRET = os.environ.get(“STRIPE_WEBHOOK_SECRET”, “”)
RESEND_API_KEY = os.environ.get(“RESEND_API_KEY”, “”)
ADGUARD_URL = os.environ.get(“ADGUARD_URL”, “http://127.0.0.1:8080”)
ADGUARD_USER = os.environ.get(“ADGUARD_USER”, “admin”)
ADGUARD_PASS = os.environ.get(“ADGUARD_PASS”, “Harbor2026!”)
DOH_BASE = os.environ.get(“DOH_BASE”, “doh.harborprivacy.com/dns-query”)
FROM_EMAIL = os.environ.get(“FROM_EMAIL”, “info@mail.harborprivacy.com”)
PROFILES_DIR = os.environ.get(“PROFILES_DIR”, “/var/www/network/profiles”)
PROFILES_URL = os.environ.get(“PROFILES_URL”, “https://harborprivacy.com/profiles”)
LOG_FILE = “/var/log/harbor-webhook.log”

logging.basicConfig(
level=logging.INFO,
format=”%(asctime)s %(levelname)s %(message)s”,
handlers=[
logging.FileHandler(LOG_FILE),
logging.StreamHandler()
]
)
log = logging.getLogger(**name**)

# ── HELPERS ────────────────────────────────────────────────

def generate_client_id(name: str, email: str) -> str:
base = re.sub(r’[^a-z0-9]’, ‘’, name.lower().split()[0] if name else email.split(’@’)[0].lower())
suffix = ‘’.join(random.choices(string.digits, k=4))
return f”{base}{suffix}”

def generate_ios_profile(client_id: str, name: str) -> str:
“”“Generate a mobileconfig DoH profile for the customer”””
profile_uuid = str(uuid.uuid4()).upper()
payload_uuid = str(uuid.uuid4()).upper()
doh_url = f”{DOH_BASE}/{client_id}”

```
profile = f"""<?xml version="1.0" encoding="UTF-8"?>
```

<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">

<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerAddresses</key>
                <array></array>
                <key>ServerURL</key>
                <string>https://{doh_url}</string>
                <key>SupplementalMatchDomains</key>
                <array></array>
            </dict>
            <key>PayloadDescription</key>
            <string>Harbor Privacy DNS over HTTPS for {name}</string>
            <key>PayloadDisplayName</key>
            <string>Harbor Privacy — {name}</string>
            <key>PayloadIdentifier</key>
            <string>com.harborprivacy.doh.{client_id}.{payload_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>ProhibitDisablement</key>
            <false/>
            <key>AllowFailover</key>
            <true/>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Harbor Privacy private DNS profile for {name}</string>
    <key>PayloadDisplayName</key>
    <string>Harbor Privacy DNS</string>
    <key>PayloadIdentifier</key>
    <string>com.harborprivacy.doh.{client_id}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>"""
    return profile

def save_ios_profile(client_id: str, name: str) -> str:
“”“Save mobileconfig to profiles directory and return download URL”””
try:
os.makedirs(PROFILES_DIR, exist_ok=True)
profile_content = generate_ios_profile(client_id, name)
filepath = os.path.join(PROFILES_DIR, f”{client_id}.mobileconfig”)
with open(filepath, ‘w’) as f:
f.write(profile_content)
download_url = f”{PROFILES_URL}/{client_id}.mobileconfig”
log.info(f”iOS profile saved: {filepath}”)
return download_url
except Exception as e:
log.error(f”Profile save error: {e}”)
return “”

def create_adguard_client(client_id: str, name: str) -> bool:
try:
payload = {
“name”: name,
“ids”: [client_id],
“tags”: [],
“filtering_enabled”: True,
“parental_enabled”: False,
“safebrowsing_enabled”: True,
“use_global_settings”: True,
“use_global_blocked_services”: True
}
resp = requests.post(
f”{ADGUARD_URL}/control/clients/add”,
json=payload,
auth=(ADGUARD_USER, ADGUARD_PASS),
timeout=10
)
if resp.status_code == 200:
log.info(f”Created AdGuard client: {client_id} for {name}”)
return True
else:
log.error(f”AdGuard client creation failed: {resp.status_code} {resp.text}”)
return False
except Exception as e:
log.error(f”AdGuard API error: {e}”)
return False

def send_welcome_email(email: str, name: str, client_id: str, plan: str, profile_url: str = “”) -> bool:
doh_address = f”{DOH_BASE}/{client_id}”

```
if plan == "remote":
    ios_section = ""
    if profile_url:
        ios_section = f"""
```

<h4>iPhone / iPad — Tap to Install Profile</h4>
<p>
  <a href="{profile_url}" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:13px;letter-spacing:0.05em;">
    📲 Download iOS DNS Profile
  </a>
</p>
<p style="font-size:12px;color:#666;">Tap the button above on your iPhone or iPad. When prompted, go to Settings → General → VPN & Device Management to install.</p>
"""
        else:
            ios_section = "<p>A custom DNS profile will be emailed to you separately.</p>"

```
    setup_instructions = f"""
```

<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0a0e0f;color:#e8f0ef;padding:32px;">
  <h1 style="font-family:Georgia,serif;color:#e8f0ef;font-weight:400;">Your Harbor Privacy Setup</h1>
  <p>Hi {name},</p>
  <p>Welcome to Harbor Privacy! Your private DNS endpoint is ready.</p>

  <h2 style="font-family:Georgia,serif;font-weight:400;color:#e8f0ef;">Your Personal DoH Address</h2>
  <p style="background:#111618;border-left:3px solid #00e5c0;padding:16px;font-family:monospace;font-size:14px;color:#00e5c0;word-break:break-all;">{doh_address}</p>

  <h2 style="font-family:Georgia,serif;font-weight:400;color:#e8f0ef;">Setup Instructions</h2>

  <h3 style="color:#00e5c0;font-family:monospace;font-size:13px;letter-spacing:0.1em;">iPhone / iPad</h3>
  {ios_section}

  <h3 style="color:#00e5c0;font-family:monospace;font-size:13px;letter-spacing:0.1em;">Android / Pixel</h3>
  <ol style="color:#6b8a87;">
    <li>Settings → Network &amp; Internet → Private DNS</li>
    <li>Select "Private DNS provider hostname"</li>
    <li>Enter: <strong style="color:#e8f0ef;">{doh_address}</strong></li>
    <li>Tap Save</li>
  </ol>

  <h3 style="color:#00e5c0;font-family:monospace;font-size:13px;letter-spacing:0.1em;">Xfinity Router (protects all home devices)</h3>
  <ol style="color:#6b8a87;">
    <li>Go to <strong style="color:#e8f0ef;">10.0.0.1</strong> in your browser</li>
    <li>Log in with credentials on your router sticker</li>
    <li>Go to Advanced → DNS Settings</li>
    <li>Set Primary DNS to: <strong style="color:#e8f0ef;">doh.harborprivacy.com</strong></li>
    <li>Save and reboot</li>
  </ol>

  <p style="border-top:1px solid #1e2a2d;padding-top:24px;color:#6b8a87;">
    Questions? Reply to this email or text <strong style="color:#e8f0ef;">781-974-6196</strong>.<br><br>
    — Tim<br>
    <a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a>
  </p>
</div>
"""
    else:
        setup_instructions = f"""
<div style="font-family:sans-serif;max-width:600px;margin:0 auto;background:#0a0e0f;color:#e8f0ef;padding:32px;">
  <h1 style="font-family:Georgia,serif;color:#e8f0ef;font-weight:400;">Your Harbor Privacy Installation is Confirmed</h1>
  <p>Hi {name},</p>
  <p>Thanks for booking your Harbor Privacy installation. I'll be in touch within 24 hours to schedule your visit.</p>
  <p style="border-top:1px solid #1e2a2d;padding-top:24px;color:#6b8a87;">
    Questions? Reply to this email or text <strong style="color:#e8f0ef;">781-974-6196</strong>.<br><br>
    — Tim<br>
    <a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a>
  </p>
</div>
"""

```
try:
    resp = requests.post(
        "https://api.resend.com/emails",
        headers={
            "Authorization": f"Bearer {RESEND_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "from": f"Harbor Privacy <{FROM_EMAIL}>",
            "to": [email],
            "subject": "Welcome to Harbor Privacy — Your Setup Instructions",
            "html": setup_instructions
        },
        timeout=10
    )
    if resp.status_code == 200:
        log.info(f"Welcome email sent to {email}")
        return True
    else:
        log.error(f"Resend failed: {resp.status_code} {resp.text}")
        return False
except Exception as e:
    log.error(f"Email error: {e}")
    return False
```

def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
try:
timestamp = None
signatures = []
for part in sig_header.split(”,”):
k, v = part.split(”=”, 1)
if k == “t”:
timestamp = v
elif k == “v1”:
signatures.append(v)
signed_payload = f”{timestamp}.{payload.decode(‘utf-8’)}”
expected = hmac.new(
secret.encode(“utf-8”),
signed_payload.encode(“utf-8”),
hashlib.sha256
).hexdigest()
return expected in signatures
except Exception as e:
log.error(f”Signature verification error: {e}”)
return False

def log_customer(client_id: str, name: str, email: str, plan: str):
entry = {
“date”: datetime.utcnow().isoformat(),
“client_id”: client_id,
“name”: name,
“email”: email,
“plan”: plan
}
with open(”/var/log/harbor-customers.json”, “a”) as f:
f.write(json.dumps(entry) + “\n”)

# ── WEBHOOK HANDLER ────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):

```
def do_POST(self):
    if self.path != "/webhook":
        self.send_response(404)
        self.end_headers()
        return

    content_length = int(self.headers.get("Content-Length", 0))
    payload = self.rfile.read(content_length)
    sig_header = self.headers.get("Stripe-Signature", "")

    if STRIPE_WEBHOOK_SECRET and not verify_stripe_signature(payload, sig_header, STRIPE_WEBHOOK_SECRET):
        log.warning("Invalid Stripe signature")
        self.send_response(400)
        self.end_headers()
        return

    try:
        event = json.loads(payload)
        event_type = event.get("type", "")
        log.info(f"Received Stripe event: {event_type}")

        if event_type == "checkout.session.completed":
            session = event["data"]["object"]
            customer_email = session.get("customer_details", {}).get("email", "")
            customer_name = session.get("customer_details", {}).get("name", "unknown")
            metadata = session.get("metadata", {})
            mode = session.get("mode", "")
            plan = "remote" if (
                "harbor-remote" in str(metadata).lower() or
                "remote" in str(metadata).lower() or
                mode == "subscription"
            ) else "install"
            log.info(f"Plan={plan} mode={mode} metadata={metadata}")

            if customer_email:
                client_id = generate_client_id(customer_name, customer_email)

                if plan == "remote":
                    create_adguard_client(client_id, customer_name)
                    profile_url = save_ios_profile(client_id, customer_name)
                else:
                    profile_url = ""

                send_welcome_email(customer_email, customer_name, client_id, plan, profile_url)
                log_customer(client_id, customer_name, customer_email, plan)
                log.info(f"Onboarded: {customer_name} ({client_id}) plan={plan}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    except Exception as e:
        log.error(f"Webhook processing error: {e}")
        self.send_response(500)
        self.end_headers()

def log_message(self, format, *args):
    pass
```

if **name** == “**main**”:
port = int(os.environ.get(“WEBHOOK_PORT”, 9000))
log.info(f”Starting Harbor Privacy webhook server on port {port}”)
server = HTTPServer((“127.0.0.1”, port), WebhookHandler)
server.serve_forever()