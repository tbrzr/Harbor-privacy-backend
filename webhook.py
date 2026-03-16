#!/usr/bin/env python3
"""
Harbor Privacy — Stripe Webhook Handler
Receives payment events, creates AdGuard clients, sends welcome emails
"""

import os
import json
import hmac
import hashlib
import logging
import re
import random
import string
import requests
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

# ── CONFIG ─────────────────────────────────────────────────
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "Harbor2026!")
DOH_BASE = os.environ.get("DOH_BASE", "doh.harborprivacy.com/dns-query")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@harborprivacy.com")
LOG_FILE = "/var/log/harbor-webhook.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ── HELPERS ────────────────────────────────────────────────

def generate_client_id(name: str, email: str) -> str:
    """Generate a clean unique client ID from customer name"""
    base = re.sub(r'[^a-z0-9]', '', name.lower().split()[0] if name else email.split('@')[0].lower())
    suffix = ''.join(random.choices(string.digits, k=4))
    return f"{base}{suffix}"


def create_adguard_client(client_id: str, name: str) -> bool:
    """Create a new client in AdGuard Home via API"""
    try:
        payload = {
            "name": name,
            "ids": [client_id],
            "tags": [],
            "filtering_enabled": True,
            "parental_enabled": False,
            "safebrowsing_enabled": True,
            "use_global_settings": True,
            "use_global_blocked_services": True
        }
        resp = requests.post(
            f"{ADGUARD_URL}/control/clients/add",
            json=payload,
            auth=(ADGUARD_USER, ADGUARD_PASS),
            timeout=10
        )
        if resp.status_code == 200:
            log.info(f"Created AdGuard client: {client_id} for {name}")
            return True
        else:
            log.error(f"AdGuard client creation failed: {resp.status_code} {resp.text}")
            return False
    except Exception as e:
        log.error(f"AdGuard API error: {e}")
        return False


def send_welcome_email(email: str, name: str, client_id: str, plan: str) -> bool:
    """Send welcome email with DoH setup instructions via Resend"""
    doh_address = f"{DOH_BASE}/{client_id}"

    if plan == "remote":
        setup_instructions = f"""
<h2>Your Harbor Privacy Setup</h2>
<p>Hi {name},</p>
<p>Welcome to Harbor Privacy! Your private DNS endpoint is ready. Here's everything you need to get set up:</p>

<h3>Your Personal DoH Address</h3>
<p style="background:#0a0e0f;color:#00e5c0;padding:16px;font-family:monospace;font-size:15px;word-break:break-all;letter-spacing:0.02em;border-left:3px solid #00e5c0;">{doh_address}</p>

<h3>Setup Instructions</h3>

<h4>iPhone / iPad</h4>
<p>A custom DNS profile will be emailed to you separately. Install it via Settings → General → VPN & Device Management.</p>

<h4>Android / Pixel</h4>
<ol>
<li>Go to Settings → Network & Internet → Private DNS</li>
<li>Select "Private DNS provider hostname"</li>
<li>Enter: <strong>{doh_address}</strong></li>
<li>Tap Save</li>
</ol>

<h4>Your Router (protects all home devices)</h4>
<p>Log into your router admin panel and set the DNS server to: <strong>doh.harborprivacy.com</strong></p>
<p>For Xfinity routers: go to 10.0.0.1 → Advanced → DNS Settings</p>

<h3>Need Help?</h3>
<p>Reply to this email or text/call 781-974-6196. I'll get back to you within a few hours.</p>

<p>— Tim<br>Harbor Privacy<br>harborprivacy.com</p>
"""
    else:
        setup_instructions = f"""
<h2>Your Harbor Privacy Installation is Confirmed</h2>
<p>Hi {name},</p>
<p>Thanks for booking your Harbor Privacy installation. I'll be in touch within 24 hours to schedule your visit.</p>
<p>Questions? Reply to this email or text 781-974-6196.</p>
<p>— Tim<br>Harbor Privacy<br>harborprivacy.com</p>
"""

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


def verify_stripe_signature(payload: bytes, sig_header: str, secret: str) -> bool:
    """Verify Stripe webhook signature"""
    try:
        timestamp = None
        signatures = []
        for part in sig_header.split(","):
            k, v = part.split("=", 1)
            if k == "t":
                timestamp = v
            elif k == "v1":
                signatures.append(v)
        signed_payload = f"{timestamp}.{payload.decode('utf-8')}"
        expected = hmac.new(
            secret.encode("utf-8"),
            signed_payload.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()
        return expected in signatures
    except Exception as e:
        log.error(f"Signature verification error: {e}")
        return False


def log_customer(client_id: str, name: str, email: str, plan: str):
    """Append customer to local log file"""
    entry = {
        "date": datetime.utcnow().isoformat(),
        "client_id": client_id,
        "name": name,
        "email": email,
        "plan": plan
    }
    with open("/var/log/harbor-customers.json", "a") as f:
        f.write(json.dumps(entry) + "\n")


# ── WEBHOOK HANDLER ────────────────────────────────────────

class WebhookHandler(BaseHTTPRequestHandler):

    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404)
            self.end_headers()
            return

        content_length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(content_length)
        sig_header = self.headers.get("Stripe-Signature", "")

        # Verify signature
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
                log.info(f"Full session dump: {json.dumps(session)}")
                metadata = session.get("metadata", {})
                mode = session.get("mode", "")
                amount = session.get("amount_total", 0)
                plan = "remote" if (
                    "harbor-remote" in str(metadata).lower() or
                    "harbor remote" in str(metadata).lower() or
                    "remote" in str(metadata).lower() or
                    mode == "subscription"
                ) else "install"
                log.info(f"Plan={plan} mode={mode} amount={amount} metadata={metadata}")

                if customer_email:
                    client_id = generate_client_id(customer_name, customer_email)

                    if plan == "remote":
                        create_adguard_client(client_id, customer_name)

                    send_welcome_email(customer_email, customer_name, client_id, plan)
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
        pass  # Suppress default HTTP logs


if __name__ == "__main__":
    port = int(os.environ.get("WEBHOOK_PORT", 9000))
    log.info(f"Starting Harbor Privacy webhook server on port {port}")
    server = HTTPServer(("127.0.0.1", port), WebhookHandler)
    server.serve_forever()
