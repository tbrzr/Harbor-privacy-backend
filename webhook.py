#!/usr/bin/env python3
import os, json, hmac, hashlib, logging, re, random, string, uuid, requests, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_WEBHOOK_SECRET_TEST = os.environ.get("STRIPE_WEBHOOK_SECRET_TEST", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "Harbor2026!")
DOH_BASE = os.environ.get("DOH_BASE", "doh.harborprivacy.com/dns-query")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
PROFILES_DIR = os.environ.get("PROFILES_DIR", "/var/www/network/profiles")
PROFILES_URL = os.environ.get("PROFILES_URL", "https://harborprivacy.com/profiles")
CUSTOMERS_LOG = "/var/log/harbor-customers.json"
SESSIONS_LOG = "/var/log/harbor-sessions.json"
LOG_FILE = "/var/log/harbor-webhook.log"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()])
log = logging.getLogger(__name__)

def is_processed(session_id):
    try:
        return session_id in open(SESSIONS_LOG).read()
    except:
        return False

def mark_processed(session_id):
    try:
        open(SESSIONS_LOG, "a").write(session_id + "\n")
    except Exception as e:
        log.error(f"Session log error: {e}")

def generate_client_id(name, email):
    base = re.sub(r'[^a-z0-9]', '', name.strip().lower().split()[0] if name.strip() else email.split('@')[0].lower())
    return f"{base}{''.join(random.choices(string.digits, k=4))}"

def generate_ios_profile(client_id, name):
    pu = str(uuid.uuid4()).upper()
    pp = str(uuid.uuid4()).upper()
    return f'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict>
<key>DNSProtocol</key><string>HTTPS</string>
<key>ServerAddresses</key><array></array>
<key>ServerURL</key><string>https://{DOH_BASE}/{client_id}</string>
<key>SupplementalMatchDomains</key><array></array>
</dict>
<key>PayloadDisplayName</key><string>Harbor Privacy - {name}</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.doh.{client_id}.{pp}</string>
<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
<key>PayloadUUID</key><string>{pp}</string>
<key>PayloadVersion</key><integer>1</integer>
<key>ProhibitDisablement</key><false/>
<key>AllowFailover</key><true/>
</dict></array>
<key>PayloadDisplayName</key><string>Harbor Privacy DNS</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.doh.{client_id}</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{pu}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>'''

def save_ios_profile(client_id, name):
    try:
        os.makedirs(PROFILES_DIR, exist_ok=True)
        path = os.path.join(PROFILES_DIR, f"{client_id}.mobileconfig")
        open(path, 'w').write(generate_ios_profile(client_id, name))
        log.info(f"iOS profile saved: {path}")
        return f"{PROFILES_URL}/{client_id}.mobileconfig"
    except Exception as e:
        log.error(f"Profile error: {e}")
        return ""

def get_allowed_clients():
    try:
        r = requests.get(f"{ADGUARD_URL}/control/access/list", auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        data = r.json() if r.status_code == 200 else {}
        return data.get("allowed_clients") or []
    except Exception as e:
        log.error(f"Get allowed clients error: {e}")
        return []

def set_allowed_clients(clients):
    try:
        r = requests.post(f"{ADGUARD_URL}/control/access/set",
            json={"allowed_clients": clients, "disallowed_clients": [], "blocked_hosts": []},
            auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        return r.status_code == 200
    except Exception as e:
        log.error(f"Set allowed clients error: {e}")
        return False

def add_to_allowed_clients(client_id):
    clients = get_allowed_clients()
    if client_id not in clients:
        clients.append(client_id)
        if set_allowed_clients(clients):
            log.info(f"Added {client_id} to allowed clients")

def remove_from_allowed_clients(client_id):
    clients = get_allowed_clients()
    if client_id in clients:
        clients.remove(client_id)
        if set_allowed_clients(clients):
            log.info(f"Removed {client_id} from allowed clients")

def create_adguard_client(client_id, name):
    try:
        r = requests.post(f"{ADGUARD_URL}/control/clients/add",
            json={"name": f"{name.strip()} ({client_id})", "ids": [client_id], "tags": [],
                  "filtering_enabled": True, "parental_enabled": False, "safebrowsing_enabled": True,
                  "use_global_settings": True, "use_global_blocked_services": True},
            auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        if r.status_code == 200:
            log.info(f"Created AdGuard client: {client_id}")
            return True
        log.error(f"AdGuard create failed: {r.status_code} {r.text}")
        return False
    except Exception as e:
        log.error(f"AdGuard error: {e}")
        return False

def delete_adguard_client(client_id):
    try:
        r = requests.post(f"{ADGUARD_URL}/control/clients/delete",
            json={"name": f"{client_id}"}, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        if r.status_code == 200:
            log.info(f"Deleted AdGuard client: {client_id}")
            return True
        return False
    except Exception as e:
        log.error(f"AdGuard delete error: {e}")
        return False

def delete_profile(client_id):
    path = f"{PROFILES_DIR}/{client_id}.mobileconfig"
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"Deleted profile: {path}")
    except Exception as e:
        log.error(f"Profile delete error: {e}")

def deactivate_after_grace(client_id, delay=3600):
    def _run():
        import time
        log.info(f"Grace period started for {client_id} - {delay}s")
        time.sleep(delay)
        remove_from_allowed_clients(client_id)
        delete_adguard_client(client_id)
        delete_profile(client_id)
        log.info(f"Deactivated after grace: {client_id}")
    threading.Thread(target=_run, daemon=True).start()

def find_customer(stripe_customer_id):
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    if r.get("stripe_customer_id") == stripe_customer_id:
                        return r
                except:
                    pass
    except:
        pass
    return {}

def log_customer(client_id, name, email, plan, stripe_customer_id=""):
    entry = {"date": datetime.utcnow().isoformat(), "client_id": client_id,
             "name": name, "email": email, "plan": plan,
             "stripe_customer_id": stripe_customer_id, "status": "active"}
    open(CUSTOMERS_LOG, "a").write(json.dumps(entry) + "\n")

def send_email(to, subject, html):
    try:
        r = requests.post("https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": f"Harbor Privacy <{FROM_EMAIL}>", "to": [to], "subject": subject, "html": html},
            timeout=10)
        if r.status_code == 200:
            log.info(f"Email sent to {to}")
            return True
        log.error(f"Resend failed: {r.status_code} {r.text}")
        return False
    except Exception as e:
        log.error(f"Email error: {e}")
        return False

def send_welcome_email(email, name, client_id, plan, profile_url=""):
    doh = f"https://{DOH_BASE}/{client_id}"
    if plan == "remote":
        ios_btn = f'<p><a href="{profile_url}" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:13px;">Download iOS DNS Profile</a></p><p style="font-size:12px;color:#6b8a87;">Tap on iPhone/iPad then Settings > General > VPN & Device Management > Install</p>' if profile_url else "<p style='color:#6b8a87;'>iOS profile will be sent separately.</p>"
        html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Your Harbor Privacy Setup</h1>
<p>Hi {name},</p><p>Your private DNS endpoint is ready.</p>
<h2 style="font-family:Georgia,serif;font-weight:400;">Your Personal DoH Address</h2>
<p style="background:#111618;border-left:3px solid #00e5c0;padding:16px;font-family:monospace;font-size:14px;color:#00e5c0;word-break:break-all;">{doh}</p>
<div style="background:#111618;border:1px solid #00e5c0;padding:20px;margin-bottom:24px;"><p style="font-family:monospace;font-size:11px;color:#00e5c0;letter-spacing:0.1em;margin-bottom:8px;">SAVE 44% — UPGRADE TO ANNUAL</p><p style="color:#e8f0ef;margin-bottom:12px;">Lock in your rate for a full year at $39.99. Use code <strong>FOUNDERS10</strong> for 50% off while it lasts.</p><a href="https://buy.stripe.com/9B69AS6knepVbPL2Gz6kg09" style="background:#00e5c0;color:#0a0e0f;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Upgrade to Annual &#8594;</a></div><h2 style="font-family:Georgia,serif;font-weight:400;">Setup Instructions</h2>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">iPhone / iPad</h3>{ios_btn}
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">Android / Pixel</h3>
<ol style="color:#6b8a87;"><li>Settings > Network and Internet > Private DNS</li><li>Private DNS provider hostname</li><li>Enter: <strong style="color:#e8f0ef;">{doh}</strong></li><li>Save</li></ol>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">Xfinity Router</h3>
<ol style="color:#6b8a87;"><li>Go to 10.0.0.1</li><li>Login with router sticker credentials</li><li>Advanced > DNS Settings</li><li>Primary DNS: <strong style="color:#e8f0ef;">doh.harborprivacy.com</strong></li><li>Save and reboot</li></ol>
<div style="border-top:1px solid #1e2a2d;margin-top:32px;padding-top:24px;">
<h3 style="color:#6b8a87;font-family:monospace;font-size:11px;letter-spacing:0.1em;">IF YOU EVER CANCEL - HOW TO REMOVE HARBOR PRIVACY</h3>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">iPhone/iPad:</strong> Settings > General > VPN and Device Management > Harbor Privacy DNS > Remove Profile</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Android/Pixel:</strong> Settings > Network and Internet > Private DNS > set to Off or Automatic</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Xfinity Router:</strong> Go to 10.0.0.1 > Advanced > DNS Settings > restore to Automatic > reboot</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Other Routers:</strong> Router admin panel > DNS settings > set to Automatic > save and reboot</p>
</div>
<p style="padding-top:24px;color:#6b8a87;">Questions? Reply or text <strong style="color:#e8f0ef;">781-974-6196</strong><br>- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
</div>'''
    else:
        html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Installation Confirmed</h1>
<p>Hi {name},</p><p>Thanks for booking. I will be in touch within 24 hours to schedule your visit.</p>
<p style="border-top:1px solid #1e2a2d;padding-top:24px;color:#6b8a87;">Questions? Reply or text <strong style="color:#e8f0ef;">781-974-6196</strong><br>- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
</div>'''
    send_email(email, "Welcome to Harbor Privacy - Your Setup Instructions", html)

def send_cancellation_email(email, name):
    html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Subscription Ended</h1>
<p>Hi {name},</p>
<p>Your Harbor Privacy subscription has been cancelled. DNS access will be deactivated in 1 hour.</p>
<h2 style="font-family:Georgia,serif;font-weight:400;">Remove Harbor Privacy from your devices</h2>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">iPhone/iPad:</strong> Settings > General > VPN and Device Management > Harbor Privacy DNS > Remove Profile</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Android/Pixel:</strong> Settings > Network and Internet > Private DNS > set to Off or Automatic</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Xfinity Router:</strong> Go to 10.0.0.1 > Advanced > DNS Settings > restore to Automatic > reboot</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Other Routers:</strong> Router admin panel > DNS settings > set to Automatic > save and reboot</p>
<p style="margin-top:16px;color:#6b8a87;">Need help? Reply to this email and I will walk you through it.</p>
<p>Resubscribe at <a href="https://harborprivacy.com/pricing" style="color:#00e5c0;">harborprivacy.com/pricing</a></p>
<p style="border-top:1px solid #1e2a2d;padding-top:24px;color:#6b8a87;">- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
</div>'''
    send_email(email, "Your Harbor Privacy subscription has ended", html)

def verify_sig(payload, sig_header, secret):
    try:
        parts = {}
        for p in sig_header.split(","):
            k, v = p.split("=", 1)
            parts[k] = v
        t = parts.get("t", "")
        sigs = [v for k, v in parts.items() if k == "v1"]
        expected = hmac.new(secret.encode(), f"{t}.{payload.decode()}".encode(), hashlib.sha256).hexdigest()
        return expected in sigs
    except:
        return False

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/webhook":
            self.send_response(404); self.end_headers(); return

        length = int(self.headers.get("Content-Length", 0))
        payload = self.rfile.read(length)
        sig = self.headers.get("Stripe-Signature", "")

        verified = (verify_sig(payload, sig, STRIPE_WEBHOOK_SECRET) if STRIPE_WEBHOOK_SECRET else False) or \
                   (verify_sig(payload, sig, STRIPE_WEBHOOK_SECRET_TEST) if STRIPE_WEBHOOK_SECRET_TEST else False)

        if (STRIPE_WEBHOOK_SECRET or STRIPE_WEBHOOK_SECRET_TEST) and not verified:
            log.warning("Invalid Stripe signature")
            self.send_response(400); self.end_headers(); return

        try:
            event = json.loads(payload)
            etype = event.get("type", "")
            log.info(f"Event: {etype}")

            if etype == "checkout.session.completed":
                s = event["data"]["object"]
                session_id = s.get("id", "")
                if is_processed(session_id):
                    log.info(f"Skipping duplicate session: {session_id}")
                else:
                    email = s.get("customer_details", {}).get("email", "")
                    name = s.get("customer_details", {}).get("name", "unknown").strip()
                    stripe_id = s.get("customer", "")
                    mode = s.get("mode", "")
                    meta = s.get("metadata", {})
                    plan = "remote" if ("remote" in str(meta).lower() or mode == "subscription") else "install"
                    log.info(f"Plan={plan} mode={mode} email={email}")
                    if email:
                        client_id = generate_client_id(name, email)
                        profile_url = ""
                        if plan == "remote":
                            create_adguard_client(client_id, name)
                            add_to_allowed_clients(client_id)
                            profile_url = save_ios_profile(client_id, name)
                        send_welcome_email(email, name, client_id, plan, profile_url)
                        log_customer(client_id, name, email, plan, stripe_id)
                        mark_processed(session_id)
                        log.info(f"Onboarded: {name} ({client_id})")

            elif etype == "customer.subscription.deleted":
                stripe_id = event["data"]["object"].get("customer", "")
                customer = find_customer(stripe_id)
                if customer:
                    cid = customer.get("client_id", "")
                    send_cancellation_email(customer.get("email", ""), customer.get("name", ""))
                    deactivate_after_grace(cid, delay=3600)
                    log.info(f"Cancellation received for {cid} - grace period 1hr")

            self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
        except Exception as e:
            log.error(f"Error: {e}")
            self.send_response(500); self.end_headers()

    def log_message(self, *args): pass

if __name__ == "__main__":
    port = int(os.environ.get("WEBHOOK_PORT", 9000))
    log.info(f"Starting on port {port}")
    HTTPServer(("127.0.0.1", port), WebhookHandler).serve_forever()
