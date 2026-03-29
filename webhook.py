#!/usr/bin/env python3
import os, json, hmac, hashlib, logging, re, random, string, uuid, requests, threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime

STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")
STRIPE_SECRET = os.environ.get("STRIPE_SECRET", "")
STRIPE_WEBHOOK_SECRET_TEST = os.environ.get("STRIPE_WEBHOOK_SECRET_TEST", "")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "")
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
<key>AllowFailover</key><true/>
</dict>
<key>PayloadDescription</key><string>Private encrypted DNS filtering for your devices. Blocks ads, trackers, and malware automatically.</string>
<key>PayloadDisplayName</key><string>Harbor Privacy - {name}</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.doh.{client_id}.{pp}</string>
<key>PayloadOrganization</key><string>Harbor Privacy</string>
<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
<key>PayloadUUID</key><string>{pp}</string>
<key>PayloadVersion</key><integer>1</integer>
<key>ProhibitDisablement</key><false/>
</dict></array>
<key>PayloadDescription</key><string>Installs Harbor Privacy encrypted DNS to block ads, trackers, and malware on this device.</string>
<key>PayloadDisplayName</key><string>Harbor Privacy DNS</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.doh.{client_id}</string>
<key>PayloadOrganization</key><string>Harbor Privacy</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>{pu}</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>'''


def generate_ios_kids_profile(client_id):
    pu = str(uuid.uuid4()).upper()
    pp = str(uuid.uuid4()).upper()
    return """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>PayloadContent</key><array><dict>
<key>DNSSettings</key><dict>
<key>DNSProtocol</key><string>HTTPS</string>
<key>ServerAddresses</key><array></array>
<key>ServerURL</key><string>https://""" + DOH_BASE + """/""" + client_id + """</string>
<key>SupplementalMatchDomains</key><array></array>
<key>AllowFailover</key><true/>
</dict>
<key>PayloadDescription</key><string>Harbor Kids DNS. Falls back to OpenDNS Family Shield if unavailable.</string>
<key>PayloadDisplayName</key><string>Harbor Kids DNS</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.kids.""" + client_id + """.""" + pp + """</string>
<key>PayloadOrganization</key><string>Harbor Privacy</string>
<key>PayloadType</key><string>com.apple.dnsSettings.managed</string>
<key>PayloadUUID</key><string>""" + pp + """</string>
<key>PayloadVersion</key><integer>1</integer>
<key>ProhibitDisablement</key><false/>
</dict></array>
<key>PayloadDescription</key><string>Harbor Kids DNS filtering. Blocks adult content and malware. Falls back to OpenDNS Family Shield if Harbor Privacy is unavailable.</string>
<key>PayloadDisplayName</key><string>Harbor Kids DNS</string>
<key>PayloadIdentifier</key><string>com.harborprivacy.kids.""" + client_id + """</string>
<key>PayloadOrganization</key><string>Harbor Privacy</string>
<key>PayloadRemovalDisallowed</key><false/>
<key>PayloadType</key><string>Configuration</string>
<key>PayloadUUID</key><string>""" + pu + """</string>
<key>PayloadVersion</key><integer>1</integer>
</dict></plist>"""

def save_ios_kids_profile(client_id, name="Harbor Kids"):
    try:
        os.makedirs(PROFILES_DIR, exist_ok=True)
        fpath = os.path.join(PROFILES_DIR, client_id + ".mobileconfig")
        open(fpath, 'w').write(generate_ios_kids_profile(client_id))
        log.info("Harbor Kids iOS profile saved: " + fpath)
        return PROFILES_URL + "/" + client_id + ".mobileconfig"
    except Exception as e:
        log.error("Kids profile error: " + str(e))
        return ""

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
        # Look up full client name first
        clients = requests.get(f"{ADGUARD_URL}/control/clients",
            auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10).json().get("clients", [])
        client = next((c for c in clients if client_id in c.get("ids", [])), None)
        if not client:
            log.warning(f"AdGuard client not found for {client_id}")
            return False
        r = requests.post(f"{ADGUARD_URL}/control/clients/delete",
            json={"name": client["name"]}, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        if r.status_code == 200:
            log.info(f"Deleted AdGuard client: {client['name']}")
            return True
        log.error(f"AdGuard delete failed: {r.status_code} {r.text}")
        return False
    except Exception as e:
        log.error(f"AdGuard delete error: {e}")
        return False

def generate_qr_code(client_id):
    try:
        import qrcode
        QR_DIR = "/var/www/network/qrcodes"
        os.makedirs(QR_DIR, exist_ok=True)
        doh = f"https://{DOH_BASE}/{client_id}"
        qr = qrcode.QRCode(version=1, box_size=10, border=4)
        qr.add_data(doh)
        qr.make(fit=True)
        img = qr.make_image(fill_color="#00e5c0", back_color="#0a0e0f")
        img.save(f"{QR_DIR}/{client_id}.png")
        log.info(f"QR code saved: {QR_DIR}/{client_id}.png")
        return f"https://harborprivacy.com/qrcodes/{client_id}.png"
    except Exception as e:
        log.error(f"QR code error: {e}")
        return ""

def generate_android_page(client_id):
    try:
        ANDROID_DIR = "/var/www/network/setup/android"
        os.makedirs(ANDROID_DIR, exist_ok=True)
        doh = f"https://{DOH_BASE}/{client_id}"
        qr_url = f"https://harborprivacy.com/qrcodes/{client_id}.png"
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Android Setup - Harbor Privacy</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Space+Grotesk:wght@400;700&display=swap" rel="stylesheet">
<style>
*{{box-sizing:border-box;margin:0;padding:0;}}
body{{background:#0a0e0f;color:#e8f0ef;font-family:'Space Grotesk',sans-serif;padding:32px 20px;max-width:480px;margin:0 auto;}}
h1{{font-size:28px;font-weight:700;margin-bottom:8px;}}
.accent{{color:#00e5c0;}}
.note{{font-family:'DM Mono',monospace;font-size:11px;color:#6b8a87;margin-bottom:32px;}}
.card{{background:#111618;border:1px solid #1e2a2d;padding:24px;margin-bottom:16px;}}
.label{{font-family:'DM Mono',monospace;font-size:10px;color:#00e5c0;letter-spacing:0.2em;text-transform:uppercase;margin-bottom:12px;}}
.doh{{background:#0a0e0f;border-left:3px solid #00e5c0;padding:16px;font-family:'DM Mono',monospace;font-size:13px;color:#00e5c0;word-break:break-all;margin-bottom:12px;}}
.btn{{display:block;text-align:center;background:#00e5c0;color:#0a0e0f;padding:12px 20px;font-family:'DM Mono',monospace;font-size:12px;letter-spacing:0.08em;text-decoration:none;margin-bottom:8px;cursor:pointer;border:none;width:100%;}}
.btn-outline{{background:transparent;border:1px solid #1e2a2d;color:#6b8a87;display:block;text-align:center;}}
.step{{display:flex;gap:16px;margin-bottom:16px;}}
.step-num{{font-family:'DM Mono',monospace;font-size:20px;color:#00e5c0;flex-shrink:0;width:32px;}}
.step-text{{font-size:14px;color:#6b8a87;line-height:1.6;}}
.qr-img{{display:block;margin:0 auto;width:200px;height:200px;border:4px solid #1e2a2d;}}
</style>
</head>
<body>
<a href="https://harborprivacy.com" style="font-family:'DM Mono',monospace;font-size:12px;color:#6b8a87;text-decoration:none;display:block;margin-bottom:32px;">harbor/privacy</a>
<h1>Android <span class="accent">Setup</span></h1>
<p class="note">Your personal private DNS setup page</p>
<div class="card">
  <div class="label">Your Private DNS Address</div>
  <div class="doh" id="doh-addr">{doh}</div>
  <button class="btn" onclick="navigator.clipboard.writeText('{doh}').then(()=>{{this.innerText='Copied!';setTimeout(()=>this.innerText='Copy Address',2000)}})">Copy Address</button>
</div>
<div class="card">
  <div class="label">Scan QR Code</div>
  <img src="{qr_url}" class="qr-img" alt="QR Code">
  <p style="font-family:'DM Mono',monospace;font-size:11px;color:#6b8a87;text-align:center;margin-top:12px;">Scan to copy your DNS address</p>
</div>
<div class="card">
  <div class="label">Setup Instructions</div>
  <div class="step"><div class="step-num">01</div><div class="step-text">Open Settings on your Android phone</div></div>
  <div class="step"><div class="step-num">02</div><div class="step-text">Go to Network and Internet then Private DNS</div></div>
  <div class="step"><div class="step-num">03</div><div class="step-text">Select Private DNS provider hostname</div></div>
  <div class="step"><div class="step-num">04</div><div class="step-text">Paste your address above and tap Save</div></div>
  <a href="intent:#Intent;action=android.settings.PRIVATE_DNS_SETTINGS;end" class="btn btn-outline" style="margin-top:16px;">Open Android DNS Settings</a>
</div>
</body>
</html>"""
        open(f"{ANDROID_DIR}/{client_id}.html", 'w').write(html)
        log.info(f"Android setup page saved: {ANDROID_DIR}/{client_id}.html")
        return f"https://harborprivacy.com/setup/android/{client_id}.html"
    except Exception as e:
        log.error(f"Android page error: {e}")
        return ""

def delete_android_page(client_id):
    path = f"/var/www/network/setup/android/{client_id}.html"
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"Deleted Android page: {path}")
    except Exception as e:
        log.error(f"Android page delete error: {e}")

def delete_qr_code(client_id):
    path = f"/var/www/network/qrcodes/{client_id}.png"
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"Deleted QR code: {path}")
    except Exception as e:
        log.error(f"QR delete error: {e}")

def delete_profile(client_id):
    path = f"{PROFILES_DIR}/{client_id}.mobileconfig"
    try:
        if os.path.exists(path):
            os.remove(path)
            log.info(f"Deleted profile: {path}")
    except Exception as e:
        log.error(f"Profile delete error: {e}")

def wipe_customer(client_id):
    # Never wipe admin account
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if customer and customer.get("email") in ("admin@harborprivacy.com", "tim@harborprivacy.com"):
        log.warning(f"Blocked attempt to wipe protected account {client_id}")
        return False
    """Full data wipe — removes all traces of a customer from every system"""
    # 1. Remove from AdGuard allowed clients
    remove_from_allowed_clients(client_id)
    # 2. Delete AdGuard client profile
    delete_adguard_client(client_id)
    # 3. Delete iOS profile file
    delete_profile(client_id)
    # 3b. Delete QR code
    delete_qr_code(client_id)
    # 3c. Delete Android setup page
    delete_android_page(client_id)
    # 4. Delete dashboard login account
    try:
        users_file = "/var/log/harbor-dashboard-users.json"
        customer_email = None
        try:
            lines = open(CUSTOMERS_LOG).readlines()
            for line in lines:
                try:
                    r = json.loads(line.strip())
                    if r.get("client_id") == client_id:
                        customer_email = r.get("email")
                        break
                except:
                    pass
        except:
            pass
        if customer_email:
            with open(users_file) as f2:
                users = json.load(f2)
            if customer_email in users:
                del users[customer_email]
                with open(users_file, "w") as f2:
                    json.dump(users, f2)
                log.info(f"Deleted dashboard user: {customer_email}")
    except Exception as e:
        log.error(f"Error deleting dashboard user: {e}")
    # 5. Remove from customers log entirely
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = [l for l in lines if client_id not in l]
        open(CUSTOMERS_LOG, "w").writelines(new_lines)
        log.info(f"Removed customer log entry for {client_id}")
    except Exception as e:
        log.error(f"Error removing customer log: {e}")
    log.info(f"Full wipe complete: {client_id}")

PENDING_WIPES_FILE = "/var/log/harbor-pending-wipes.json"

def schedule_wipe(client_id, delay=3600):
    """Write pending wipe to disk so it survives restarts"""
    import time
    wipe_at = time.time() + delay
    try:
        try:
            with open(PENDING_WIPES_FILE) as f2:
                pending = json.load(f2)
        except:
            pending = {}
        pending[client_id] = wipe_at
        with open(PENDING_WIPES_FILE, "w") as f2:
            json.dump(pending, f2)
        log.info(f"Scheduled wipe for {client_id} at {wipe_at}")
    except Exception as e:
        log.error(f"Error scheduling wipe: {e}")

def process_pending_wipes():
    """Check pending wipes file and execute any that are due"""
    import time
    try:
        try:
            with open(PENDING_WIPES_FILE) as f2:
                pending = json.load(f2)
        except:
            return
        now = time.time()
        executed = []
        for client_id, wipe_at in pending.items():
            if now >= wipe_at:
                log.info(f"Executing scheduled wipe for {client_id}")
                wipe_customer(client_id)
                executed.append(client_id)
        if executed:
            for cid in executed:
                del pending[cid]
            with open(PENDING_WIPES_FILE, "w") as f2:
                json.dump(pending, f2)
    except Exception as e:
        log.error(f"Error processing pending wipes: {e}")

def deactivate_after_grace(client_id, delay=3600):
    schedule_wipe(client_id, delay)

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

def log_customer(client_id, name, email, plan, stripe_customer_id="", plan_type=None, is_trial=False):
    entry = {"date": datetime.utcnow().isoformat(), "client_id": client_id,
             "name": name, "email": email, "plan": plan,
            "plan_type": plan_type or plan,
            "is_trial": is_trial,
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

def enable_family_safe(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        client = next((c for c in clients if client_id in c.get("ids",[])), None)
        if not client:
            return False
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        data = {"safe_search":ss,"blocked_services_schedule":{"time_zone":"Local"},"name":client["name"],"blocked_services":client.get("blocked_services") or [],"ids":client.get("ids",[]),"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False}
        req.post(f"{AGH}/control/clients/update", json={"name":client["name"],"data":data}, auth=(USER,PASS), timeout=10)
        return True
    except Exception as e:
        log.error(f"enable_family_safe error: {e}")
        return False

def disable_family_safe(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        client = next((c for c in clients if client_id in c.get("ids",[])), None)
        if not client:
            return False
        ss = {"enabled":False,"bing":False,"duckduckgo":False,"ecosia":False,"google":False,"pixabay":False,"yandex":False,"youtube":False}
        data = {"safe_search":ss,"blocked_services_schedule":{"time_zone":"Local"},"name":client["name"],"blocked_services":client.get("blocked_services") or [],"ids":client.get("ids",[]),"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":False,"safebrowsing_enabled":True,"safesearch_enabled":False,"use_global_blocked_services":True,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False}
        req.post(f"{AGH}/control/clients/update", json={"name":client["name"],"data":data}, auth=(USER,PASS), timeout=10)
        return True
    except Exception as e:
        log.error(f"disable_family_safe error: {e}")
        return False

def update_customer_family_safe(email, enabled):
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("email","").lower() == email.lower():
                r["family_safe"] = enabled
            new_lines.append(json.dumps(r))
        open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
    except Exception as e:
        log.error(f"update_customer_family_safe error: {e}")

def enable_harbor_kids(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        kids_id = f"{client_id}kid1"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        r = req.post(f"{AGH}/control/clients/add", json=data, auth=(USER,PASS), timeout=10)
        log.info(f"Harbor Kids client created: {kids_id} status={r.status_code}")
        if r.status_code in [200, 201]:
            save_ios_kids_profile(kids_id)
            generate_android_page(kids_id)
            add_to_allowed_clients(kids_id)
            return True
        return False
    except Exception as e:
        log.error(f"enable_harbor_kids error: {e}")
        return False

def add_harbor_kids_profile(client_id, kid_num):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        kids_id = f"{client_id}kid{kid_num}"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        r = req.post(f"{AGH}/control/clients/add", json=data, auth=(USER,PASS), timeout=10)
        log.info(f"Harbor Kids profile added: {kids_id} status={r.status_code}")
        if r.status_code in [200, 201]:
            save_ios_kids_profile(kids_id)
            generate_android_page(kids_id)
            add_to_allowed_clients(kids_id)
            return True
        return False
    except Exception as e:
        log.error(f"add_harbor_kids_profile error: {e}")
        return False

def update_customer_harbor_kids(email):
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("email","").lower() == email.lower():
                r["harbor_kids"] = True
                kid_count = r.get("harbor_kids_count", 0) + 1
                r["harbor_kids_count"] = kid_count
            new_lines.append(json.dumps(r))
        open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
    except Exception as e:
        log.error(f"update_customer_harbor_kids error: {e}")

def disable_harbor_kids(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        kids_clients = [c for c in clients if c.get("name","").startswith(f"{client_id}kid")]
        for kc in kids_clients:
            kid_name = kc["name"]
            req.post(f"{AGH}/control/clients/delete", json={"name":kid_name}, auth=(USER,PASS), timeout=10)
            remove_from_allowed_clients(kid_name)
            log.info(f"Harbor Kids client deleted: {kid_name}")
            # Clean up profile files
            for fpath in [
                os.path.join(PROFILES_DIR, f"{kid_name}.mobileconfig"),
                f"/var/www/network/qrcodes/{kid_name}.png",
                f"/var/www/network/setup/android/{kid_name}.html"
            ]:
                try:
                    if os.path.exists(fpath):
                        os.remove(fpath)
                        log.info(f"Deleted {fpath}")
                except Exception as fe:
                    log.error(f"File delete error: {fe}")
        return True
    except Exception as e:
        log.error(f"disable_harbor_kids error: {e}")
        return False

def update_customer_harbor_kids_off(email):
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("email","").lower() == email.lower():
                r["harbor_kids"] = False
                r["harbor_kids_count"] = 0
            new_lines.append(json.dumps(r))
        open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
    except Exception as e:
        log.error(f"update_customer_harbor_kids_off error: {e}")



def send_family_safe_email(email, name, enabled):
    action = "activated" if enabled else "deactivated"
    html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h2 style="font-family:Georgia,serif;font-weight:400;">Family Safe {action.title()}</h2>
<p>Hi {name},</p>
<p>Your Family Safe add-on has been {action}. SafeSearch enforcement and adult content blocking are now {"enabled" if enabled else "disabled"} on your Harbor Privacy account.</p>
<p style="color:#6b8a87;font-size:13px;">Manage your settings at <a href="https://dashboard.harborprivacy.com" style="color:#00e5c0;">dashboard.harborprivacy.com</a></p>
</div>'''
    send_email(email, f"Harbor Privacy - Family Safe {action.title()}", html)

def send_harbor_kids_email(email, name, client_id):
    kids_id = f"{client_id}kid1"
    html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h2 style="font-family:Georgia,serif;font-weight:400;">Your Harbor Kids Setup is Ready</h2>
<p>Hi {name},</p>
<p>Harbor Kids is now active on your account. Here's everything you need to get your child's device protected — it takes about 5 minutes per device.</p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">YOUR HARBOR KIDS PROFILE ID</h3>
<p style="background:#111618;border-left:3px solid #00e5c0;padding:16px;font-family:monospace;font-size:14px;color:#00e5c0;">{kids_id}</p>
<p style="color:#6b8a87;font-size:13px;">You'll see this in your dashboard under active clients.</p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">WHAT HARBOR KIDS BLOCKS</h3>
<p style="color:#6b8a87;font-size:13px;">Adult content, gambling, violence, malware, phishing, and invasive ad networks — all filtered before they reach your child's screen.</p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">SET UP YOUR CHILD'S DEVICE</h3>
<p style="color:#6b8a87;font-size:13px;">The full setup guide covers iPhone, iPad, Mac, Windows, and Android — including how to lock the protection so your child can't remove it without your password.</p>
<p><a href="https://harborprivacy.com/docs/harbor-kids" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:13px;">View Setup Guide &#8594;</a></p>
<p style="color:#6b8a87;font-size:13px;margin-top:24px;">If anything your child needs gets blocked, reply here and I'll whitelist it for their profile — usually fixed within a few hours.</p>
<div style="border-top:1px solid #1e2a2d;padding-top:20px;margin-top:20px;">
<a href="https://dashboard.harborprivacy.com" style="display:inline-block;border:1px solid #00e5c0;color:#00e5c0;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Your Dashboard &#8594;</a>
</div>
<p style="padding-top:24px;color:#6b8a87;">Questions? Reply or text <strong style="color:#e8f0ef;">781-974-6196</strong><br>- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
</div>'''
    send_email(email, "Your Harbor Kids Setup is Ready", html)


def find_customer_by_email(email):
    try:
        for line in open(CUSTOMERS_LOG):
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("email","").lower() == email.lower() and r.get("status") == "active":
                return r
    except:
        pass
    return None

def enable_family_safe(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        client = next((c for c in clients if client_id in c.get("ids",[])), None)
        if not client:
            return False
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        data = {"safe_search":ss,"blocked_services_schedule":{"time_zone":"Local"},"name":client["name"],"blocked_services":client.get("blocked_services") or [],"ids":client.get("ids",[]),"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False}
        req.post(f"{AGH}/control/clients/update", json={"name":client["name"],"data":data}, auth=(USER,PASS), timeout=10)
        return True
    except Exception as e:
        log.error(f"enable_family_safe error: {e}")
        return False

def disable_family_safe(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        client = next((c for c in clients if client_id in c.get("ids",[])), None)
        if not client:
            return False
        ss = {"enabled":False,"bing":False,"duckduckgo":False,"ecosia":False,"google":False,"pixabay":False,"yandex":False,"youtube":False}
        data = {"safe_search":ss,"blocked_services_schedule":{"time_zone":"Local"},"name":client["name"],"blocked_services":client.get("blocked_services") or [],"ids":client.get("ids",[]),"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":False,"safebrowsing_enabled":True,"safesearch_enabled":False,"use_global_blocked_services":True,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False}
        req.post(f"{AGH}/control/clients/update", json={"name":client["name"],"data":data}, auth=(USER,PASS), timeout=10)
        return True
    except Exception as e:
        log.error(f"disable_family_safe error: {e}")
        return False

def update_customer_family_safe(email, enabled):
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("email","").lower() == email.lower():
                r["family_safe"] = enabled
            new_lines.append(json.dumps(r))
        open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
    except Exception as e:
        log.error(f"update_customer_family_safe error: {e}")

    doh = f"https://{DOH_BASE}/{client_id}"

    if plan_type == "harbor-remote-light":
        html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Welcome to Harbor Light</h1>
<p>Hi {name},</p>
<p>Your personal DNS privacy address is ready. Add it to your devices to start blocking ads and trackers.</p>
<h2 style="font-family:Georgia,serif;font-weight:400;">Your Personal DoH Address</h2>
<p style="background:#111618;border-left:3px solid #00e5c0;padding:16px;font-family:monospace;font-size:14px;color:#00e5c0;word-break:break-all;">{doh}</p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">iPhone / iPad</h3>
<p style="color:#6b8a87;font-size:13px;">Settings &gt; General &gt; VPN &amp; Device Management &gt; Install Profile</p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">Android</h3>
<ol style="color:#6b8a87;"><li>Settings &gt; Network and Internet &gt; Private DNS</li><li>Enter: <strong style="color:#e8f0ef;">{doh}</strong></li><li>Save</li></ol>
<div style="background:#111618;border:1px solid #00e5c0;padding:20px;margin:24px 0;">
<p style="font-family:monospace;font-size:11px;color:#00e5c0;letter-spacing:0.1em;margin-bottom:8px;">WANT MORE CONTROL?</p>
<p style="color:#e8f0ef;margin-bottom:12px;">Upgrade to Harbor Remote for the full dashboard, stats, custom rules and more.</p>
<a href="https://buy.stripe.com/cNi3cugZ1dlR07380T6kg0e" style="background:#00e5c0;color:#0a0e0f;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Upgrade to Remote $5.99/mo</a>
</div>
<div style="border-top:1px solid #1e2a2d;padding-top:20px;margin-top:20px;">
<a href="https://dashboard.harborprivacy.com" style="display:inline-block;border:1px solid #00e5c0;color:#00e5c0;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Your Dashboard</a>
</div>
<p style="padding-top:24px;color:#6b8a87;">Questions? Reply or text <strong style="color:#e8f0ef;">781-974-6196</strong><br>- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
</div>'''
        send_email(email, "Welcome to Harbor Light - Your DNS Privacy Address", html)
        return

    if plan == "remote":
        ios_btn = f'<p><a href="{profile_url}" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:12px 24px;text-decoration:none;font-family:monospace;font-size:13px;">Download iOS DNS Profile</a></p><p style="font-size:12px;color:#6b8a87;">Tap on iPhone/iPad then Settings > General > VPN & Device Management > Install</p>' if profile_url else "<p style='color:#6b8a87;'>iOS profile will be sent separately.</p>"
        html = f'''<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h1 style="font-family:Georgia,serif;font-weight:400;">Your Harbor Privacy Setup</h1>
<p>Hi {name},</p><p>Your private DNS endpoint is ready.</p>
<h2 style="font-family:Georgia,serif;font-weight:400;">Your Personal DoH Address</h2>
<p style="background:#111618;border-left:3px solid #00e5c0;padding:16px;font-family:monospace;font-size:14px;color:#00e5c0;word-break:break-all;">{doh}</p>
<div style="background:#111618;border:1px solid #00e5c0;padding:20px;margin-bottom:24px;"><p style="font-family:monospace;font-size:11px;color:#00e5c0;letter-spacing:0.1em;margin-bottom:8px;">SAVE 44% — UPGRADE TO ANNUAL</p><p style="color:#e8f0ef;margin-bottom:12px;">Lock in your rate for a full year at $39.99. Use code <strong>FOUNDERS10</strong> for 50% off while it lasts.</p><a href="https://buy.stripe.com/9B69AS6knepVbPL2Gz6kg09?prefilled_email={email}" style="background:#00e5c0;color:#0a0e0f;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Upgrade to Annual &#8594;</a></div><h2 style="font-family:Georgia,serif;font-weight:400;">Setup Instructions</h2>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">iPhone / iPad</h3><p style="color:#6b8a87;font-size:13px;margin-bottom:12px;"><strong style="color:#e8f0ef;">Note:</strong> When installing the profile you may see an "Unsigned" notice. This is normal for small businesses and is safe to install. The profile only configures your DNS settings and nothing else.</p>{ios_btn}
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">Android / Pixel</h3>
<p style="color:#6b8a87;font-size:13px;margin-bottom:12px;">Android uses a different setup method. Use the free <strong style="color:#e8f0ef;">Intra app</strong> (by Google) for the best experience with your personal DNS address.</p>
<ol style="color:#6b8a87;font-size:13px;margin-bottom:16px;"><li>Install <strong style="color:#e8f0ef;">Intra</strong> from the Play Store (free, by Google Jigsaw)</li><li>Open Intra > tap the settings gear</li><li>Select "Custom DNS over HTTPS server"</li><li>Paste your personal address: <strong style="color:#e8f0ef;">{doh}</strong></li><li>Tap OK and enable Intra</li></ol>
<p><a href="https://harborprivacy.com/setup/android/{client_id}.html" style="display:inline-block;background:transparent;border:1px solid #00e5c0;color:#00e5c0;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Android Setup Guide + QR Code &#8594;</a></p>
<h3 style="color:#00e5c0;font-family:monospace;font-size:13px;">Xfinity Router</h3>
<ol style="color:#6b8a87;"><li>Go to 10.0.0.1</li><li>Login with router sticker credentials</li><li>Advanced > DNS Settings</li><li>Primary DNS: <strong style="color:#e8f0ef;">doh.harborprivacy.com</strong></li><li>Save and reboot</li></ol>
<div style="border-top:1px solid #1e2a2d;margin-top:32px;padding-top:24px;">
<h3 style="color:#6b8a87;font-family:monospace;font-size:11px;letter-spacing:0.1em;">IF YOU EVER CANCEL - HOW TO REMOVE HARBOR PRIVACY</h3>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">iPhone/iPad:</strong> Settings > General > VPN and Device Management > Harbor Privacy DNS > Remove Profile</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Android/Pixel:</strong> Settings > Network and Internet > Private DNS > set to Off or Automatic</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Xfinity Router:</strong> Go to 10.0.0.1 > Advanced > DNS Settings > restore to Automatic > reboot</p>
<p style="color:#6b8a87;font-size:13px;"><strong style="color:#e8f0ef;">Other Routers:</strong> Router admin panel > DNS settings > set to Automatic > save and reboot</p>
</div>
</p><div style="border-top:1px solid #1e2a2d;padding-top:20px;margin-top:20px;">{('<a href="' + invoice_url + '" style="display:inline-block;background:#00e5c0;color:#0a0e0f;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;margin-right:8px;">View Invoice &#8594;</a>') if invoice_url else ''}<a href="https://billing.stripe.com/p/login/3cI28qfUX5Tp5rn80T6kg00" style="display:inline-block;border:1px solid #00e5c0;color:#00e5c0;padding:10px 20px;text-decoration:none;font-family:monospace;font-size:12px;">Manage Subscription &#8594;</a></div><p style="padding-top:24px;color:#6b8a87;">Questions? Reply or text <strong style="color:#e8f0ef;">781-974-6196</strong><br>- Tim<br><a href="https://harborprivacy.com" style="color:#00e5c0;">harborprivacy.com</a></p>
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
        process_pending_wipes()
        if self.path == "/deploy":
            import hmac, hashlib, subprocess
            length = int(self.headers.get("Content-Length", 0))
            payload = self.rfile.read(length)
            sig = self.headers.get("X-Hub-Signature-256", "")
            secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "").encode()
            if secret:
                expected = "sha256=" + hmac.new(secret, payload, hashlib.sha256).hexdigest()
                if not hmac.compare_digest(expected, sig):
                    self.send_response(400); self.end_headers(); return
            self.send_response(200); self.end_headers()
            subprocess.Popen(["bash", "-c", "cd /var/www/network && git pull origin main >> /home/ubuntu/deploy.log 2>&1 && find /var/www/network -name '*.html' -exec sed -i 's/\xe2\x80\x93/--/g' {} \;"])
            log.info("GitHub deploy triggered")
            return

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
                        generate_qr_code(client_id)
                        invoice_id = s.get("invoice", "")
                        invoice_url = ""
                        if invoice_id:
                            try:
                                import urllib.request as _ur, json as _json
                                req = _ur.Request(f"https://api.stripe.com/v1/invoices/{invoice_id}", headers={"Authorization": f"Bearer {STRIPE_SECRET}"})
                                inv_data = _json.loads(_ur.urlopen(req).read())
                                invoice_url = inv_data.get("hosted_invoice_url", "")
                            except Exception as ie:
                                log.error(f"invoice fetch error: {ie}")
                        send_welcome_email(email, name, client_id, plan, profile_url, invoice_url, plan_type=plan_type)
                        plan_type = meta.get("plan_type", plan)
                        is_trial = s.get("payment_status", "") == "no_payment_required"
                        log_customer(client_id, name, email, plan, stripe_id, plan_type=plan_type, is_trial=is_trial)
                        mark_processed(session_id)
                        log.info(f"Onboarded: {name} ({client_id})")

            elif etype == "invoice.payment_succeeded":
                try:
                    invoice = event["data"]["object"]
                    customer_email = invoice.get("customer_email","")
                    customer_name = invoice.get("customer_name","Customer")
                    lines_data = invoice.get("lines",{}).get("data",[])
                    for line in lines_data:
                        product_id = line.get("pricing",{}).get("price_details",{}).get("product","")
                        if product_id == "prod_UAtyhAUNLKSyLQ":
                            cust = find_customer_by_email(customer_email)
                            if cust:
                                enable_family_safe(cust["client_id"])
                                update_customer_family_safe(customer_email, True)
                                send_family_safe_email(customer_email, customer_name, True)
                                log.info(f"Family Safe enabled for {customer_email}")
                        if product_id == "prod_UE3j4vZAk3WDrb" or line.get("metadata", {}).get("plan", "") == "home-remote-kids":
                            cust = find_customer_by_email(customer_email)
                            if cust:
                                enable_harbor_kids(cust["client_id"])
                                update_customer_harbor_kids(customer_email)
                                send_harbor_kids_email(customer_email, customer_name, cust["client_id"])
                                log.info(f"Harbor Kids enabled and email sent for {customer_email}")
                except Exception as e:
                    log.error(f"invoice handler error: {e}")

            elif etype == "customer.subscription.updated":
                try:
                    sub = data["object"]
                    stripe_id = sub.get("customer", "")
                    items = sub.get("items", {}).get("data", [])
                    if items:
                        interval = items[0].get("price", {}).get("recurring", {}).get("interval", "")
                        interval_count = items[0].get("price", {}).get("recurring", {}).get("interval_count", 1)
                        if interval == "year":
                            new_plan_type = "annual"
                        elif interval == "month" and interval_count == 6:
                            new_plan_type = "6month"
                        elif interval == "month" and interval_count == 3:
                            new_plan_type = "3month"
                        else:
                            new_plan_type = "remote"
                        customers = load_customers()
                        updated = False
                        for c in customers:
                            if c.get("stripe_customer_id") == stripe_id:
                                c["plan_type"] = new_plan_type
                                updated = True
                                log.info(f"Plan updated: {stripe_id} -> {new_plan_type}")
                                break
                        if updated:
                            with open(CUSTOMERS_LOG, "w") as cf:
                                for c in customers:
                                    cf.write(json.dumps(c) + "\n")
                except Exception as e:
                    log.error(f"subscription.updated error: {e}")

            elif etype == "customer.subscription.deleted":
                stripe_id = event["data"]["object"].get("customer", "")
                sub_items = event["data"]["object"].get("items", {}).get("data", [])
                product_id = sub_items[0].get("price", {}).get("product", "") if sub_items else ""
                meta = event["data"]["object"].get("metadata", {})
                plan_meta = meta.get("plan", "")
                customer = find_customer(stripe_id)
                if customer:
                    cid = customer.get("client_id", "")
                    if product_id == "prod_UE3j4vZAk3WDrb" or plan_meta == "home-remote-kids":
                        disable_harbor_kids(cid)
                        update_customer_harbor_kids_off(customer.get("email", ""))
                        log.info(f"Harbor Kids cancelled for {cid}")
                    else:
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
