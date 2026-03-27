#!/usr/bin/env python3
"""
Harbor Privacy Customer Dashboard
dashboard.harborprivacy.com
"""

import os, json, secrets
from datetime import datetime, timedelta
from functools import wraps
from io import BytesIO
import base64

import bcrypt
import jwt
import pyotp
import qrcode
import requests
from flask import Flask, request, jsonify, render_template_string, redirect, make_response, session

app = Flask(__name__)

@app.after_request
def add_no_cache(response):
    if request.path == '/dashboard':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
app.secret_key = os.environ.get("FLASK_SECRET", "harbor-privacy-secret-2026")

SECRET_KEY = os.environ.get("DASHBOARD_SECRET", "change-me")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "")
CUSTOMERS_LOG = os.environ.get("CUSTOMERS_LOG", "/var/log/harbor-customers.json")
USERS_DB = os.environ.get("USERS_DB", "/var/log/harbor-dashboard-users.json")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
ADMIN_EMAIL = "admin@harborprivacy.com"

# ── DATA ──────────────────────────────────────────────────

def load_users():
    try:
        with open(USERS_DB) as f:
            return json.load(f)
    except:
        return {}

def save_users(users):
    with open(USERS_DB, 'w') as f:
        json.dump(users, f, indent=2)

def get_user(email):
    return load_users().get(email.lower())

def save_customers(customers):
    try:
        with open(CUSTOMERS_LOG, "w") as fh:
            for c in customers:
                fh.write(json.dumps(c) + "\n")
        return True
    except Exception as e:
        print("save_customers error: " + str(e))
        return False

def load_customers():
    customers = []
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    if r.get("status") == "active":
                        customers.append(r)
                except:
                    pass
    except:
        pass
    return customers

def update_customer_email(old_email, new_email):
    lines = []
    updated = False
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    c = json.loads(line)
                    if c.get("email", "").lower() == old_email.lower():
                        c["email"] = new_email.lower()
                        updated = True
                    lines.append(json.dumps(c))
                except:
                    lines.append(line)
        if updated:
            with open(CUSTOMERS_LOG, 'w') as f:
                f.write("\n".join(lines) + "\n")
        return updated
    except:
        return False

def find_customer(email):
    for c in load_customers():
        if c.get("email", "").lower() == email.lower():
            return c
    return None

def has_family_addon(client_id):
    """Check if customer has active Family Safe addon by checking AdGuard client metadata"""
    client = get_client(client_id)
    if not client:
        return False
    # Check if parental was enabled via paid addon (tag in client name or metadata)
    # We use the customer log to check for family addon
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    if r.get("client_id") == client_id and r.get("family_safe") == True:
                        return True
                except:
                    pass
    except:
        pass
    return False

# ── SUPPORT CODES ────────────────────────────────────────
import secrets, time as _time
SUPPORT_CODES_FILE = "/var/log/harbor-support-codes.json"

def _load_codes():
    try:
        with open(SUPPORT_CODES_FILE) as f:
            return json.load(f)
    except:
        return {}

def _save_codes(codes):
    try:
        with open(SUPPORT_CODES_FILE, 'w') as f:
            json.dump(codes, f)
        os.chmod(SUPPORT_CODES_FILE, 0o600)
    except Exception as e:
        print(f"Support code save error: {e}")
LOGIN_ATTEMPTS = {}  # {ip: {count, locked_until}}

def check_rate_limit(ip):
    import time as _t
    entry = LOGIN_ATTEMPTS.get(ip, {})
    if entry.get("locked_until", 0) > _t.time():
        return False
    return True

def record_failed_login(ip):
    import time as _t
    entry = LOGIN_ATTEMPTS.get(ip, {"count": 0, "locked_until": 0})
    entry["count"] = entry.get("count", 0) + 1
    if entry["count"] >= 5:
        entry["locked_until"] = _t.time() + 900
        entry["count"] = 0
    LOGIN_ATTEMPTS[ip] = entry

def clear_failed_logins(ip):
    LOGIN_ATTEMPTS.pop(ip, None)

def generate_support_code(client_id):
    code = str(secrets.randbelow(900000) + 100000)
    codes = _load_codes()
    codes[client_id] = {"code": code, "expires": _time.time() + 1800, "attempts": 0, "created": _time.time(), "used": False}
    _save_codes(codes)
    return code

def verify_support_code(client_id, code):
    if not code:
        return False
    codes = _load_codes()
    entry = codes.get(client_id)
    if not entry:
        return False
    if _time.time() > entry["expires"]:
        del codes[client_id]
        _save_codes(codes)
        return False
    if entry.get("attempts", 0) >= 5:
        del codes[client_id]
        _save_codes(codes)
        return False
    if entry["code"] == str(code):
        return True
    entry["attempts"] = entry.get("attempts", 0) + 1
    codes[client_id] = entry
    _save_codes(codes)
    return False

def revoke_support_code(client_id):
    codes = _load_codes()
    codes.pop(client_id, None)
    _save_codes(codes)

# ── ADGUARD ──────────────────────────────────────────────

def agh_get(path):
    try:
        r = requests.get(f"{ADGUARD_URL}{path}", auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        return r.json() if r.status_code == 200 else {}
    except:
        return {}

def agh_post(path, data):
    try:
        r = requests.post(f"{ADGUARD_URL}{path}", json=data, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        return r.status_code == 200
    except:
        return False

def get_allowed_clients():
    access = agh_get("/control/access/list")
    return access.get("allowed_clients", [])

def get_client(client_id):
    clients = agh_get("/control/clients")
    for c in clients.get("clients", []):
        if client_id in c.get("ids", []):
            return c
    return {}

def is_client_allowed(client_id):
    return client_id in get_allowed_clients()

def get_stats():
    return agh_get("/control/stats")

def get_client_stats(client_id):
    """Pull per-client stats from AdGuard stats API"""
    try:
        stats = agh_get("/control/stats")
        # Get total queries for this client
        top_clients = stats.get("top_clients", [])
        total = 0
        for entry in top_clients:
            if client_id in entry:
                total = entry[client_id]
                break
        # Get global block rate and apply to client
        global_total = stats.get("num_dns_queries", 0)
        global_blocked = stats.get("num_blocked_filtering", 0) + stats.get("num_replaced_safebrowsing", 0) + stats.get("num_replaced_parental", 0)
        global_pct = round(global_blocked / max(global_total, 1) * 100, 1)
        # Estimate blocked for this client
        blocked = round(total * global_pct / 100)
        pct = global_pct
        # Top blocked domains globally
        top_blocked_raw = stats.get("top_blocked_domains", [])[:5]
        top_blocked = [{"name": list(d.keys())[0], "count": list(d.values())[0]} for d in top_blocked_raw if d]
        return {"total": total, "blocked": blocked, "pct": pct, "top_blocked": []}
    except:
        return {"total": 0, "blocked": 0, "pct": 0, "top_blocked": []}

def get_all_blocked_services():
    data = agh_get("/control/blocked_services/all")
    services = data.get("blocked_services", [])
    groups = {}
    for s in services:
        g = s.get("group_id", "other")
        if g not in groups:
            groups[g] = []
        groups[g].append({"id": s["id"], "name": s["name"]})
    return groups

def get_client_blocked_services(client_id):
    client = get_client(client_id)
    if not client:
        return []
    return client.get("blocked_services") or []

PROFILES = {
    "kid": {
        "name": "Kid Mode",
        "icon": "👧",
        "desc": "Blocks social media, adult content, dating apps, gambling and streaming",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","tumblr",
                     "tinder","discord","youtube","twitch","4chan","9gag",
                     "amino","bigo_live","vk","wechat","telegram","whatsapp","viber","signal",
                     "dailymotion","vimeo","bluesky","clubhouse","wizz","chatgpt","deepseek",
                     "copilot","claude","betano","betfair","betway","blaze"]
    },
    "work": {
        "name": "Work Focus",
        "icon": "💼",
        "desc": "Blocks social media, streaming and gaming to keep you focused",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","youtube",
                     "twitch","netflix","disneyplus","amazon_streaming","spotify","spotify_video",
                     "steam","discord","dailymotion","vimeo","crunchyroll","plex","pluto_tv",
                     "apple_streaming","tidal","soundcloud","deezer","bilibili",
                     "activision_blizzard","battle_net","epic_games","electronic_arts",
                     "riot_games","roblox","rockstar_games","ubisoft","xboxlive"]
    },
    "gaming": {
        "name": "Gaming Mode",
        "icon": "🎮",
        "desc": "Blocks social media and distractions, leaves gaming services open",
        "services": ["tiktok","snapchat","instagram","twitter","facebook","reddit","youtube",
                     "amazon_streaming","netflix","disneyplus","tinder","tumblr",
                     "dailymotion","vimeo","bilibili","shein","temu","betano","betfair","betway"]
    }
}

def save_profile_snapshot(client_id, services):
    """Save current services as custom snapshot before applying a profile"""
    lines = []
    updated = False
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                    if r.get("client_id") == client_id:
                        r["custom_services_snapshot"] = services
                        updated = True
                    lines.append(json.dumps(r))
                except:
                    lines.append(line)
        if updated:
            with open(CUSTOMERS_LOG, "w") as f:
                f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"Snapshot save error: {e}")

def save_active_profile(client_id, profile_name):
    """Save the active profile name to customer record"""
    lines = []
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if not line: continue
                try:
                    r = json.loads(line)
                    if r.get("client_id") == client_id:
                        r["active_profile"] = profile_name
                    lines.append(json.dumps(r))
                except:
                    lines.append(line)
        with open(CUSTOMERS_LOG, "w") as f:
            f.write("\n".join(lines) + "\n")
    except Exception as e:
        print(f"Profile save error: {e}")

def set_client_blocked_services(client_id, services):
    client = get_client(client_id)
    if not client:
        with open("/tmp/profile_debug.txt", "a") as dbg:
            dbg.write(f"set_client_blocked: no client found for {client_id}\n")
        return False
    updated = {**client, "blocked_services": services, "use_global_blocked_services": False}
    try:
        r = requests.post(f"{ADGUARD_URL}/control/clients/update", json={"name": client.get("name", client_id), "data": updated}, auth=(ADGUARD_USER, ADGUARD_PASS), timeout=10)
        with open("/tmp/profile_debug.txt", "a") as dbg:
            dbg.write(f"set_client_blocked: status={r.status_code} response={r.text[:100]}\n")
        return r.status_code == 200
    except Exception as e:
        with open("/tmp/profile_debug.txt", "a") as dbg:
            dbg.write(f"set_client_blocked error: {e}\n")
        return False

def add_custom_rule(client_id, domain, block=True):
    prefix = "||" if block else "@@||"
    rule = f"{prefix}{domain}^$client={client_id}"
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        if rule not in rules:
            rules.append(rule)
            return agh_post("/control/filtering/set_rules", {"rules": rules})
        return True
    except Exception as e:
        log.error(f"add_custom_rule error: {e}")
        return False

def get_client_rules(client_id):
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        return [r for r in rules if f"$client={client_id}" in r]
    except:
        return []

def remove_custom_rule(client_id, rule):
    # rule passed in may or may not have $client= suffix
    full_rule = rule if f"$client={client_id}" in rule else f"{rule}$client={client_id}"
    try:
        data = agh_get("/control/filtering/status")
        rules = data.get("user_rules", [])
        new_rules = [r for r in rules if r != full_rule and r != rule]
        return agh_post("/control/filtering/set_rules", {"rules": new_rules})
    except Exception as e:
        log.error(f"remove_custom_rule error: {e}")
        return False
    return agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": {**client, "filtering_rules": rules}})

# ── AUTH ──────────────────────────────────────────────────

def make_token(email, is_admin=False):
    return jwt.encode({
        "email": email,
        "admin": is_admin,
        "exp": datetime.utcnow() + timedelta(hours=8)
    }, SECRET_KEY, algorithm="HS256")

def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("hp_token")
        if not token:
            return redirect("/login")
        payload = verify_token(token)
        if not payload:
            return redirect("/login")
        request.user_email = payload["email"]
        request.is_admin = payload.get("admin", False)
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get("hp_token")
        if not token:
            return redirect("/login")
        payload = verify_token(token)
        if not payload or not payload.get("admin"):
            return redirect("/dashboard")
        request.user_email = payload["email"]
        request.is_admin = True
        return f(*args, **kwargs)
    return decorated

def send_email(to, subject, html):
    try:
        requests.post("https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": f"Harbor Privacy <{FROM_EMAIL}>", "to": [to], "subject": subject, "html": html},
            timeout=10)
    except:
        pass

# ── SHARED STYLE ──────────────────────────────────────────

STYLE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="icon" type="image/svg+xml" href="https://harborprivacy.com/favicon.svg">
<link rel="icon" type="image/png" sizes="32x32" href="https://harborprivacy.com/favicon-32.png">
<link rel="apple-touch-icon" sizes="180x180" href="https://harborprivacy.com/favicon-180.png">
<link rel="manifest" href="https://harborprivacy.com/manifest.json">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="Harbor Privacy">
<meta name="theme-color" content="#00e5c0">
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>{% block title %}Harbor Privacy Dashboard{% endblock %}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&family=DM+Serif+Display:ital@0;1&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0a0e0f;--surface:#111618;--border:#1e2a2d;--accent:#00e5c0;--text:#e8f0ef;--muted:#6b8a87;--danger:#ff4e4e;}
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;font-weight:300;line-height:1.7;min-height:100vh;}
  body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:0.3;pointer-events:none;z-index:0;}
  nav{padding:16px 32px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;background:var(--surface);}
  .logo{font-family:'DM Mono',monospace;font-size:15px;color:var(--accent);letter-spacing:0.1em;text-decoration:none;}
  .logo span{color:var(--muted);}
  .nav-links{display:flex;gap:20px;align-items:center;}
  .nav-links a{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;letter-spacing:0.06em;transition:color 0.15s;}
  .nav-links a:hover,.nav-links a.active{color:var(--accent);}
  .wrap{max-width:960px;margin:0 auto;padding:48px 32px 80px;position:relative;z-index:1;}
  .wrap-sm{max-width:500px;margin:0 auto;padding:60px 32px;position:relative;z-index:1;}
  .card{background:var(--surface);border:1px solid var(--border);padding:32px;margin-bottom:20px;}
  .card-label{font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;}
  h1{font-family:'DM Serif Display',serif;font-size:40px;font-weight:400;line-height:1.1;}
  h2{font-family:'DM Serif Display',serif;font-size:26px;font-weight:400;margin-bottom:12px;}
  input,select{background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:'DM Sans',sans-serif;font-size:14px;padding:12px 16px;outline:none;width:100%;margin-bottom:12px;transition:border 0.2s;}
  input:focus,select:focus{border-color:var(--accent);}
  input::placeholder{color:var(--muted);}
  input:disabled{opacity:0.4;cursor:not-allowed;}
  .btn{background:var(--accent);color:var(--bg);padding:12px 24px;font-family:'DM Mono',monospace;font-size:12px;letter-spacing:0.08em;border:none;cursor:pointer;font-weight:500;text-decoration:none;display:inline-block;transition:background 0.2s;}
  .btn:hover{background:#00ffda;}
  .btn-sm{padding:6px 14px;font-size:10px;}
  .btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);}
  .btn-outline:hover{border-color:var(--accent);color:var(--accent);background:transparent;}
  .btn-danger{background:var(--danger);}
  .btn-danger:hover{background:#ff6b6b;}
  .btn-disabled{background:var(--border);color:var(--muted);cursor:not-allowed;pointer-events:none;}
  .stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);margin-bottom:20px;}
  .stat{background:var(--surface);padding:24px;}
  .stat-num{font-family:'DM Serif Display',serif;font-size:40px;color:var(--accent);line-height:1;margin-bottom:6px;}
  .stat-num.muted{color:var(--border);}
  .stat-label{font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:0.12em;text-transform:uppercase;}
  .toggle-row{display:flex;justify-content:space-between;align-items:center;padding:16px 0;border-bottom:1px solid var(--border);}
  .toggle-row:last-child{border-bottom:none;}
  .toggle-label{font-size:15px;color:var(--text);}
  .toggle-label.locked{color:var(--muted);}
  .toggle-desc{font-size:13px;color:var(--muted);margin-top:3px;}
  .toggle{position:relative;width:48px;height:26px;flex-shrink:0;}
  .toggle input{opacity:0;width:0;height:0;}
  .slider{position:absolute;inset:0;background:var(--border);border-radius:26px;transition:0.3s;cursor:pointer;}
  .slider:before{content:'';position:absolute;height:20px;width:20px;left:3px;bottom:3px;background:var(--muted);border-radius:50%;transition:0.3s;}
  input:checked+.slider{background:var(--accent);}
  input:checked+.slider:before{transform:translateX(22px);background:var(--bg);}
  .slider.locked{cursor:not-allowed;opacity:0.4;}
  .row{display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);}
  .row:last-child{border-bottom:none;}
  .rule-block{color:var(--danger);font-family:'DM Mono',monospace;font-size:12px;}
  .rule-allow{color:var(--accent);font-family:'DM Mono',monospace;font-size:12px;}
  .badge{font-family:'DM Mono',monospace;font-size:9px;padding:3px 8px;letter-spacing:0.1em;font-weight:500;vertical-align:middle;}
  .badge-on{background:var(--accent);color:var(--bg);}
  .badge-off{background:var(--border);color:var(--muted);}
  .badge-admin{background:#7c3aed;color:#fff;}
  .badge-owner{background:var(--accent);color:#0a0e0f;}
  .badge-trial{background:#f59e0b;color:#0a0e0f;}
  .badge-monthly{background:#3b82f6;color:#fff;}
  .badge-3month{background:#10b981;color:#0a0e0f;}
  .badge-6month{background:#059669;color:#fff;}
  .badge-annual{background:#047857;color:#fff;}
  .badge-family{background:#7c3aed;color:#fff;}
  .badge-locked{background:var(--border);color:var(--muted);}
  .profile-btn{background:var(--surface);border:1px solid var(--border);color:var(--text);padding:16px;cursor:pointer;text-align:center;font-family:'DM Mono',monospace;font-size:12px;transition:border-color 0.2s;}
  .profile-btn:hover{border-color:var(--accent);}
  .profile-active{border-color:var(--accent) !important;background:rgba(0,229,192,0.08) !important;}
  .doh-box{background:var(--bg);border-left:3px solid var(--accent);padding:16px;font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);word-break:break-all;margin:12px 0;}
  .doh-box.locked{border-left-color:var(--border);color:var(--muted);filter:blur(4px);user-select:none;}
  .error{color:var(--danger);font-family:'DM Mono',monospace;font-size:12px;margin-bottom:16px;padding:12px 16px;border:1px solid var(--danger);}
  .success{color:var(--accent);font-family:'DM Mono',monospace;font-size:12px;margin-bottom:16px;padding:12px 16px;border:1px solid var(--accent);}
  .note{font-size:14px;color:var(--muted);line-height:1.6;}
  .locked-overlay{background:var(--surface);border:1px solid var(--border);padding:20px 24px;display:flex;align-items:center;gap:16px;margin-bottom:20px;}
  .locked-icon{font-size:24px;flex-shrink:0;}
  .locked-text{font-size:14px;color:var(--muted);}
  .locked-text strong{color:var(--text);display:block;margin-bottom:4px;}
  .customer-grid{display:grid;gap:1px;background:var(--border);border:1px solid var(--border);}
  .customer-row{background:var(--surface);padding:18px 24px;display:grid;grid-template-columns:1fr 140px 110px 80px 100px;gap:16px;align-items:center;transition:background 0.15s;}
  .customer-row:hover{background:#151c1e;}
  .customer-header{background:var(--bg) !important;border-bottom:1px solid var(--border);}
  @media(max-width:768px){
    .stat-grid{grid-template-columns:1fr;}
    .wrap{padding:32px 20px 60px;}
    .wrap-sm{padding:40px 20px;}
    nav{padding:14px 20px;}
    .customer-row{grid-template-columns:1fr 80px;}
  }
</style>
<script>
var TIMEOUT=30*60*1000,WARNING=25*60*1000,timer,warnTimer,warned=false;
function resetTimer(){clearTimeout(timer);clearTimeout(warnTimer);warned=false;var w=document.getElementById("timeout-warning");if(w)w.style.display="none";warnTimer=setTimeout(showWarning,WARNING);timer=setTimeout(function(){window.location.href="/logout";},TIMEOUT);}
function showWarning(){if(warned)return;warned=true;var w=document.getElementById("timeout-warning");if(w)w.style.display="flex";}
document.addEventListener("mousemove",resetTimer);
document.addEventListener("keypress",resetTimer);
document.addEventListener("click",resetTimer);
document.addEventListener("touchstart",resetTimer);
window.addEventListener("load",resetTimer);
</script>
"""

NAV_CUSTOMER = """
<div id="timeout-warning" style="display:none;position:fixed;bottom:24px;right:24px;background:#111618;border:1px solid #00e5c0;padding:20px 24px;z-index:9999;font-family:monospace;font-size:12px;color:#e8f0ef;flex-direction:column;gap:12px;max-width:300px;"><span>You will be logged out in 5 minutes due to inactivity.</span><button onclick="resetTimer()" style="background:#00e5c0;color:#0a0e0f;border:none;padding:8px 16px;cursor:pointer;font-family:monospace;font-size:11px;">Stay Logged In</button></div>
<nav>
  <a href="/dashboard" class="logo">harbor<span>/</span>privacy</a>
  <div class="nav-links">
    <a href="https://harborprivacy.com">← Site</a>
    <a href="/dashboard" class="{{ 'active' if active == 'dashboard' else '' }}">Dashboard</a>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    {% if user_email == "tim@harborprivacy.com" %}<span class="badge badge-owner">OWNER</span>{% endif %}
    {% if is_trial %}<span class="badge badge-trial">FREE TRIAL</span>{% endif %}
    {% if plan_badge %}<span class="badge badge-{{ plan_badge.lower().replace(' ','-') }}">{{ plan_badge }}</span>{% endif %}
    {% if has_family_badge %}<span class="badge badge-family">FAMILY SAFE</span>{% endif %}
    <a href="/logout">Sign Out</a>
  </div>
</nav>"""

NAV_ADMIN = """
<div id="timeout-warning" style="display:none;position:fixed;bottom:24px;right:24px;background:#111618;border:1px solid #00e5c0;padding:20px 24px;z-index:9999;font-family:monospace;font-size:12px;color:#e8f0ef;flex-direction:column;gap:12px;max-width:300px;"><span>You will be logged out in 5 minutes due to inactivity.</span><button onclick="resetTimer()" style="background:#00e5c0;color:#0a0e0f;border:none;padding:8px 16px;cursor:pointer;font-family:monospace;font-size:11px;">Stay Logged In</button></div>
<nav>
  <a href="/admin" class="logo">harbor<span>/</span>privacy</a>
  <div class="nav-links">
    <a href="https://harborprivacy.com">← Site</a>
    <span class="badge badge-admin">ADMIN</span>
    <a href="/admin" class="{{ 'active' if active == 'admin' else '' }}">Customers</a>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    <a href="/logout">Sign Out</a>
  </div>
</nav>"""

# ── ROUTES: AUTH ──────────────────────────────────────────

@app.route("/")
def index():
    token = request.cookies.get("hp_token")
    if token:
        payload = verify_token(token)
        if payload:
            return redirect("/admin" if payload.get("admin") else "/dashboard")
    return redirect("/login")

@app.route("/login", methods=["GET", "POST"])
def login():
    # Step 1: email only
    # Step 2: password (or setup if new)

    step = request.args.get("step", "1")
    email = request.args.get("email", "").lower().strip()
    error = None
    show_2fa = False

    if request.method == "POST":
        action = request.form.get("action", "")
        email = request.form.get("email", "").lower().strip()

        if action == "check_email":
            # Step 1: check if email exists
            if not email:
                error = "Please enter your email address."
                step = "1"
            else:
                user = get_user(email)
                if user:
                    # Has account - go to password step
                    step = "2"
                elif email == ADMIN_EMAIL:
                    # Admin first time setup
                    return redirect(f"/setup?email={email}&admin=1")
                else:
                    customer = find_customer(email)
                    if customer:
                        # Customer but no account yet - go to setup
                        return redirect(f"/setup?email={email}")
                    else:
                        error = "No Harbor Privacy subscription found for this email. Need help? Email support@harborprivacy.com"
                        step = "1"

        elif action == "login":
            ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
            if not check_rate_limit(ip):
                error = "Too many failed attempts. Try again in 15 minutes."
                step = "2"
            else:
                password = request.form.get("password", "")
                totp_code = request.form.get("totp", "").strip()
                user = get_user(email)
                if not user:
                    error = "Session expired. Please start over."
                    step = "1"
                    email = ""
                elif not bcrypt.checkpw(password.encode(), user["password"].encode()):
                    record_failed_login(ip)
                    error = "Incorrect password."
                    step = "2"
                    show_2fa = bool(user.get("totp_secret"))
                else:
                    if user.get("totp_secret"):
                        if not totp_code:
                            session["pw_verified"] = email
                            show_2fa = True
                            step = "2"
                        elif session.get("pw_verified") != email:
                            error = "Session expired. Please start over."
                            step = "1"
                            session.pop("pw_verified", None)
                        elif not pyotp.TOTP(user["totp_secret"]).verify(totp_code, valid_window=1):
                            error = "Invalid 2FA code."
                            show_2fa = True
                            step = "2"
                        else:
                            session.pop("pw_verified", None)
                            is_admin = email == ADMIN_EMAIL
                            token = make_token(email, is_admin=is_admin)
                            resp = make_response(redirect("/admin" if is_admin else "/dashboard"))
                            resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400)
                            return resp
                    else:
                        is_admin = email == ADMIN_EMAIL
                        token = make_token(email, is_admin=is_admin)
                        resp = make_response(redirect("/admin" if is_admin else "/dashboard"))
                        resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400)
                        return resp

    html = STYLE + """
<nav>
  <a href="https://harborprivacy.com" class="logo">harbor<span>/</span>privacy</a>
  <div class="nav-links">
    <a href="https://harborprivacy.com" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">← Back to site</a>
  </div>
</nav>
<div class="wrap-sm">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Customer Dashboard</p>
  <h1 style="margin-bottom:8px;">Sign in.</h1>
  <p class="note" style="margin-bottom:32px;">{% if step == '1' %}Enter your email to get started.{% else %}Welcome back — enter your password.{% endif %}</p>

  {% if error %}<div class="error">{{ error }}</div>{% endif %}

  {% if step == '1' %}
  <form method="POST">
    <input type="hidden" name="action" value="check_email">
    <input type="email" name="email" placeholder="Your email address" value="{{ email }}" required autocomplete="email" autofocus>
    <button type="submit" class="btn" style="width:100%;">Continue →</button>
  </form>
  {% else %}
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="email" value="{{ email }}">
    <div style="background:var(--surface);border:1px solid var(--border);padding:12px 16px;margin-bottom:16px;font-family:'DM Mono',monospace;font-size:13px;color:var(--muted);display:flex;justify-content:space-between;align-items:center;">
      <span>{{ email }}</span>
      <a href="/login" style="font-size:11px;color:var(--accent);text-decoration:none;">Change</a>
    </div>
    {% if show_2fa %}
    <p style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;margin-bottom:8px;">AUTHENTICATOR CODE</p>
    <input type="text" name="totp" placeholder="6-digit code" maxlength="6" autocomplete="one-time-code" autofocus>
    {% else %}
    <input type="password" name="password" placeholder="Your password" required autocomplete="current-password" autofocus>
    {% endif %}
    <button type="submit" class="btn" style="width:100%;margin-top:4px;">{% if show_2fa %}Verify →{% else %}Sign In →{% endif %}</button>
  </form>
  <div style="margin-top:16px;">
    <a href="/forgot?email={{ email }}" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Forgot password?</a>
  </div>
  {% endif %}
</div>"""
    return render_template_string(html, step=step, email=email, error=error, show_2fa=show_2fa)

@app.route("/dns-whoami/<token>")
def dns_whoami(token):
    import json as _json, os, time
    RESULTS_FILE = "/tmp/harbor-whoami-results.json"
    try:
        if os.path.exists(RESULTS_FILE):
            results = _json.loads(open(RESULTS_FILE).read())
            if token in results:
                entry = results[token]
                if time.time() - entry["ts"] < 300:
                    resp = jsonify({"ip": entry["ip"], "ok": True, "found": True})
                    resp.headers["Access-Control-Allow-Origin"] = "*"
                    return resp
            now = time.time()
            recent = [(k,v) for k,v in results.items() if now - v["ts"] < 10]
            if recent:
                latest = sorted(recent, key=lambda x: x[1]["ts"], reverse=True)[0]
                resp = jsonify({"ip": latest[1]["ip"], "ok": True, "found": True})
                resp.headers["Access-Control-Allow-Origin"] = "*"
                return resp
    except Exception as e:
        print(f"dns_whoami error: {e}")
    resp = jsonify({"ok": True, "found": False})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/dns-check")
def dns_check():
    ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr
    resp = jsonify({"ip": ip, "ok": True})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/setup", methods=["GET", "POST"])
def setup():
    email = request.args.get("email", "") or request.form.get("email", "")
    is_admin = request.args.get("admin", "0") == "1" or request.form.get("is_admin", "0") == "1"
    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
        email = request.form.get("email", "").lower().strip()
        is_admin = request.form.get("is_admin", "0") == "1"

        if not is_admin and not find_customer(email):
            error = "No active subscription found. Contact support@harborprivacy.com"
        elif len(password) < 8:
            error = "Password must be at least 8 characters."
        elif password != password2:
            error = "Passwords do not match."
        else:
            users = load_users()
            hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
            users[email.lower()] = {"email": email.lower(), "password": hashed, "created": datetime.utcnow().isoformat()}
            save_users(users)
            token = make_token(email.lower(), is_admin=is_admin)
            resp = make_response(redirect("/admin" if is_admin else "/setup/2fa-prompt"))
            resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400)
            return resp

    html = STYLE + """
<nav>
  <a href="https://harborprivacy.com" class="logo">harbor<span>/</span>privacy</a>
</nav>
<div class="wrap-sm">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">{% if is_admin %}Admin Setup{% else %}First Time Setup{% endif %}</p>
  <h1 style="margin-bottom:8px;">Create your password.</h1>
  <p class="note" style="margin-bottom:32px;">{% if is_admin %}Set a password for your Harbor Privacy admin account.{% else %}Welcome to Harbor Privacy. Create a password to access your dashboard.{% endif %}</p>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="hidden" name="email" value="{{ email }}">
    <input type="hidden" name="is_admin" value="{{ '1' if is_admin else '0' }}">
    <div style="background:var(--surface);border:1px solid var(--border);padding:12px 16px;margin-bottom:16px;font-family:'DM Mono',monospace;font-size:13px;color:var(--muted);">{{ email }}</div>
    <input type="password" name="password" placeholder="Choose a password (min 8 characters)" required minlength="8" autofocus>
    <input type="password" name="password2" placeholder="Confirm your password" required>
    <button type="submit" class="btn" style="width:100%;margin-top:4px;">Create Account →</button>
  </form>
</div>"""
    return render_template_string(html, email=email, is_admin=is_admin, error=error)


@app.route("/setup/2fa-prompt")
@login_required
def setup_2fa_prompt():
    html = STYLE + """
<nav>
  <a href="https://harborprivacy.com" class="logo">harbor<span>/</span>privacy</a>
</nav>
<div class="wrap-sm" style="text-align:center;">
  <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;">Account Security</p>
  <h1 style="margin-bottom:12px;">Add two-factor authentication?</h1>
  <p class="note" style="margin-bottom:32px;">2FA adds an extra layer of security to your account. You can always set it up later in Settings.</p>
  <div style="display:flex;flex-direction:column;gap:12px;">
    <a href="/settings/2fa/setup" class="btn" style="width:100%;text-align:center;">Set Up 2FA Now →</a>
    <a href="/dashboard" style="font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);text-align:center;padding:12px;">Skip for now</a>
  </div>
</div>"""
    return render_template_string(html)

@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("hp_token")
    return resp

# ── CUSTOMER DASHBOARD ────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    if request.is_admin and not request.args.get("preview"):
        return redirect("/admin")

    email = request.user_email
    customer = find_customer(email)
    is_active = customer is not None
    client_id = customer.get("client_id", "") if customer else ""
    client = get_client(client_id) if client_id else {}
    name = customer.get("name", email.split("@")[0]).split()[0].title() if customer else email.split("@")[0].title()

    # Stats - per client
    if is_active and client_id:
        client_stats = get_client_stats(client_id)
        total = client_stats["total"]
        blocked = client_stats["blocked"]
        pct = client_stats["pct"]
        top_blocked = client_stats["top_blocked"]
    else:
        total = blocked = pct = 0
        top_blocked = []

    rules = get_client_rules(client_id) if client_id else []
    family_safe = client.get("parental_enabled", False) if client else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    filtering_paused = not client.get("filtering_enabled", True) if client else False
    has_family = has_family_addon(client_id) if client_id else False
    is_founder = customer.get("is_founder", False) if customer else False
    plan_type = customer.get("plan_type", "") if customer else ""
    is_trial = customer.get("is_trial", False) if customer else False
    plan_badge = ""

    # Harbor Light plan — stripped dashboard
    if plan_type == "harbor-remote-light":
        html = STYLE + NAV_CUSTOMER + """
<div class="wrap" style="max-width:580px;">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Harbor Light</p>
    <h1>{{ name }}</h1>
  </div>

  <div class="card">
    <div class="card-label">Your DoH Address</div>
    <div class="doh-box" id="doh-address">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
    <button onclick="copyDoH()" style="margin-top:8px;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;cursor:pointer;" id="copy-btn">Copy Address</button>
    <script>
    function copyDoH(){
      var text = document.getElementById('doh-address').innerText;
      navigator.clipboard.writeText(text).then(function(){
        var btn = document.getElementById('copy-btn');
        btn.innerText = 'Copied!';
        setTimeout(function(){ btn.innerText = 'Copy Address'; }, 2000);
      });
    }
    </script>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;">
      <a href="https://harborprivacy.com/profiles/{{ client_id }}.mobileconfig" style="display:inline-block;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;text-decoration:none;">Download iOS Profile</a>
      <a href="https://harborprivacy.com/setup/android/{{ client_id }}" target="_blank" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;text-decoration:none;">Android Setup + QR</a>
    </div>
    <p class="note" style="margin-top:12px;">Add this to your iPhone under Settings → General → VPN & Device Management, or Android under Settings → Private DNS.</p>
  </div>

  <div class="card">
    <div class="card-label">Block or Allow a Site</div>
    <p class="note" style="margin-bottom:16px;">If something gets blocked that should not be, allow it here. Or block a specific site on your network.</p>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px;">
      <input type="text" id="light-domain" placeholder="example.com" style="flex:1;min-width:140px;background:var(--bg);border:1px solid var(--border);color:var(--text);padding:10px 12px;font-family:'DM Mono',monospace;font-size:13px;">
      <button onclick="lightAddRule(false)" class="btn" style="background:var(--accent);color:var(--bg);">Allow</button>
      <button onclick="lightAddRule(true)" class="btn" style="background:transparent;border:1px solid var(--danger);color:var(--danger);">Block</button>
    </div>
    <div id="light-rules-list">
      {% for rule in rules %}
      <div class="row" style="display:flex;justify-content:space-between;align-items:center;padding:8px 0;border-bottom:1px solid var(--border);">
        <span class="{% if rule.startswith('@@') %}rule-allow{% else %}rule-block{% endif %}" style="font-family:'DM Mono',monospace;font-size:12px;">{{ rule }}</span>
        <button onclick="removeRule('{{ rule }}')" class="btn btn-danger btn-sm">Remove</button>
      </div>
      {% else %}
      <p class="note">No custom rules yet.</p>
      {% endfor %}
    </div>
    <script>
    function lightAddRule(block){
      var domain = document.getElementById('light-domain').value.trim();
      if(!domain) return;
      fetch('/api/rule', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({domain:domain, block:block})})
        .then(r=>r.json()).then(d=>{ if(d.ok) location.reload(); else alert('Error: '+d.error); });
    }
    </script>
  </div>

  <div class="card" style="border-color:var(--accent);background:rgba(0,229,192,0.04);">
    <div class="card-label" style="color:var(--accent);">Upgrade to Harbor Remote</div>
    <p style="color:var(--text);font-size:14px;margin-bottom:16px;">Get your full dashboard — see your stats, block specific services, set custom rules, and more.</p>
    <div style="display:flex;gap:12px;align-items:center;flex-wrap:wrap;">
      <a href="https://buy.stripe.com/cNi3cugZ1dlR07380T6kg0e?prefilled_email={{ user_email }}" target="_blank" class="btn">Upgrade to Remote — $5.99/mo →</a>
      <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Cancel anytime</span>
    </div>
  </div>

  <div class="card">
    <div class="card-label">Support</div>
    <p class="note" style="margin-bottom:16px;">Need help with setup or have a question?</p>
    <a href="mailto:support@harborprivacy.com" class="btn" style="background:transparent;border-color:var(--border);color:var(--text);">Email Support →</a>
  </div>

  <div class="card">
    <div class="card-label">Settings</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <a href="/settings" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Change Password →</a>
      <a href="/settings" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Two-Factor Authentication →</a>
      <a href="/settings/data-request" style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);text-decoration:none;">Download My Data →</a>
    </div>
  </div>

</div>
</html>"""
        return render_template_string(html, name=name, client_id=client_id, active="dashboard")
    if plan_type == "harbor-remote-light": plan_badge = "LIGHT"
    elif plan_type == "3month": plan_badge = "3-MONTH"
    elif plan_type == "6month": plan_badge = "6-MONTH"
    elif plan_type == "annual": plan_badge = "ANNUAL"
    elif is_active and not is_trial: plan_badge = "MONTHLY"
    has_family_badge = family_safe


    html = STYLE + NAV_CUSTOMER + """
<div class="wrap">

  <div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:32px;flex-wrap:wrap;gap:16px;">
    <div>
      <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Your Dashboard</p>
      <h1>{{ name }} {% if is_founder %}<span class="badge" style="background:#00e5c0;color:#0a0e0f;font-size:10px;vertical-align:middle;">FOUNDER</span>{% endif %}</h1>
    </div>
    {% if is_active %}
    <div style="text-align:right;">
      <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:0.1em;margin-bottom:4px;">CLIENT ID</div>
      <div style="font-family:'DM Mono',monospace;font-size:14px;color:var(--accent);">{{ client_id }}</div>
    </div>
    {% else %}
    <span class="badge badge-locked" style="padding:8px 16px;font-size:11px;">NO ACTIVE PLAN</span>
    {% endif %}
  </div>

  {% if is_active %}
  <div style="margin-bottom:24px;display:flex;align-items:center;gap:12px;flex-wrap:wrap;">
    <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Protection:</div>
    {% if filtering_paused %}
    <span class="badge badge-off" style="padding:6px 12px;">PAUSED</span>
    <button onclick="togglePause(false)" class="btn" style="padding:8px 18px;font-size:11px;">Resume Protection</button>
    <span style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);">All filtering off — re-enable when done troubleshooting</span>
    {% else %}
    <span class="badge badge-on" style="padding:6px 12px;">ACTIVE</span>
    <button onclick="togglePause(true)" class="btn" style="padding:8px 18px;font-size:11px;background:transparent;border:1px solid var(--border);color:var(--muted);">Pause for Troubleshooting</button>
    {% endif %}
  </div>
  {% endif %}

  {% if not is_active %}
  <div class="locked-overlay" style="border-color:var(--accent);background:#00e5c008;margin-bottom:32px;">
    <div class="locked-icon">⚠</div>
    <div class="locked-text">
      <strong>No active Harbor Remote subscription found</strong>
      Your dashboard is ready — features will unlock once your subscription is active. If you just subscribed, try refreshing in a few minutes.
      <div style="margin-top:12px;display:flex;gap:10px;flex-wrap:wrap;">
        <a href="https://harborprivacy.com/pricing" class="btn btn-sm">View Plans →</a>
        <a href="/dashboard" class="btn btn-sm btn-outline">Refresh</a>
        <a href="mailto:support@harborprivacy.com" class="btn btn-sm btn-outline">Get Help</a>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- STATS -->
  <div class="stat-grid">
    <div class="stat">
      <div class="stat-num {% if not is_active %}muted{% endif %}">{{ total if is_active else '—' }}</div>
      <div class="stat-label">Queries Today</div>
    </div>
    <div class="stat">
      <div class="stat-num {% if not is_active %}muted{% endif %}">{{ blocked if is_active else '—' }}</div>
      <div class="stat-label">Blocked Today</div>
    </div>
    <div class="stat">
      <div class="stat-num {% if not is_active %}muted{% endif %}">{{ (pct|string + '%') if is_active else '—' }}</div>
      <div class="stat-label">Block Rate</div>
    </div>
  </div>

  <!-- CUSTOMER INFO CARD -->
  {% if is_active %}
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Account Info</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">EMAIL</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ user_email }}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">PLAN</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{% if plan_badge %}{{ plan_badge }}{% else %}Remote{% endif %}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">STATUS</span>
        <span class="badge badge-on">ACTIVE</span>
      </div>
      {% if customer %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">JOINED</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{{ customer.date[:10] }}</span>
      </div>
      {% endif %}
      {% if is_founder %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">TIER</span>
        <span class="badge" style="background:#00e5c0;color:#0a0e0f;">FOUNDER</span>
      </div>
      {% endif %}
      {% if has_family %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">ADD-ONS</span>
        <span class="badge badge-family">FAMILY SAFE</span>
      </div>
      {% endif %}
    </div>
  </div>
  {% endif %}

  <!-- DOH ADDRESS -->
  <div class="card">
    <div class="card-label">Your Private DNS Address</div>
    {% if is_active %}
    <div class="doh-box" id="doh-address">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
    <button onclick="copyDoH()" style="margin-top:8px;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;cursor:pointer;" id="copy-btn">Copy Address</button>
    <script>
    function copyDoH(){
      var text = document.getElementById('doh-address').innerText;
      navigator.clipboard.writeText(text).then(function(){
        var btn = document.getElementById('copy-btn');
        btn.innerText = 'Copied!';
        setTimeout(function(){ btn.innerText = 'Copy Address'; }, 2000);
      });
    }
    </script>
    <div style="display:flex;gap:8px;flex-wrap:wrap;margin-top:12px;">
      <a href="https://harborprivacy.com/profiles/{{ client_id }}.mobileconfig" style="display:inline-block;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;text-decoration:none;">Download iOS Profile</a>
      <a href="https://harborprivacy.com/setup/android/{{ client_id }}" target="_blank" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;text-decoration:none;">Android Setup + QR</a>
    </div>
    <p class="note" style="margin-top:12px;">Use this address in your DNS over HTTPS settings. <a href="https://harborprivacy.com/docs" style="color:var(--accent);">Setup guide →</a></p>
    {% else %}
    <div class="doh-box locked">https://doh.harborprivacy.com/dns-query/••••••••••</div>
    <p class="note">Your personal DNS address will appear here once your subscription is active.</p>
    {% endif %}
  </div>

  <!-- UPGRADE CARD — monthly only -->
  {% if plan_badge == "MONTHLY" and is_active %}
  <div class="card" style="border-color:#1e3a35;background:rgba(0,229,192,0.03);margin-bottom:20px;">
    <div class="card-label" style="color:var(--accent);">Save More — Upgrade Your Plan</div>
    <div style="display:flex;flex-direction:column;gap:10px;margin-top:8px;">
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
        <div>
          <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">3 Months — Save 17%</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">$4.99/mo billed quarterly</div>
        </div>
        <a href="https://buy.stripe.com/7sYcN47or2HdbPLeph6kg0a?prefilled_email={{ user_email }}" target="_blank" style="background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;padding:6px 14px;text-decoration:none;white-space:nowrap;">Switch →</a>
      </div>
      <div style="border-top:1px solid var(--border);"></div>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
        <div>
          <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">6 Months — Save 30%</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">$4.16/mo billed every 6 months</div>
        </div>
        <a href="https://buy.stripe.com/00w9AS38b6XtdXTch96kg0b?prefilled_email={{ user_email }}" target="_blank" style="background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;padding:6px 14px;text-decoration:none;white-space:nowrap;">Switch →</a>
      </div>
      <div style="border-top:1px solid var(--border);"></div>
      <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;">
        <div>
          <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">Annual — Save 44%</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">$3.33/mo billed yearly</div>
        </div>
        <a href="https://buy.stripe.com/9B69AS6knepVbPL2Gz6kg09?prefilled_email={{ user_email }}" target="_blank" style="background:var(--accent);color:var(--bg);font-family:'DM Mono',monospace;font-size:11px;padding:6px 14px;text-decoration:none;white-space:nowrap;">Switch →</a>
      </div>
    </div>
  </div>
  {% endif %}

  <!-- ADD-ONS -->
  <div class="card">
    <div class="card-label">Add-Ons {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <div style="position:relative;">
      <div style="position:relative;">
      <div style="position:relative;">
      <div class="toggle-row">
        <div>
          <div class="toggle-label">
            Family Safe
            <span class="badge {% if family_safe %}badge-on{% else %}badge-off{% endif %}">{% if family_safe %}ON{% else %}OFF{% endif %}</span>
          </div>
          <div class="toggle-desc">SafeSearch enforcement, adult content blocking, NSFW filtering</div>
        </div>
        <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
          <input type="checkbox" {% if family_safe %}checked{% endif %} {% if not is_active or not has_family %}disabled{% else %}onchange="toggleAddon('family',this.checked)"{% endif %}>
          <span class="slider" style="border-radius:24px;"></span>
        </label>
      </div>
      {% if is_active and not has_family %}
      <div style="position:absolute;inset:0;background:rgba(10,14,15,0.82);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:space-between;padding:0 20px;border-radius:2px;">
        <div>
          <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:4px;">Add-On Available</div>
          <div style="font-size:14px;color:var(--text);">Family Safe &mdash; <span style="color:var(--accent);font-family:'DM Mono',monospace;">$0.59/mo</span></div>
          <div style="font-size:12px;color:var(--muted);margin-top:2px;">SafeSearch, adult content blocking, family filtering</div>
        </div>
        <a href="https://buy.stripe.com/28EbJ038bftZ5rn80T6kg0d" target="_blank" style="background:var(--accent);color:#1a2a2d;padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;font-weight:500;white-space:nowrap;flex-shrink:0;margin-left:16px;">Add On &rarr;</a>
      </div>
      {% endif %}
    </div>
      <div style="position:relative;">
      <div class="toggle-row">
        <div>
          <div class="toggle-label">
            Harbor Kids
            <span class="badge {% if harbor_kids %}badge-on{% else %}badge-off{% endif %}">{% if harbor_kids %}ON{% else %}OFF{% endif %}</span>
          </div>
          <div class="toggle-desc">DNS filtering for your child's devices — blocks adult content, malware, and ads</div>
        </div>
        <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
          <input type="checkbox" {% if harbor_kids %}checked{% endif %} disabled>
          <span class="slider" style="border-radius:24px;"></span>
        </label>
      </div>
      {% if is_active and not harbor_kids %}
      <div style="position:absolute;inset:0;background:rgba(10,14,15,0.82);backdrop-filter:blur(4px);-webkit-backdrop-filter:blur(4px);display:flex;align-items:center;justify-content:space-between;padding:0 20px;border-radius:2px;">
        <div>
          <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:4px;">Add-On Available</div>
          <div style="font-size:14px;color:var(--text);">Harbor Kids &mdash; <span style="color:var(--accent);font-family:'DM Mono',monospace;">$2.49/mo</span></div>
          <div style="font-size:12px;color:var(--muted);margin-top:2px;">Child device filtering, adult content blocking, parental DNS control</div>
        </div>
        <a href="https://buy.stripe.com/fZu4gyfUX0z55rneph6kg0f?prefilled_email={{ user_email }}" target="_blank" style="background:var(--accent);color:#1a2a2d;padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;font-weight:500;white-space:nowrap;flex-shrink:0;margin-left:16px;">Add On &rarr;</a>
      </div>
      {% endif %}
    </div>
  </div>

  <div class="card">
    <div class="card-label">Harbor Kids &#8212; Your Child Profiles</div>
    {% if harbor_kids and kids_profiles %}
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">Each child profile has its own DNS address. Use the setup guide to install it on your child's device.</p>
    {% for kp in kids_profiles %}
    <div style="border:1px solid var(--border);padding:16px;margin-bottom:12px;background:var(--bg);">
      <div style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);margin-bottom:10px;">{{ kp.name }}</div>
      <div style="background:var(--surface);border-left:3px solid var(--accent);padding:10px 14px;font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);word-break:break-all;margin-bottom:10px;">https://doh.harborprivacy.com/dns-query/{{ kp.name }}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="https://harborprivacy.com/profiles/{{ kp.name }}.mobileconfig" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#8659; iOS/Mac Profile</a>
        <a href="https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=https://doh.harborprivacy.com/dns-query/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
        <a href="https://harborprivacy.com/docs/harbor-kids#kids-setup" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">Windows Setup</a>
      </div>
    </div>
    {% endfor %}
    {% elif harbor_kids %}
    <p style="font-size:13px;color:var(--muted);">Your Harbor Kids profile is being set up. Check back shortly or contact support@harborprivacy.com.</p>
    {% else %}
    <p style="font-size:13px;color:var(--muted);">Add Harbor Kids from the Add-Ons section above to get started.</p>
    {% endif %}
    <div style="font-size:11px;color:var(--muted);margin-top:12px;">Harbor Kids accounts are managed by a parent or guardian. We do not collect personal information from children. <a href="https://harborprivacy.com/nologs" style="color:var(--accent);text-decoration:none;">Privacy Policy</a></div>
  </div>

  <!-- CUSTOM RULES -->
  <div class="card">
    <div class="card-label">Custom Rules {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    {% if is_active %}
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <input type="text" id="rule-domain" placeholder="example.com" style="margin:0;flex:1;min-width:140px;">
      <select id="rule-type" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;margin:0;width:auto;">
        <option value="block">Block</option>
        <option value="allow">Allow</option>
      </select>
      <button onclick="addRule()" class="btn">Add Rule</button>
    </div>
    {% for rule in rules %}
    <div class="row">
      <span class="{% if rule.startswith('@@') %}rule-allow{% else %}rule-block{% endif %}">{{ rule }}</span>
      <button onclick="removeRule('{{ rule }}')" class="btn btn-danger btn-sm">Remove</button>
    </div>
    {% else %}
    <p class="note">No custom rules yet. Add a domain above to block or allow it.</p>
    {% endfor %}
    {% else %}
    <p class="note" style="margin-bottom:16px;">Block or allow specific websites on your network. Unlocks with an active Harbor Remote subscription.</p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;opacity:0.4;pointer-events:none;">
      <input type="text" placeholder="example.com" style="margin:0;flex:1;min-width:140px;" disabled>
      <button class="btn btn-disabled">Add Rule</button>
    </div>
    {% endif %}
  </div>

  {% if is_active %}
  <div class="card">
    <div class="card-label">Quick Profiles {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    {% if is_active %}
    <p class="note" style="margin-bottom:20px;">Apply a preset profile to quickly block groups of services. Your custom settings are saved automatically. Current: {{ active_profile }}</p>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:10px;margin-bottom:16px;">
      <button onclick="applyProfile('kid')" class="profile-btn {% if active_profile == 'kid' %}profile-active{% endif %}" data-profile="kid">
        <div style="font-size:24px;margin-bottom:6px;">👧</div>
        <div style="font-weight:700;margin-bottom:4px;">Kid Mode</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, adult, gambling</div>
      </button>
      <button onclick="applyProfile('work')" class="profile-btn {% if active_profile == 'work' %}profile-active{% endif %}" data-profile="work">
        <div style="font-size:24px;margin-bottom:6px;">💼</div>
        <div style="font-weight:700;margin-bottom:4px;">Work Focus</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, streaming, gaming</div>
      </button>
      <button onclick="applyProfile('gaming')" class="profile-btn {% if active_profile == 'gaming' %}profile-active{% endif %}" data-profile="gaming">
        <div style="font-size:24px;margin-bottom:6px;">🎮</div>
        <div style="font-weight:700;margin-bottom:4px;">Gaming Mode</div>
        <div style="font-size:11px;opacity:0.7;">Blocks social, keeps gaming open</div>
      </button>
      <button onclick="applyProfile('custom')" class="profile-btn {% if active_profile == 'custom' or not active_profile %}profile-active{% endif %}" data-profile="custom">
        <div style="font-size:24px;margin-bottom:6px;">⚙️</div>
        <div style="font-weight:700;margin-bottom:4px;">Custom</div>
        <div style="font-size:11px;opacity:0.7;">Your saved settings</div>
      </button>
    </div>
    <button onclick="applyProfile('clear')" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);background:transparent;border:1px solid var(--border);padding:6px 14px;cursor:pointer;">Clear All Blocks</button>
    {% endif %}
  </div>

  <div class="card">
    <div class="card-label">Blocked Services {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <p class="note" style="margin-bottom:20px;">Block entire services on your network. Toggle on to block, off to allow.</p>
    {% for group_name, services in service_groups.items() %}
    <div style="margin-bottom:20px;">
      <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:10px;padding-bottom:8px;border-bottom:1px solid var(--border);">{{ group_name.replace("_"," ") }}</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;">
        {% for svc in services %}
        <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--bg);border:1px solid var(--border);">
          <span style="font-size:13px;color:var(--text);">{{ svc.name }}</span>
          <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
            <input type="checkbox" {% if svc.id in blocked_services %}checked{% endif %} onchange="toggleService('{{ svc.id }}',this.checked)">
            <span class="slider" style="border-radius:24px;"></span>
          </label>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}

  {% if is_active %}
  <div class="card">
    <div class="card-label">Support Access</div>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px;">If you need help, generate a temporary support code and share it with Harbor Privacy. The code expires in 30 minutes and gives access to your settings only while active.</p>
    <button onclick="genCode()" class="btn" style="margin-bottom:12px;">Generate Support Code</button>
    <div id="support-code-box" style="display:none;background:var(--bg);border-left:3px solid var(--accent);padding:16px;font-family:'DM Mono',monospace;font-size:24px;color:var(--accent);letter-spacing:0.3em;text-align:center;margin-bottom:8px;"></div>
    <p id="support-code-note" style="display:none;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Share this code with support. Expires in 30 minutes.</p>
  </div>
  {% endif %}

</div>
<script>
async function togglePause(pause){
  if(pause && !confirm('This will disable all ad blocking and filtering. Continue?')) return;
  const r=await fetch('/api/pause',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({paused:pause})});
  const d=await r.json();
  if(d.ok) location.reload(); else alert('Failed to update. Try again.');
}
async function applyProfile(profile){
  if(profile === 'clear' && !confirm('Remove all blocked services?')) return;
  const btns = document.querySelectorAll('.profile-btn');
  btns.forEach(b => b.classList.remove('profile-active'));
  const activeBtn = document.querySelector('[data-profile="'+profile+'"]');
  if(activeBtn) activeBtn.classList.add('profile-active');
  const r = await fetch('/api/profile',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({profile})});
  const d = await r.json();
  if(d.ok) location.reload();
  else alert('Error: ' + (d.error || 'Unknown error'));
}
async function toggleAddon(type,enabled){
  const r=await fetch('/api/addon'+location.search,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,enabled})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed to update. Please try again.');
}
async function toggleService(id, blocked){
  const r=await fetch('/api/service'+location.search,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service_id:id,blocked:blocked})});
  const d=await r.json();
  if(d.ok) window.location.href='/dashboard'+location.search;
}
async function genCode(){
  const r=await fetch('/api/support-code',{method:'POST'});
  const d=await r.json();
  if(d.code){
    document.getElementById('support-code-box').style.display='block';
    document.getElementById('support-code-box').innerText=d.code;
    document.getElementById('support-code-note').style.display='block';
  }
}
async function addRule(){
  const domain=document.getElementById('rule-domain').value.trim();
  const type=document.getElementById('rule-type').value;
  if(!domain)return;
  const r=await fetch('/api/rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({domain,block:type==='block'})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed to add rule.');
}
async function removeRule(rule){
  if(!confirm('Remove this rule?'))return;
  const r=await fetch('/api/rule',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({rule})});
  const d=await r.json();
  if(d.ok)location.reload();
}
</script>
</html>"""
    service_groups = get_all_blocked_services() if is_active else {}
    blocked_services = get_client_blocked_services(client_id) if is_active and client_id else []
    return render_template_string(html, name=name, client_id=client_id,
        is_active=is_active, total=total, blocked=blocked, pct=pct,
        rules=rules, family_safe=family_safe, has_family=has_family, harbor_kids=harbor_kids, kids_profiles=get_kids_profiles(client_id),
        active_profile=customer.get("active_profile", "custom") if customer else "custom",
        user_email=email, is_trial=is_trial, plan_badge=plan_badge, has_family_badge=has_family_badge,
        filtering_paused=filtering_paused,
        is_founder=is_founder, top_blocked=top_blocked, customer=customer,
        service_groups=service_groups, blocked_services=blocked_services, active="dashboard")

# ── ADMIN DASHBOARD ───────────────────────────────────────

@app.route("/admin")
@admin_required
def admin():
    allowed = get_allowed_clients()
    all_customers = load_customers()
    customers = [c for c in all_customers if c.get("client_id") in allowed]
    stats = get_stats()
    total_queries = stats.get("num_dns_queries", 0)
    total_blocked = stats.get("num_blocked_filtering", 0)
    block_pct = round(total_blocked / max(total_queries, 1) * 100, 1)

    html = STYLE + NAV_ADMIN + """
<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin Panel</p>
    <h1>Harbor Privacy.</h1>
  </div>

  <div class="stat-grid" style="margin-bottom:32px;">
    <div class="stat"><div class="stat-num">{{ customers|length }}</div><div class="stat-label">Active Customers</div></div>
    <div class="stat"><div class="stat-num">{{ total_queries }}</div><div class="stat-label">DNS Queries Today</div></div>
    <div class="stat"><div class="stat-num">{{ block_pct }}%</div><div class="stat-label">Network Block Rate</div></div>
  </div>

  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
    <a href="/admin/links" style="display:inline-block;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; Link Manager</a>
    <a href="/admin/analytics" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; DNS Analytics</a>
  </div>

  <div class="card">
    <div class="card-label">Active Customers</div>
    {% if customers %}
    <div class="customer-grid">
      <div class="customer-row customer-header" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:0.1em;">
        <span>CUSTOMER</span>
        <span>CLIENT ID</span>
        <span>PLAN</span>
        <span>FAMILY</span>
        <span>ACTIONS</span>
      </div>
      {% for c in customers %}
      {% set cl = get_client(c.client_id) %}
      <div class="customer-row">
        <div>
          <div style="font-size:14px;color:var(--text);">{{ c.name }}</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">{{ c.email }}</div>
        </div>
        <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ c.client_id }}</div>
        <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">{{ c.plan }}</div>
        <div><span class="badge {% if cl and cl.parental_enabled %}badge-on{% else %}badge-off{% endif %}">{% if cl and cl.parental_enabled %}ON{% else %}OFF{% endif %}</span></div>
        <div style="display:flex;gap:6px;align-items:center;">
          <a href="/admin/customer/{{ c.client_id }}" class="btn btn-sm" style="padding:4px 10px;font-size:10px;">View →</a>
          {% if c.client_id != "harbor7066" %}
          <button onclick="deleteCustomer('{{ c.client_id }}','{{ c.name }}')" class="btn btn-sm" style="background:rgba(255,107,107,0.12);color:#ff6b6b;border-color:rgba(255,107,107,0.3);">✕</button>
          {% endif %}
        </div>
      </div>
      {% endfor %}
    </div>
    {% else %}
    <p class="note">No active customers yet. Share your pricing page to get started.</p>
    {% endif %}
  </div>
</div>
</html>"""
    return render_template_string(html, customers=customers,
        total_queries=total_queries, block_pct=block_pct,
        get_client=get_client, active="admin")

@app.route("/admin/analytics")
@admin_required
def admin_analytics():
    import json as _json, time
    ANALYTICS_FILE = "/var/log/harbor-dns-analytics.json"
    try:
        records = _json.loads(open(ANALYTICS_FILE).read())
    except:
        records = []

    now = time.time()
    today = [r for r in records if r["ts"] > now - 86400]
    this_week = [r for r in records if r["ts"] > now - 604800]

    isp_counts = {}
    for r in this_week:
        isp = r.get("isp","Unknown")
        isp_counts[isp] = isp_counts.get(isp,0) + 1
    isp_sorted = sorted(isp_counts.items(), key=lambda x: x[1], reverse=True)[:10]

    protected_week = sum(1 for r in this_week if r.get("protected"))
    unprotected_week = len(this_week) - protected_week

    hourly = [0]*24
    for r in today:
        hourly[r.get("hour",0)] += 1

    daily_labels = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"]
    daily = [0]*7
    for r in this_week:
        daily[r.get("day",0)] += 1

    ref_counts = {}
    for r in this_week:
        ref = r.get("referrer","Direct") or "Direct"
        if "facebook" in ref.lower(): ref = "Facebook"
        elif "linkedin" in ref.lower(): ref = "LinkedIn"
        elif "google" in ref.lower(): ref = "Google"
        elif "harborprivacy" in ref.lower(): ref = "Harbor Privacy Site"
        else: ref = ref.split("/")[2] if ref.count("/") >= 2 else ref
        ref_counts[ref] = ref_counts.get(ref,0) + 1
    ref_sorted = sorted(ref_counts.items(), key=lambda x: x[1], reverse=True)[:8]

    html = STYLE + NAV_ADMIN + """<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin</p>
    <h1>DNS Checker Analytics</h1>
  </div>
  <div class="stat-grid" style="margin-bottom:20px;">
    <div class="stat"><div class="stat-num">""" + str(len(today)) + """</div><div class="stat-label">Checks Today</div></div>
    <div class="stat"><div class="stat-num">""" + str(len(this_week)) + """</div><div class="stat-label">This Week</div></div>
    <div class="stat"><div class="stat-num">""" + str(len(records)) + """</div><div class="stat-label">All Time</div></div>
  </div>
  <div class="stat-grid" style="margin-bottom:20px;">
    <div class="stat"><div class="stat-num" style="color:#ff4e4e;">""" + str(unprotected_week) + """</div><div class="stat-label">Unprotected</div></div>
    <div class="stat"><div class="stat-num">""" + str(protected_week) + """</div><div class="stat-label">Harbor Protected</div></div>
    <div class="stat"><div class="stat-num">""" + str(round(protected_week/max(len(this_week),1)*100)) + """%</div><div class="stat-label">Protection Rate</div></div>
  </div>
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">ISPs Detected This Week</div>
    """ + "".join([f'<div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);"><span style="color:{"var(--accent)" if "Harbor" in isp else "var(--text)"};">{isp}</span><span style="font-family:DM Mono,monospace;font-size:12px;color:var(--muted);">{count}</span></div>' for isp,count in isp_sorted]) + """
  </div>
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Traffic Sources This Week</div>
    """ + "".join([f'<div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);"><span>{ref}</span><span style="font-family:DM Mono,monospace;font-size:12px;color:var(--muted);">{count}</span></div>' for ref,count in ref_sorted]) + """
  </div>
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Checks by Hour Today</div>
    <div style="display:flex;align-items:flex-end;gap:3px;height:80px;margin-top:16px;">
      """ + "".join([f'<div style="flex:1;background:{"var(--accent)" if hourly[i]==max(hourly+[1]) else "var(--border)"};height:{max(int(hourly[i]/max(max(hourly),1)*80),2)}px;" title="{i}:00"></div>' for i in range(24)]) + """
    </div>
    <div style="display:flex;justify-content:space-between;font-family:DM Mono,monospace;font-size:9px;color:var(--muted);margin-top:4px;"><span>12am</span><span>6am</span><span>12pm</span><span>6pm</span><span>11pm</span></div>
  </div>
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Checks by Day This Week</div>
    <div style="display:flex;align-items:flex-end;gap:8px;height:80px;margin-top:16px;">
      """ + "".join([f'<div style="flex:1;display:flex;flex-direction:column;align-items:center;gap:4px;"><div style="width:100%;background:{"var(--accent)" if daily[i]==max(daily+[1]) else "var(--border)"};height:{max(int(daily[i]/max(max(daily),1)*60),2)}px;"></div><span style="font-family:DM Mono,monospace;font-size:9px;color:var(--muted);">{daily_labels[i]}</span></div>' for i in range(7)]) + """
    </div>
  </div>
  <a href="/admin" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;">← Back to Admin</a>
</div></html>"""
    return render_template_string(html, active="admin")

@app.route("/admin/links", methods=["GET"])
@admin_required
def admin_links():
    import json as _json
    LINKS_FILE = "/var/www/link/links.json"
    try:
        links = _json.loads(open(LINKS_FILE).read())
    except:
        links = []
    html = STYLE + NAV_ADMIN + """
<div class="wrap">
  <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:32px;flex-wrap:wrap;gap:16px;">
    <div>
      <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin</p>
      <h1>Link Manager</h1>
    </div>
    <a href="/admin" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;">← Back to Admin</a>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Add New Link</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <input type="text" id="new-label" placeholder="Label (e.g. See Plans)" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;">
      <input type="text" id="new-icon" placeholder="Icon (emoji or symbol)" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;">
      <input type="url" id="new-url" placeholder="https://..." style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;">
      <label style="display:flex;align-items:center;gap:8px;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">
        <input type="checkbox" id="new-featured"> Featured (teal highlight)
      </label>
      <button onclick="addLink()" class="btn">Add Link</button>
      <div id="add-status" style="font-family:'DM Mono',monospace;font-size:11px;"></div>
    </div>
  </div>

  <div class="card">
    <div class="card-label">Current Links</div>
    <div id="links-list">
      {% for i, link in links %}
      <div style="display:flex;justify-content:space-between;align-items:center;padding:12px 0;border-bottom:1px solid var(--border);gap:12px;" id="link-{{ i }}">
        <div style="flex:1;min-width:0;">
          <div style="font-size:14px;color:{% if link.featured %}var(--accent){% else %}var(--text){% endif %};">{{ link.icon }} {{ link.label }}</div>
          <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;">{{ link.url }}</div>
        </div>
        <div style="display:flex;gap:8px;flex-shrink:0;">
          <button onclick="moveLink({{ i }}, -1)" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 8px;cursor:pointer;font-size:12px;">↑</button>
          <button onclick="moveLink({{ i }}, 1)" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:4px 8px;cursor:pointer;font-size:12px;">↓</button>
          <button onclick="deleteLink({{ i }})" style="background:transparent;border:1px solid #ff4e4e;color:#ff4e4e;padding:4px 8px;cursor:pointer;font-family:'DM Mono',monospace;font-size:10px;">Remove</button>
        </div>
      </div>
      {% endfor %}
    </div>
  </div>

  <div style="margin-top:16px;">
    <a href="https://link.harborprivacy.com" target="_blank" class="btn" style="display:inline-block;text-decoration:none;">Preview Link Page →</a>
  </div>
</div>

<script>
async function addLink(){
  const label = document.getElementById('new-label').value.trim();
  const icon = document.getElementById('new-icon').value.trim();
  const url = document.getElementById('new-url').value.trim();
  const featured = document.getElementById('new-featured').checked;
  if(!label || !url){ document.getElementById('add-status').textContent='Label and URL required'; return; }
  const r = await fetch('/api/admin/links', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'add', label, icon, url, featured})});
  const d = await r.json();
  if(d.ok) location.reload();
  else document.getElementById('add-status').textContent = 'Error: ' + d.error;
}
async function deleteLink(i){
  if(!confirm('Remove this link?')) return;
  const r = await fetch('/api/admin/links', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'delete', index:i})});
  const d = await r.json();
  if(d.ok) location.reload();
}
async function moveLink(i, dir){
  const r = await fetch('/api/admin/links', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'move', index:i, dir:dir})});
  const d = await r.json();
  if(d.ok) location.reload();
}
</script>
</html>"""
    return render_template_string(html, links=enumerate(links), active="admin")

@app.route("/api/admin/links", methods=["POST"])
@admin_required
def api_admin_links():
    import json as _json
    LINKS_FILE = "/var/www/link/links.json"
    data = request.json
    action = data.get("action")
    try:
        links = _json.loads(open(LINKS_FILE).read())
    except:
        links = []
    if action == "add":
        links.append({"label": data.get("label",""), "icon": data.get("icon","→"), "url": data.get("url",""), "featured": data.get("featured", False)})
    elif action == "delete":
        idx = data.get("index", -1)
        if 0 <= idx < len(links):
            links.pop(idx)
    elif action == "move":
        idx = data.get("index", -1)
        direction = data.get("dir", 1)
        new_idx = idx + direction
        if 0 <= idx < len(links) and 0 <= new_idx < len(links):
            links[idx], links[new_idx] = links[new_idx], links[idx]
    _json.dump(links, open(LINKS_FILE, "w"), indent=2)
    resp = jsonify({"ok": True})
    return resp

@app.route("/admin/customer/<client_id>", methods=["GET", "POST"])
@admin_required
def admin_customer(client_id):
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return redirect("/admin")

    if request.method == "POST":
        action = request.form.get("action", "")
        if action == "update_email":
            old_email = request.form.get("old_email", "").strip()
            new_email = request.form.get("new_email", "").strip().lower()
            if old_email and new_email and old_email != new_email:
                updated = update_customer_email(old_email, new_email)
                log.info(f"Admin email update: {old_email} -> {new_email} success={updated}")
        elif action == "toggle_plan" and customer.get("email") == ADMIN_EMAIL:
            new_plan = request.form.get("plan_type", "remote")
            customers = load_customers()
            for c in customers:
                if c.get("client_id") == client_id:
                    c["plan_type"] = new_plan
                    c["plan"] = "remote"
                    break
            save_customers(customers)
            print(f"Admin plan toggle: {client_id} -> {new_plan}")
        return redirect(f"/admin/customer/{client_id}")

    client = get_client(client_id)
    rules = get_client_rules(client_id) if client_id else []
    family_safe = client.get("parental_enabled", False) if client else False
    filtering_paused = not client.get("filtering_enabled", True) if client else False
    has_family = has_family_addon(client_id) if client_id else False
    harbor_kids = customer.get("harbor_kids", False) if customer else False
    is_founder = customer.get("is_founder", False) if customer else False
    cstats = get_client_stats(client_id)

    html = STYLE + NAV_ADMIN + """
<div class="wrap" style="max-width:720px;">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;margin-bottom:8px;">CUSTOMER DETAIL</p>
    <h1>{{ customer.name }}</h1>
    <p class="note" style="margin-top:8px;">{{ customer.email }} &nbsp;&middot;&nbsp; {{ customer.plan }} &nbsp;&middot;&nbsp; ID: {{ client_id }}</p>
  </div>

  <div class="stat-grid" style="margin-bottom:20px;">
    <div class="stat"><div class="stat-num">{{ cstats.total }}</div><div class="stat-label">Queries Today</div></div>
    <div class="stat"><div class="stat-num">{{ cstats.blocked }}</div><div class="stat-label">Blocked Today</div></div>
    <div class="stat"><div class="stat-num">{{ cstats.pct }}%</div><div class="stat-label">Block Rate</div></div>
  </div>

  <div class="card">
    <div class="card-label">Customer Info</div>
    <div style="display:flex;flex-direction:column;gap:12px;">
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">EMAIL</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ customer.email }}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">PLAN</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{{ customer.plan }}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">STATUS</span>
        <span class="badge {% if customer.status == 'active' %}badge-on{% else %}badge-off{% endif %}">{{ customer.status|upper }}</span>
      </div>
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">JOINED</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">{{ customer.date[:10] }}</span>
      </div>
      {% if is_founder %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">TIER</span>
        <span class="badge" style="background:#00e5c0;color:#0a0e0f;">FOUNDER</span>
      </div>
      {% endif %}
    </div>

    {% if customer.email == "admin@harborprivacy.com" %}
    <div style="border-top:1px solid var(--border);margin:16px 0;"></div>
    <a href="https://dashboard.harborprivacy.com/dashboard?preview=1" target="_blank" class="btn" style="display:block;text-align:center;margin-bottom:16px;">Preview Customer Dashboard</a>
    <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:12px;">Test Plan Mode</div>
    <form method="POST" action="/admin/customer/{{ customer.client_id }}">
      <input type="hidden" name="action" value="toggle_plan">
      <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <select name="plan_type" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;font-family:'DM Mono',monospace;font-size:12px;flex:1;">
          <option value="remote" {% if customer.plan_type == "remote" %}selected{% endif %}>Harbor Remote</option>
          <option value="harbor-remote-light" {% if customer.plan_type == "harbor-remote-light" %}selected{% endif %}>Harbor Light</option>
          <option value="install" {% if customer.plan_type == "install" %}selected{% endif %}>On-Site Install</option>
          <option value="3month" {% if customer.plan_type == "3month" %}selected{% endif %}>Remote 3-Month</option>
          <option value="6month" {% if customer.plan_type == "6month" %}selected{% endif %}>Remote 6-Month</option>
          <option value="annual" {% if customer.plan_type == "annual" %}selected{% endif %}>Remote Annual</option>
        </select>
        <button type="submit" class="btn" style="padding:8px 16px;">Switch</button>
      </div>
      <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);margin-top:8px;">Current: {{ customer.plan_type }}</p>
    </form>
    {% endif %}

    <div style="border-top:1px solid var(--border);margin:16px 0;"></div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;">Update Email</div>
      <div style="display:flex;gap:8px;">
        <button onclick="resendWelcome('{{ customer.client_id }}')" class="btn btn-sm" style="background:transparent;border-color:var(--accent);color:var(--accent);">Resend Welcome</button>
        <button onclick="reprovision('{{ customer.client_id }}')" class="btn btn-sm btn-danger">Re-provision</button>
      </div>
    </div>
    <form method="POST" action="/admin/customer/{{ customer.client_id }}">
      <input type="hidden" name="action" value="update_email">
      <input type="hidden" name="old_email" value="{{ customer.email }}">
      <div style="display:flex;gap:8px;">
        <input type="email" name="new_email" placeholder="New email address" style="flex:1;margin:0;">
        <button type="submit" class="btn btn-sm">Update</button>
      </div>
    </form>
  </div>

  {% if not code_valid %}
  <div class="card">
    <div class="card-label">Support Access Required</div>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px;">Ask the customer to generate a support code from their dashboard, then enter it below to view and manage their settings.</p>
    <div style="display:flex;gap:12px;">
      <form method="GET" action="/admin/customer/{{ client_id }}" style="display:flex;gap:12px;flex:1;">
        <input type="text" name="code" placeholder="6-digit code" style="margin:0;flex:1;letter-spacing:0.2em;font-size:18px;" maxlength="6" inputmode="numeric" pattern="[0-9]*">
        <button type="submit" class="btn">Unlock</button>
      </form>
    </div>
    <p id="code-error" style="display:none;color:var(--danger);font-family:'DM Mono',monospace;font-size:11px;margin-top:8px;">Invalid or expired code.</p>
  </div>
  {% else %}
  <div class="card" style="border-color:var(--accent);">
    <div class="card-label" style="color:var(--accent);">Support Access Active</div>
    <p style="color:var(--muted);font-size:13px;margin-bottom:12px;">You have temporary access to this customer's settings. This session is logged.</p>
    <button onclick="revokeCode()" class="btn btn-danger btn-sm">End Access</button>
  </div>

  <div class="card">
    <div class="card-label">Add-Ons</div>
    <div class="toggle-row">
      <div>
        <div class="toggle-label">
          Family Safe
          {% if has_family %}
          <span class="badge {% if family_safe %}badge-on{% else %}badge-off{% endif %}">{% if family_safe %}ON{% else %}OFF{% endif %}</span>
          {% else %}
          <span class="badge badge-locked">NOT PURCHASED</span>
          {% endif %}
        </div>
        <div class="toggle-desc">Parental controls, SafeSearch, NSFW filtering</div>
      </div>
      <label class="toggle">
        <input type="checkbox" {% if family_safe %}checked{% endif %} {% if not has_family %}disabled{% else %}onchange="toggleFamily(this.checked)"{% endif %}>
        <span class="slider {% if not has_family %}locked{% endif %}"></span>
      </label>
    </div>
    <div class="toggle-row">
      <div>
        <div class="toggle-label">
          Harbor Kids
          {% if harbor_kids %}
          <span class="badge badge-on">ON</span>
          {% else %}
          <span class="badge badge-off">OFF</span>
          {% endif %}
        </div>
        <div class="toggle-desc">Child device DNS filtering, adult content blocking, parental control</div>
      </div>
      <label class="toggle">
        <input type="checkbox" {% if harbor_kids %}checked{% endif %} disabled>
        <span class="slider locked"></span>
      </label>
    </div>
  </div>

  <div class="card">
    <div class="card-label">Harbor Kids — Child Profiles</div>
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">Each child gets their own AdGuard client with Family Protection. Add profiles below — each gets a unique DoH address and setup links.</p>
    {% if kids_profiles %}
    {% for kp in kids_profiles %}
    <div style="border:1px solid var(--border);padding:16px;margin-bottom:12px;background:var(--bg);">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:10px;">
        <span style="font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);">{{ kp.name }}</span>
        <button onclick="removeKidProfile('{{ kp.name }}')" style="background:none;border:1px solid #ff4e4e;color:#ff4e4e;padding:4px 10px;font-family:'DM Mono',monospace;font-size:10px;cursor:pointer;">Remove</button>
      </div>
      <div style="background:var(--surface);border-left:3px solid var(--accent);padding:10px 14px;font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);word-break:break-all;margin-bottom:10px;">https://doh.harborprivacy.com/dns-query/{{ kp.name }}</div>
      <div style="display:flex;gap:8px;flex-wrap:wrap;">
        <a href="https://harborprivacy.com/profiles/{{ kp.name }}.mobileconfig" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#8659; iOS/Mac Profile</a>
        <a href="https://chart.googleapis.com/chart?chs=200x200&cht=qr&chl=https://doh.harborprivacy.com/dns-query/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
        <a href="https://harborprivacy.com/docs/harbor-kids#kids-setup" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">Windows Setup</a>
      </div>
    </div>
    {% endfor %}
    {% else %}
    <p style="font-size:13px;color:var(--muted);margin-bottom:16px;">No kid profiles yet. Add one below.</p>
    {% endif %}
    <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px;">
      <button onclick="addKidProfile()" style="background:var(--accent);color:#0a0e0f;border:none;padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;letter-spacing:0.08em;">+ Add Kid Profile</button>
      <span style="font-size:12px;color:var(--muted);">Will create {{ client_id }}-kid{{ (kids_profiles|length) + 1 }}</span>
    </div>
    <div style="font-size:11px;color:var(--muted);">Harbor Kids accounts are managed by a parent or guardian. We do not collect personal information from children. <a href="https://harborprivacy.com/nologs" style="color:var(--accent);text-decoration:none;">Privacy Policy →</a></div>
  </div>

    <div class="card-label">Blocked Services</div>
    {% for group_name, services in service_groups.items() %}
    <div style="margin-bottom:20px;">
      <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);letter-spacing:0.15em;text-transform:uppercase;margin-bottom:12px;">{{ group_name }}</div>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">
        {% for svc in services %}
        <div class="toggle-row" style="padding:8px 12px;background:var(--bg);border:1px solid var(--border);">
          <div style="font-size:13px;color:var(--text);">{{ svc.name }}</div>
          <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
            <input type="checkbox" {% if svc.id in blocked_services %}checked{% endif %} onchange="toggleService('{{ svc.id }}',this.checked)">
            <span class="slider" style="border-radius:24px;"></span>
          </label>
        </div>
        {% endfor %}
      </div>
    </div>
    {% endfor %}
  </div>

  <div class="card">
    <div class="card-label">Custom Rules</div>
    <div style="display:flex;gap:12px;margin-bottom:20px;flex-wrap:wrap;">
      <input type="text" id="rule-domain" placeholder="example.com" style="margin:0;flex:1;">
      <select id="rule-type" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;margin:0;width:auto;">
        <option value="block">Block</option>
        <option value="allow">Allow</option>
      </select>
      <button onclick="addRule()" class="btn">Add</button>
    </div>
    {% for rule in rules %}
    <div class="row">
      <span class="{% if rule.startswith('@@') %}rule-allow{% else %}rule-block{% endif %}">{{ rule }}</span>
      <button onclick="removeRule(this.dataset.rule)" data-rule="{{ rule | e }}" class="btn btn-danger btn-sm">Remove</button>
    </div>
    {% else %}
    <p class="note">No custom rules for this customer.</p>
    {% endfor %}
  </div>
  {% endif %}

</div>
<script>
const CID='{{ client_id }}';
function submitCode(){
  const code=document.getElementById('code-input').value.trim();
  if(!code)return;
  window.location.href='/admin/customer/'+CID+'?code='+code;
}
async function deleteCustomer(cid, name){
  if(!confirm('DELETE ' + name + '?\nThis will:\n- Cancel their Stripe subscription\n- Remove their DoH access\n- Delete their dashboard login\n\nThis cannot be undone.')) return;
  const btn = event.target;
  btn.textContent = 'Deleting...';
  btn.disabled = true;
  const r = await fetch('/api/admin/delete-customer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid})});
  const d = await r.json();
  if(d.ok){
    alert('Deleted ' + d.name + ' (' + d.email + ')');
    window.location.reload();
  } else {
    alert('Error: ' + d.error);
    btn.textContent = 'Delete';
    btn.disabled = false;
  }
}
async function resendWelcome(cid){
  const btn=event.target;btn.textContent='Sending...';btn.disabled=true;
  const r=await fetch('/api/admin/resend-welcome',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid})});
  const d=await r.json();
  btn.textContent=d.ok?'Sent!':'Error';
  setTimeout(()=>{btn.textContent='Resend Welcome';btn.disabled=false;},3000);
}
async function reprovision(cid){
  const newEmail=prompt('Enter correct email (blank to keep current):');
  if(newEmail===null)return;
  if(!confirm('This deletes the old DoH address and creates a new one. Customer must update devices. Continue?'))return;
  const btn=event.target;btn.textContent='Working...';btn.disabled=true;
  const r=await fetch('/api/admin/reprovision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid,new_email:newEmail})});
  const d=await r.json();
  if(d.ok){alert('Done! New ID: '+d.new_client_id+' Email: '+d.email);window.location.reload();}
  else{alert('Error: '+d.error);btn.textContent='Re-provision';btn.disabled=false;}
}
async function revokeCode(){
  await fetch('/api/admin/revoke-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID})});
  window.location.href='/admin/customer/'+CID;
}
async function addKidProfile(){
  const kids = document.querySelectorAll('[id^="kid-"]').length;
  const kid_num = (document.querySelectorAll('.kid-profile-row').length || 0) + 1;
  const r=await fetch('/api/admin/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID,type:'harbor_kids_add',kid_num:kid_num})});
  const d=await r.json();
  if(d.ok){alert('Kid profile '+d.kids_id+' created.');location.reload();}else{alert('Failed to create profile.');}
}
async function removeKidProfile(kids_id){
  if(!confirm('Remove '+kids_id+'? This will delete their DNS profile.'))return;
  const r=await fetch('/api/admin/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID,type:'harbor_kids_remove',kids_id:kids_id})});
  const d=await r.json();
  if(d.ok){location.reload();}else{alert('Failed to remove profile.');}
}
async function toggleFamily(enabled){
  const r=await fetch('/api/admin/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID,type:'family',enabled})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed.');
}
async function toggleService(id, blocked){
  const r=await fetch('/api/service',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({service_id:id,blocked:blocked})});
  const d=await r.json();
  // toggle updates silently
}
async function genCode(){
  const r=await fetch('/api/support-code',{method:'POST'});
  const d=await r.json();
  if(d.code){
    document.getElementById('support-code-box').style.display='block';
    document.getElementById('support-code-box').innerText=d.code;
    document.getElementById('support-code-note').style.display='block';
  }
}
async function addRule(){
  const domain=document.getElementById('rule-domain').value.trim();
  const type=document.getElementById('rule-type').value;
  if(!domain)return;
  const r=await fetch('/api/admin/rule',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID,domain,block:type==='block'})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed.');
}
async function removeRule(rule){
  if(!confirm('Remove?'))return;
  const r=await fetch('/api/admin/rule',{method:'DELETE',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID,rule})});
  const d=await r.json();
  if(d.ok)location.reload();
}
</script>
</html>"""
    service_groups = get_all_blocked_services()
    blocked_services = get_client_blocked_services(client_id)
    # Auto-grant access for internal/test accounts, require code for real customers
    customer_email = customer.get("email", "")
    code_valid = customer_email.endswith("@harborprivacy.com") or verify_support_code(client_id, request.args.get("code", ""))
    return render_template_string(html, customer=customer, client_id=client_id,
        rules=rules, family_safe=family_safe, harbor_kids=harbor_kids, kids_profiles=get_kids_profiles(client_id), cstats=cstats,
        service_groups=service_groups, blocked_services=blocked_services,
        code_valid=code_valid, active="admin")

# ── SETTINGS ──────────────────────────────────────────────

@app.route("/settings", methods=["GET"])
@login_required
def settings():
    email = request.user_email
    user = get_user(email)
    has_2fa = bool(user.get("totp_secret")) if user else False
    is_admin = request.is_admin
    msg = request.args.get("msg", "")
    msg_ok = request.args.get("ok", "0") == "1"

    NAV = NAV_ADMIN if is_admin else NAV_CUSTOMER

    html = STYLE + NAV + """
<div class="wrap" style="max-width:580px;">
  <h1 style="margin-bottom:32px;">Settings.</h1>

  {% if msg %}
  <div class="{{ 'success' if msg_ok else 'error' }}">{{ msg }}</div>
  {% endif %}

  <div class="card">
    <div class="card-label">Change Password</div>
    <form method="POST" action="/settings/password">
      <input type="password" name="current" placeholder="Current password" required>
      <input type="password" name="new_pw" placeholder="New password (min 8 characters)" required minlength="8">
      <input type="password" name="confirm" placeholder="Confirm new password" required>
      <button type="submit" class="btn">Update Password</button>
    </form>
  </div>

  <div class="card">
    <div class="card-label">Two-Factor Authentication</div>
    {% if not has_2fa %}
    <p class="note" style="margin-bottom:16px;">Add an extra layer of security. Works with Google Authenticator, Authy, or any TOTP app.</p>
    <a href="/settings/2fa/setup" class="btn">Set Up 2FA →</a>
    {% else %}
    <p style="color:var(--accent);font-family:'DM Mono',monospace;font-size:13px;margin-bottom:16px;">&#10003; Two-factor authentication is enabled.</p>
    <form method="POST" action="/settings/2fa/disable" style="display:flex;gap:12px;flex-wrap:wrap;">
      <input type="password" name="password" placeholder="Enter password to disable" required style="margin:0;flex:1;">
      <button type="submit" class="btn btn-danger">Disable 2FA</button>
    </form>
    {% endif %}
  </div>

  {% if not is_admin %}
  <div class="card">
    <div class="card-label">Weekly Stats Email</div>
    <p class="note" style="margin-bottom:16px;">Get a summary of your blocking stats every Monday morning. No browsing history — just your numbers.</p>
    <div class="toggle-row">
      <div>
        <div class="toggle-label">Weekly Email <span class="badge {% if weekly_email %}badge-on{% else %}badge-off{% endif %}">{% if weekly_email %}ON{% else %}OFF{% endif %}</span></div>
        <div class="toggle-desc">Sent every Monday at 8am</div>
      </div>
      <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
        <input type="checkbox" {% if weekly_email %}checked{% endif %} onchange="toggleWeeklyEmail(this.checked)">
        <span class="slider" style="border-radius:24px;"></span>
      </label>
    </div>
  </div>

  <div class="card">
    <div class="card-label">Your Data</div>
    <p class="note" style="margin-bottom:16px;">Request a report of everything Harbor Privacy holds about you. We'll email it within 24 hours.</p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;">
      <a href="/settings/data-request" class="btn btn-outline">Request My Data</a>
      <a href="https://billing.stripe.com/p/login/3cI28qfUX5Tp5rn80T6kg00" target="_blank" class="btn btn-outline">Manage Subscription</a>
    </div>
  </div>
  {% else %}
  <div class="card">
    <div class="card-label">Admin Account</div>
    <p class="note" style="margin-bottom:4px;">Logged in as Harbor Privacy administrator.</p>
    <p class="note" style="margin-bottom:16px;">{{ email }}</p>
    <a href="/admin" class="btn btn-outline">Back to Admin Panel</a>
  </div>
  {% endif %}

</div>
<script>
async function toggleWeeklyEmail(enabled){
  const r = await fetch('/api/weekly-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});
  const d = await r.json();
  if(!d.ok) alert('Error updating preference');
}
</script>
</html>"""
    user = get_user(request.user_email)
    weekly_email = user.get("weekly_email", False) if user else False
    return render_template_string(html, has_2fa=has_2fa, is_admin=is_admin, weekly_email=weekly_email,
        msg=msg, msg_ok=msg_ok, email=email, active="settings")

@app.route("/settings/password", methods=["POST"])
@login_required
def change_password():
    email = request.user_email
    user = get_user(email)
    current = request.form.get("current", "")
    new_pw = request.form.get("new_pw", "")
    confirm = request.form.get("confirm", "")

    if not bcrypt.checkpw(current.encode(), user["password"].encode()):
        return redirect("/settings?msg=Current+password+is+incorrect.&ok=0")
    if len(new_pw) < 8:
        return redirect("/settings?msg=Password+must+be+at+least+8+characters.&ok=0")
    if new_pw != confirm:
        return redirect("/settings?msg=Passwords+do+not+match.&ok=0")

    users = load_users()
    users[email]["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
    save_users(users)
    return redirect("/settings?msg=Password+updated+successfully.&ok=1")

@app.route("/settings/2fa/setup")
@login_required
def setup_2fa():
    email = request.user_email
    secret = pyotp.random_base32()
    uri = pyotp.TOTP(secret).provisioning_uri(email, issuer_name="Harbor Privacy")
    img = qrcode.make(uri)
    buf = BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    is_admin = request.is_admin
    NAV = NAV_ADMIN if is_admin else NAV_CUSTOMER

    html = STYLE + NAV + """
<div class="wrap" style="max-width:480px;">
  <h1 style="margin-bottom:8px;">Set up 2FA.</h1>
  <p class="note" style="margin-bottom:28px;">Scan this QR code with Google Authenticator or Authy, then confirm with the 6-digit code.</p>
  <div style="background:#fff;display:inline-block;padding:16px;margin-bottom:16px;border:1px solid var(--border);">
    <img src="data:image/png;base64,{{ qr }}" width="200" height="200">
  </div>
  <p style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);margin-bottom:8px;letter-spacing:0.1em;">CAN'T SCAN? ENTER THIS CODE MANUALLY:</p>
  <div style="background:var(--bg);border:1px solid var(--border);padding:12px 16px;font-family:'DM Mono',monospace;font-size:14px;color:var(--accent);letter-spacing:0.2em;word-break:break-all;margin-bottom:24px;">{{ secret }}</div>
  <form method="POST" action="/settings/2fa/enable">
    <input type="hidden" name="secret" value="{{ secret }}">
    <input type="text" name="code" placeholder="Enter 6-digit code to confirm" maxlength="6" required autofocus>
    <button type="submit" class="btn" style="width:100%;">Enable 2FA →</button>
  </form>
  <div style="margin-top:16px;"><a href="/settings" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">← Cancel</a></div>
</div>
</html>"""
    return render_template_string(html, qr=qr_b64, secret=secret, active="settings")

@app.route("/settings/2fa/enable", methods=["POST"])
@login_required
def enable_2fa():
    email = request.user_email
    secret = request.form.get("secret", "")
    code = request.form.get("code", "")
    if not pyotp.TOTP(secret).verify(code, valid_window=1):
        return redirect("/settings?msg=Invalid+code.+Please+try+again.&ok=0")
    users = load_users()
    users[email]["totp_secret"] = secret
    save_users(users)
    return redirect("/settings?msg=Two-factor+authentication+enabled.&ok=1")

@app.route("/settings/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    email = request.user_email
    user = get_user(email)
    password = request.form.get("password", "")
    if not bcrypt.checkpw(password.encode(), user["password"].encode()):
        return redirect("/settings?msg=Incorrect+password.&ok=0")
    users = load_users()
    users[email].pop("totp_secret", None)
    save_users(users)
    return redirect("/settings?msg=2FA+disabled.&ok=1")

@app.route("/settings/data-request")
@login_required
def data_request():
    email = request.user_email
    customer = find_customer(email)
    user = get_user(email)
    html_body = f"""<div style="font-family:sans-serif;max-width:600px;background:#0a0e0f;color:#e8f0ef;padding:32px;">
<h2 style="font-family:Georgia,serif;font-weight:400;color:#00e5c0;">Your Harbor Privacy Data Report</h2>
<p style="color:#6b8a87;font-size:13px;">Generated: {datetime.utcnow().isoformat()} UTC</p>
<hr style="border-color:#1e2a2d;margin:20px 0;">
<p><strong>Email:</strong> {email}</p>
<p><strong>Name:</strong> {customer.get('name','') if customer else 'N/A'}</p>
<p><strong>Client ID:</strong> {customer.get('client_id','') if customer else 'N/A'}</p>
<p><strong>Plan:</strong> {customer.get('plan','') if customer else 'N/A'}</p>
<p><strong>Account Created:</strong> {user.get('created','') if user else 'N/A'}</p>
<p><strong>Status:</strong> {'Active' if customer else 'No active subscription'}</p>
<hr style="border-color:#1e2a2d;margin:20px 0;">
<p><strong>DNS Query Logs:</strong> None retained.</p>
<p><strong>Browsing History:</strong> None retained.</p>
<p><strong>Payment Data:</strong> Handled by Stripe. Harbor Privacy does not store card details.</p>
<hr style="border-color:#1e2a2d;margin:20px 0;">
<p style="color:#6b8a87;font-size:13px;">Questions? Email support@harborprivacy.com</p>
</div>"""
    send_email(email, "Your Harbor Privacy Data Report", html_body)
    return redirect("/settings?msg=Your+data+report+has+been+sent+to+your+email.&ok=1")

# ── PASSWORD RESET ────────────────────────────────────────

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    email = request.args.get("email", "")
    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        user = get_user(email)
        if user:
            token = secrets.token_urlsafe(32)
            users = load_users()
            users[email]["reset_token"] = token
            users[email]["reset_exp"] = (datetime.utcnow() + timedelta(hours=1)).isoformat()
            save_users(users)
            reset_url = f"https://dashboard.harborprivacy.com/reset?token={token}"
            send_email(email, "Reset your Harbor Privacy password",
                f'<div style="font-family:sans-serif;background:#0a0e0f;color:#e8f0ef;padding:32px;"><h2 style="font-family:Georgia,serif;font-weight:400;">Password Reset</h2><p>Click below to reset your password. This link expires in 1 hour.</p><p><a href="{reset_url}" style="color:#00e5c0;">{reset_url}</a></p><p style="color:#6b8a87;font-size:13px;">If you did not request this, ignore this email.</p></div>')
        sent = True

    html = STYLE + """
<nav><a href="https://harborprivacy.com" class="logo">harbor<span>/</span>privacy</a></nav>
<div class="wrap-sm">
  <h1 style="margin-bottom:8px;">Forgot password?</h1>
  {% if sent %}
  <div class="success">If an account exists for that email, a reset link has been sent. Check your inbox.</div>
  <div style="margin-top:16px;"><a href="/login" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">← Back to login</a></div>
  {% else %}
  <p class="note" style="margin-bottom:28px;">Enter your email and we will send a reset link.</p>
  <form method="POST">
    <input type="email" name="email" placeholder="Your email address" value="{{ email }}" required autofocus>
    <button type="submit" class="btn" style="width:100%;">Send Reset Link →</button>
  </form>
  <div style="margin-top:16px;"><a href="/login" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">← Back to login</a></div>
  {% endif %}
</div>
</html>"""
    return render_template_string(html, sent=sent, email=email)

@app.route("/reset", methods=["GET", "POST"])
def reset():
    token = request.args.get("token") or request.form.get("token", "")
    error = None

    if request.method == "POST":
        new_pw = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        users = load_users()
        found = False
        for email, user in users.items():
            if user.get("reset_token") == token:
                found = True
                exp = datetime.fromisoformat(user.get("reset_exp", "2000-01-01"))
                if datetime.utcnow() > exp:
                    error = "This reset link has expired. Please request a new one."
                elif len(new_pw) < 8:
                    error = "Password must be at least 8 characters."
                elif new_pw != confirm:
                    error = "Passwords do not match."
                else:
                    users[email]["password"] = bcrypt.hashpw(new_pw.encode(), bcrypt.gensalt()).decode()
                    users[email].pop("reset_token", None)
                    users[email].pop("reset_exp", None)
                    users[email].pop("totp_secret", None)
                    save_users(users)
                    return redirect("/login")
                break
        if not found:
            error = "Invalid or expired reset link. Please request a new one."

    html = STYLE + """
<nav><a href="https://harborprivacy.com" class="logo">harbor<span>/</span>privacy</a></nav>
<div class="wrap-sm">
  <h1 style="margin-bottom:8px;">Set new password.</h1>
  {% if error %}<div class="error">{{ error }}</div>{% endif %}
  <form method="POST">
    <input type="hidden" name="token" value="{{ token }}">
    <input type="password" name="password" placeholder="New password (min 8 characters)" required minlength="8" autofocus>
    <input type="password" name="confirm" placeholder="Confirm new password" required>
    <button type="submit" class="btn" style="width:100%;">Set New Password →</button>
  </form>
</div>
</html>"""
    return render_template_string(html, token=token, error=error)

# ── API ───────────────────────────────────────────────────

@app.route("/api/weekly-email", methods=["POST"])
@login_required
def api_weekly_email():
    data = request.get_json()
    enabled = data.get("enabled", False)
    users = load_users()
    email = request.user_email
    if email in users:
        users[email]["weekly_email"] = enabled
        save_users(users)
        log.info(f"Weekly email {enabled} for {email}")
        return jsonify({"ok": True})
    return jsonify({"ok": False})

@app.route("/api/profile", methods=["POST"])
@login_required
def api_apply_profile():
    data = request.get_json()
    profile_name = data.get("profile", "")
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False, "error": "No active plan"})
    client_id = customer.get("client_id", "")

    if profile_name == "clear":
        set_client_blocked_services(client_id, [])
        save_active_profile(client_id, "clear")
        return jsonify({"ok": True})

    if profile_name == "custom":
        # Restore snapshot
        snapshot = customer.get("custom_services_snapshot", [])
        set_client_blocked_services(client_id, snapshot)
        save_active_profile(client_id, "custom")
        return jsonify({"ok": True})

    if profile_name not in PROFILES:
        return jsonify({"ok": False, "error": "Unknown profile"})

    print(f"DEBUG profile: client_id={client_id} profile={profile_name}")
    client_check = get_client(client_id)
    print(f"DEBUG get_client result: {client_check.get('name') if client_check else None}")
    # Save current as custom snapshot before switching
    current = get_client_blocked_services(client_id)
    if customer.get("active_profile", "custom") == "custom":
        save_profile_snapshot(client_id, current)

    # Apply profile
    services = PROFILES[profile_name]["services"]
    result = set_client_blocked_services(client_id, services)
    save_active_profile(client_id, profile_name)
    print(f"Profile {profile_name} applied for {client_id}")
    return jsonify({"ok": True, "profile": profile_name})

@app.route("/api/pause", methods=["POST"])
@login_required
def api_pause():
    if request.is_admin:
        return jsonify({"ok": False})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False})
    client_id = customer.get("client_id", "")
    client = get_client(client_id)
    if not client:
        return jsonify({"ok": False})
    paused = request.json.get("paused", False)
    updated = {**client, "filtering_enabled": not paused}
    return jsonify({"ok": agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": updated})})

@app.route("/api/support-code", methods=["POST"])
@login_required
def api_support_code():
    if request.is_admin:
        return jsonify({"ok": False})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False})
    code = generate_support_code(customer.get("client_id", ""))
    return jsonify({"ok": True, "code": code})

@app.route("/api/admin/revoke-code", methods=["POST"])
@admin_required
def api_admin_revoke_code():
    data = request.json
    revoke_support_code(data.get("client_id", ""))
    return jsonify({"ok": True})

@admin_required
def api_admin_revoke_code():
    data = request.json
    revoke_support_code(data.get("client_id", ""))
    return jsonify({"ok": True})

@app.route("/api/addon", methods=["POST"])
@login_required
def api_addon():
    if request.is_admin and not request.args.get("preview"):
        return jsonify({"ok": False, "error": "Use admin endpoint"})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False, "error": "No active subscription"})
    client_id = customer.get("client_id", "")
    data = request.json
    client = get_client(client_id)
    if not client:
        return jsonify({"ok": False})
    if data.get("type") == "family":
        enabled = data.get("enabled", False)
        updated = {**client, "parental_enabled": enabled, "safebrowsing_enabled": True, "use_global_settings": False, "safe_search": {"enabled": enabled, "bing": enabled, "duckduckgo": enabled, "ecosia": enabled, "google": enabled, "pixabay": enabled, "yandex": enabled, "youtube": enabled}}
        return jsonify({"ok": agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": updated})})

    if data.get("type") == "harbor_kids_add":
        kid_num = data.get("kid_num", 1)
        kids_id = f"{client_id}-kid{kid_num}"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        kid_data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        ok = agh_post("/control/clients/add", kid_data)
        if ok:
            update_customer_harbor_kids_flag(client_id, True)
        return jsonify({"ok": ok, "kids_id": kids_id})

    if data.get("type") == "harbor_kids_remove":
        kids_id = data.get("kids_id", "")
        ok = agh_post("/control/clients/delete", {"name": kids_id})
        remaining = get_kids_profiles(client_id)
        if not remaining:
            update_customer_harbor_kids_flag(client_id, False)
        return jsonify({"ok": ok})

    return jsonify({"ok": False})

@app.route("/api/admin/delete-customer", methods=["POST"])
@admin_required
def admin_delete_customer():
    data = request.get_json()
    protected = ["admin@harborprivacy.com", "tim@harborprivacy.com"]
    customers = load_customers()
    target = next((c for c in customers if c.get("client_id") == data.get("client_id")), None)
    if target and target.get("email") in protected:
        return jsonify({"ok": False, "error": "Cannot delete protected account"})
    data = request.get_json()
    client_id = data.get("client_id", "")
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return jsonify({"ok": False, "error": "Customer not found"})
    if client_id in ["harbor7066"]:
        return jsonify({"ok": False, "error": "Cannot delete owner account"})
    try:
        import sys, requests as _req
        sys.path.insert(0, "/home/ubuntu/harbor-backend")
        from webhook import wipe_customer, STRIPE_SECRET
        name = customer.get("name", "Customer")
        email = customer.get("email", "")
        stripe_id = customer.get("stripe_customer_id", "")

        # 1. Cancel Stripe subscription
        if stripe_id and STRIPE_SECRET:
            try:
                subs = _req.get(
                    f"https://api.stripe.com/v1/subscriptions",
                    params={"customer": stripe_id, "status": "active"},
                    auth=(STRIPE_SECRET, "")
                ).json()
                for sub in subs.get("data", []):
                    _req.delete(
                        f"https://api.stripe.com/v1/subscriptions/{sub['id']}",
                        auth=(STRIPE_SECRET, "")
                    )
                    log.info(f"Cancelled Stripe sub {sub['id']} for {client_id}")
            except Exception as e:
                log.error(f"Stripe cancel error: {e}")

        # 2. Full wipe — AdGuard, profile, customers.json, dashboard login
        wipe_customer(client_id)
        log.info(f"Admin deleted customer {client_id} {email}")
        return jsonify({"ok": True, "name": name, "email": email})
    except Exception as e:
        log.error(f"Delete customer error: {e}")
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/admin/resend-welcome", methods=["POST"])
@admin_required
def admin_resend_welcome():
    data = request.get_json()
    client_id = data.get("client_id", "")
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return jsonify({"ok": False, "error": "Customer not found"})
    try:
        import sys
        sys.path.insert(0, "/home/ubuntu/harbor-backend")
        from webhook import send_welcome_email
        email = customer.get("email", "")
        name = customer.get("name", "Customer")
        plan = customer.get("plan", "remote")
        profile_url = f"https://harborprivacy.com/profiles/{client_id}.mobileconfig"
        send_welcome_email(email, name, client_id, plan, profile_url)
        log.info(f"Admin resent welcome to {email} for {client_id}")
        return jsonify({"ok": True})
    except Exception as e:
        log.error(f"Resend welcome error: {e}")
        return jsonify({"ok": False, "error": str(e)})

@app.route("/api/admin/reprovision", methods=["POST"])
@admin_required
def admin_reprovision():
    data = request.get_json()
    client_id = data.get("client_id", "")
    new_email = data.get("new_email", "").strip().lower()
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return jsonify({"ok": False, "error": "Customer not found"})
    try:
        import sys, json as _json
        sys.path.insert(0, "/home/ubuntu/harbor-backend")
        from webhook import (wipe_customer, generate_client_id, create_adguard_client,
                             add_to_allowed_clients, save_ios_profile, send_welcome_email, log_customer)
        name = customer.get("name", "Customer")
        plan = customer.get("plan", "remote")
        stripe_id = customer.get("stripe_customer_id", "")
        old_email = customer.get("email", "")
        email = new_email if new_email else old_email
        wipe_customer(client_id)
        log.info(f"Reprovision: wiped {client_id}")
        new_client_id = generate_client_id(name, email)
        create_adguard_client(new_client_id, name)
        add_to_allowed_clients(new_client_id)
        profile_url = save_ios_profile(new_client_id, name)
        lines = []
        with open("/var/log/harbor-customers.json") as f2:
            for line in f2:
                line = line.strip()
                if not line: continue
                try:
                    r = _json.loads(line)
                    if r.get("client_id") != client_id:
                        lines.append(_json.dumps(r))
                except:
                    lines.append(line)
        with open("/var/log/harbor-customers.json", "w") as f2:
            f2.write("\n".join(lines) + "\n")
        log_customer(new_client_id, name, email, plan, stripe_id)
        send_welcome_email(email, name, new_client_id, plan, profile_url)
        log.info(f"Reprovision complete: {old_email} -> {email} old={client_id} new={new_client_id}")
        return jsonify({"ok": True, "new_client_id": new_client_id, "email": email})
    except Exception as e:
        log.error(f"Reprovision error: {e}")
        return jsonify({"ok": False, "error": str(e)})


def get_kids_profiles(client_id):
    try:
        import requests as req
        AGH = os.environ.get("ADGUARD_URL","http://127.0.0.1:8080")
        USER = os.environ.get("ADGUARD_USER","admin")
        PASS = os.environ.get("ADGUARD_PASS","")
        r = req.get(f"{AGH}/control/clients", auth=(USER,PASS), timeout=10)
        clients = r.json().get("clients",[])
        return [c for c in clients if c.get("name","").startswith(f"{client_id}-kid")]
    except:
        return []

def update_customer_harbor_kids_flag(client_id, enabled):
    try:
        lines = open(CUSTOMERS_LOG).readlines()
        new_lines = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            r = json.loads(line)
            if r.get("client_id","") == client_id:
                r["harbor_kids"] = enabled
            new_lines.append(json.dumps(r))
        open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
    except Exception as e:
        log.error(f"update_customer_harbor_kids_flag error: {e}")

@app.route("/api/admin/addon", methods=["POST"])
@admin_required
def api_admin_addon():
    data = request.json
    client_id = data.get("client_id", "")
    client = get_client(client_id)
    if not client:
        return jsonify({"ok": False})
    if data.get("type") == "family":
        enabled = data.get("enabled", False)
        updated = {**client, "parental_enabled": enabled, "safebrowsing_enabled": True, "use_global_settings": False, "safe_search": {"enabled": enabled, "bing": enabled, "duckduckgo": enabled, "ecosia": enabled, "google": enabled, "pixabay": enabled, "yandex": enabled, "youtube": enabled}}
        return jsonify({"ok": agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": updated})})

    if data.get("type") == "harbor_kids_add":
        kid_num = data.get("kid_num", 1)
        kids_id = f"{client_id}-kid{kid_num}"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        kid_data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        ok = agh_post("/control/clients/add", kid_data)
        if ok:
            update_customer_harbor_kids_flag(client_id, True)
        return jsonify({"ok": ok, "kids_id": kids_id})

    if data.get("type") == "harbor_kids_remove":
        kids_id = data.get("kids_id", "")
        ok = agh_post("/control/clients/delete", {"name": kids_id})
        remaining = get_kids_profiles(client_id)
        if not remaining:
            update_customer_harbor_kids_flag(client_id, False)
        return jsonify({"ok": ok})

    return jsonify({"ok": False})

@app.route("/api/service", methods=["POST"])
@login_required
def api_service():
    if request.is_admin and not request.args.get("preview"):
        return jsonify({"ok": False})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False})
    client_id = customer.get("client_id", "")
    data = request.json
    service_id = data.get("service_id", "")
    blocked = data.get("blocked", True)
    current = get_client_blocked_services(client_id)
    if blocked and service_id not in current:
        current.append(service_id)
    elif not blocked and service_id in current:
        current.remove(service_id)
    result = set_client_blocked_services(client_id, current)
    if result:
        # Switch to custom profile when user manually toggles a service
        save_active_profile(client_id, "custom")
    return jsonify({"ok": result})

@app.route("/api/rule", methods=["POST", "DELETE"])
@login_required
def api_rule():
    if request.is_admin:
        return jsonify({"ok": False})
    customer = find_customer(request.user_email)
    if not customer:
        return jsonify({"ok": False})
    client_id = customer.get("client_id", "")
    data = request.json
    if request.method == "POST":
        domain = data.get("domain", "").strip().lower()
        return jsonify({"ok": add_custom_rule(client_id, domain, data.get("block", True))})
    return jsonify({"ok": remove_custom_rule(client_id, data.get("rule", ""))})

@app.route("/api/admin/service", methods=["POST"])
@admin_required
def api_admin_service():
    data = request.json
    client_id = data.get("client_id", "")
    service_id = data.get("service_id", "")
    blocked = data.get("blocked", True)
    current = get_client_blocked_services(client_id)
    if blocked and service_id not in current:
        current.append(service_id)
    elif not blocked and service_id in current:
        current.remove(service_id)
    return jsonify({"ok": set_client_blocked_services(client_id, current)})

@app.route("/api/admin/rule", methods=["POST", "DELETE"])
@admin_required
def api_admin_rule():
    data = request.json
    client_id = data.get("client_id", "")
    if request.method == "POST":
        return jsonify({"ok": add_custom_rule(client_id, data.get("domain","").strip().lower(), data.get("block", True))})
    return jsonify({"ok": remove_custom_rule(client_id, data.get("rule", ""))})

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DASHBOARD_PORT", 7000)), debug=False)
