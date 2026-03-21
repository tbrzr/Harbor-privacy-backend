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
from flask import Flask, request, jsonify, render_template_string, redirect, make_response

app = Flask(__name__)

SECRET_KEY = os.environ.get("DASHBOARD_SECRET", "change-me")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "Harbor2026!")
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
SUPPORT_CODES = {}  # {client_id: {code, expires, attempts}}

def generate_support_code(client_id):
    code = str(secrets.randbelow(900000) + 100000)
    SUPPORT_CODES[client_id] = {"code": code, "expires": _time.time() + 1800}
    return code

def verify_support_code(client_id, code):
    entry = SUPPORT_CODES.get(client_id)
    if not entry:
        return False
    if _time.time() > entry["expires"]:
        del SUPPORT_CODES[client_id]
        return False
    if entry.get("attempts", 0) >= 5:
        del SUPPORT_CODES[client_id]
        return False
    if entry["code"] == str(code):
        return True
    entry["attempts"] = entry.get("attempts", 0) + 1
    return False

def revoke_support_code(client_id):
    SUPPORT_CODES.pop(client_id, None)

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
    """Pull per-client stats from query log"""
    try:
        log = agh_get(f"/control/querylog?limit=1000&search={client_id}")
        entries = log.get("data", [])
        total = len(entries)
        blocked = sum(1 for e in entries if e.get("reason", "") in 
                     ["FilteredBlackList", "FilteredBlockedService", "FilteredParental", "FilteredSafeBrowsing"])
        pct = round(blocked / max(total, 1) * 100, 1)
        # Top blocked domains
        blocked_domains = {}
        for e in entries:
            if e.get("reason", "") in ["FilteredBlackList", "FilteredBlockedService", "FilteredParental", "FilteredSafeBrowsing"]:
                domain = e.get("question", {}).get("name", "").rstrip(".")
                blocked_domains[domain] = blocked_domains.get(domain, 0) + 1
        top_blocked = sorted(blocked_domains.items(), key=lambda x: x[1], reverse=True)[:5]
        top_blocked = [{"name": k, "count": v} for k, v in top_blocked]
        return {"total": total, "blocked": blocked, "pct": pct, "top_blocked": top_blocked}
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

def set_client_blocked_services(client_id, services):
    client = get_client(client_id)
    if not client:
        return False
    updated = {**client, "blocked_services": services, "use_global_blocked_services": False}
    return agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": updated})

def add_custom_rule(client_id, domain, block=True):
    prefix = "||" if block else "@@||"
    rule = f"{prefix}{domain}^"
    client = get_client(client_id)
    if not client:
        return False
    rules = client.get("filtering_rules", [])
    if rule not in rules:
        rules.append(rule)
    return agh_post("/control/clients/update", {"name": client.get("name", client_id), "data": {**client, "filtering_rules": rules}})

def remove_custom_rule(client_id, rule):
    client = get_client(client_id)
    if not client:
        return False
    rules = [r for r in client.get("filtering_rules", []) if r != rule]
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
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
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
  .badge-locked{background:var(--border);color:var(--muted);}
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
    <a href="/dashboard" class="{{ 'active' if active == 'dashboard' else '' }}">Dashboard</a>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    <a href="/logout">Sign Out</a>
  </div>
</nav>"""

NAV_ADMIN = """
<div id="timeout-warning" style="display:none;position:fixed;bottom:24px;right:24px;background:#111618;border:1px solid #00e5c0;padding:20px 24px;z-index:9999;font-family:monospace;font-size:12px;color:#e8f0ef;flex-direction:column;gap:12px;max-width:300px;"><span>You will be logged out in 5 minutes due to inactivity.</span><button onclick="resetTimer()" style="background:#00e5c0;color:#0a0e0f;border:none;padding:8px 16px;cursor:pointer;font-family:monospace;font-size:11px;">Stay Logged In</button></div>
<nav>
  <a href="/admin" class="logo">harbor<span>/</span>privacy</a>
  <div class="nav-links">
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
            # Step 2: verify password
            password = request.form.get("password", "")
            totp_code = request.form.get("totp", "").strip()
            user = get_user(email)

            if not user:
                error = "Session expired. Please start over."
                step = "1"
                email = ""
            elif not bcrypt.checkpw(password.encode(), user["password"].encode()):
                error = "Incorrect password."
                step = "2"
                show_2fa = bool(user.get("totp_secret"))
            else:
                if user.get("totp_secret"):
                    if not totp_code:
                        show_2fa = True
                        step = "2"
                    elif not pyotp.TOTP(user["totp_secret"]).verify(totp_code, valid_window=1):
                        error = "Invalid 2FA code."
                        show_2fa = True
                        step = "2"
                    else:
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
    <input type="password" name="password" placeholder="Your password" required autocomplete="current-password" autofocus>
    {% if show_2fa %}
    <input type="text" name="totp" placeholder="6-digit authenticator code" maxlength="6" autocomplete="one-time-code">
    {% endif %}
    <button type="submit" class="btn" style="width:100%;margin-top:4px;">Sign In →</button>
  </form>
  <div style="margin-top:16px;">
    <a href="/forgot?email={{ email }}" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Forgot password?</a>
  </div>
  {% endif %}
</div>"""
    return render_template_string(html, step=step, email=email, error=error, show_2fa=show_2fa)

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
            resp = make_response(redirect("/admin" if is_admin else "/dashboard"))
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

@app.route("/logout")
def logout():
    resp = make_response(redirect("/login"))
    resp.delete_cookie("hp_token")
    return resp

# ── CUSTOMER DASHBOARD ────────────────────────────────────

@app.route("/dashboard")
@login_required
def dashboard():
    if request.is_admin:
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

    rules = client.get("filtering_rules", []) if client else []
    family_safe = client.get("parental_enabled", False) if client else False
    has_family = has_family_addon(client_id) if client_id else False
    is_founder = customer.get("is_founder", False) if customer else False

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

  <!-- DOH ADDRESS -->
  <div class="card">
    <div class="card-label">Your Private DNS Address</div>
    {% if is_active %}
    <div class="doh-box">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
    <p class="note">Use this address in your DNS over HTTPS settings. <a href="https://harborprivacy.com/docs" style="color:var(--accent);">Setup guide →</a></p>
    {% else %}
    <div class="doh-box locked">https://doh.harborprivacy.com/dns-query/••••••••••</div>
    <p class="note">Your personal DNS address will appear here once your subscription is active.</p>
    {% endif %}
  </div>

  <!-- ADD-ONS -->
  <div class="card">
    <div class="card-label">Add-Ons {% if not is_active %}<span class="badge badge-locked">LOCKED</span>{% endif %}</div>
    <div style="position:relative;">
      <div class="toggle-row">
        <div>
          <div class="toggle-label">
            Family Safe
            <span class="badge {% if family_safe %}badge-on{% else %}badge-off{% endif %}">{% if family_safe %}ON{% else %}OFF{% endif %}</span>
          </div>
          <div class="toggle-desc">SafeSearch enforcement, adult content blocking, family-friendly filtering</div>
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

  {% if is_active and top_blocked %}
  <div class="card">
    <div class="card-label">Top Blocked Today</div>
    {% for d in top_blocked %}
    <div class="row">
      <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--muted);">{{ d.name }}</span>
      <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--accent);">{{ d.count }}</span>
    </div>
    {% endfor %}
  </div>
  {% endif %}

</div>
<script>
async function toggleAddon(type,enabled){
  const r=await fetch('/api/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type,enabled})});
  const d=await r.json();
  if(d.ok)location.reload();else alert('Failed to update. Please try again.');
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
        rules=rules, family_safe=family_safe, has_family=has_family,
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
        <div><a href="/admin/customer/{{ c.client_id }}" class="btn btn-sm">View →</a></div>
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

@app.route("/admin/customer/<client_id>")
@admin_required
def admin_customer(client_id):
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return redirect("/admin")

    client = get_client(client_id)
    rules = client.get("filtering_rules", []) if client else []
    family_safe = client.get("parental_enabled", False) if client else False
    has_family = has_family_addon(client_id) if client_id else False
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

  {% if not code_valid %}
  <div class="card">
    <div class="card-label">Support Access Required</div>
    <p style="color:var(--muted);font-size:13px;margin-bottom:16px;">Ask the customer to generate a support code from their dashboard, then enter it below to view and manage their settings.</p>
    <div style="display:flex;gap:12px;">
      <input type="text" id="code-input" placeholder="6-digit code" style="margin:0;flex:1;letter-spacing:0.2em;font-size:18px;" maxlength="6">
      <button onclick="submitCode()" class="btn">Unlock</button>
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
        <div class="toggle-label">Family Safe <span class="badge {% if family_safe %}badge-on{% else %}badge-off{% endif %}">{% if family_safe %}ON{% else %}OFF{% endif %}</span></div>
        <div class="toggle-desc">Parental controls, SafeSearch, Hagezi NSFW blocklist</div>
      </div>
      <label class="toggle">
        <input type="checkbox" {% if family_safe %}checked{% endif %} onchange="toggleFamily(this.checked)">
        <span class="slider"></span>
      </label>
    </div>
  </div>

  <div class="card">
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

  <div class="card">
    <div class="card-label">DoH Address</div>
    <div class="doh-box">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
  </div>
</div>
<script>
const CID='{{ client_id }}';
function submitCode(){
  const code=document.getElementById('code-input').value.trim();
  if(!code)return;
  window.location.href='/admin/customer/'+CID+'?code='+code;
}
async function revokeCode(){
  await fetch('/api/admin/revoke-code',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:CID})});
  window.location.href='/admin/customer/'+CID;
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
    code_valid = True  # Admin always has full access
    return render_template_string(html, customer=customer, client_id=client_id,
        rules=rules, family_safe=family_safe, cstats=cstats,
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
</html>"""
    return render_template_string(html, has_2fa=has_2fa, is_admin=is_admin,
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
  <div style="background:#fff;display:inline-block;padding:16px;margin-bottom:24px;border:1px solid var(--border);">
    <img src="data:image/png;base64,{{ qr }}" width="200" height="200">
  </div>
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
    if request.is_admin:
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
    return jsonify({"ok": False})

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
    return jsonify({"ok": False})

@app.route("/api/service", methods=["POST"])
@login_required
def api_service():
    if request.is_admin:
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
    return jsonify({"ok": set_client_blocked_services(client_id, current)})

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
