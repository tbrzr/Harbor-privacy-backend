# ════════════════════════════════════════════════════════════
#  HARBOR PRIVACY DASHBOARD -- dashboard.py
# ════════════════════════════════════════════════════════════
#  Single-file Flask app on port 7000 (dashboard.harborprivacy.com)
#
#  ─── TABLE OF CONTENTS ─────────────────────────────────────
#   01  CONFIG & APP INIT          (~ll 40-70)
#   02  CSRF GUARD                 (~ll 60-115)
#   03  SIGNUP STATS / TURNSTILE   (~ll 115-150)
#   04  DATA: users / customers    (~ll 150-240)
#   05  SUPPORT CODES / RATE LIMIT (~ll 240-330)
#   06  ADGUARD (AGH) HELPERS      (~ll 330-560)
#   07  AUTH (token + decorators)  (~ll 560-600)
#   08  EMAIL / FAILURE LOG        (~ll 600-640)
#   09  SHARED STYLE + NAV         (~ll 640-820)
#   10  ROUTES: AUTH               (~ll 820-1120)
#   11  ROUTES: CUSTOMER DASHBOARD (~ll 1120-1640)
#   12  ROUTES: ADMIN              (~ll 1640-2410)
#   13  ROUTES: SETTINGS           (~ll 2410-2640)
#   14  ROUTES: PASSWORD RESET     (~ll 2640-2730)
#   15  ROUTES: API (customer)     (~ll 2730-3160)
#   16  ROUTES: API (admin)        (~ll 3160-3220)
#   17  ROUTES: ADMIN LOGS         (~ll 3220-3260)
#   18  ROUTES: SOCIAL             (~ll 3260-3500)
#   19  ROUTES: TRIAL /begin       (~ll 3500-3590)
#   20  ROUTES: SOCIAL AUTOPOST    (~ll 3590-4340)
#   21  ROUTES: START MAGIC        (~ll 4340-4410)
#   22  HEALTH                     (~ll 4410+)
#
#  ─── HARD RULES ─────────────────────────────────────────────
#   * plan_type MUST be defined BEFORE harbor_kids in both
#     admin_customer() and main customer dashboard() route.
#   * Do not modify lines near 920 / 1747 without reading those
#     sections fully.
#   * Section banners below mark logical owners. Helpers belong
#     in their section; routes should not import from sibling
#     route sections.
#   * Pre-restart: ~/check-dashboard.sh
# ════════════════════════════════════════════════════════════

#!/usr/bin/env python3
"""
Harbor Privacy Customer Dashboard
dashboard.harborprivacy.com
"""

import os, json, secrets, logging
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
log = logging.getLogger(__name__)

@app.after_request
def add_no_cache(response):
    if request.path == '/dashboard':
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response
app.secret_key = os.environ["FLASK_SECRET"]
from werkzeug.middleware.proxy_fix import ProxyFix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True

# ── CSRF GUARD ────────────────────────────────────────────
# Require X-CSRF header (or csrf field) on POST/PUT/DELETE for session-auth
# endpoints. Exempt public flows that have their own protection.
CSRF_EXEMPT_PREFIXES = (
    "/begin",                # Turnstile + rate limit
    "/login", "/forgot", "/reset", "/setup",  # Turnstile / token in URL
    "/api/start-",           # has own magic token
    "/api/start-magic", "/api/start-verify",
    "/api/home-status",      # HOME_STATUS_TOKEN
    "/api/home-beacon",      # public script
    "/api/windows/",         # own code flow
    "/api/dns-analytics",    # public ingest, rate-limited
    "/api/social/autopost",  # X-Autopost-Secret
    "/api/agh-status",       # GET
)

@app.before_request
def _csrf_guard():
    if request.method not in ("POST", "PUT", "DELETE", "PATCH"):
        return
    p = request.path or ""
    for pref in CSRF_EXEMPT_PREFIXES:
        if p == pref or p.startswith(pref):
            return
    expected = session.get("csrf")
    if not expected:
        # Logged-out POST to a guarded route — let the route's own auth reject it
        return
    sent = request.headers.get("X-CSRF") or ""
    if not sent and request.form:
        sent = request.form.get("csrf", "")
    if not sent and request.is_json:
        try:
            sent = (request.get_json(silent=True) or {}).get("csrf", "")
        except Exception:
            sent = ""
    if not sent or not secrets.compare_digest(str(sent), str(expected)):
        log.warning(f"CSRF rejected path={p} ua={request.headers.get('User-Agent','')[:80]} sent_len={len(sent)} exp_len={len(expected)} xcsrf={request.headers.get('X-CSRF','<none>')[:12]!r} sess_csrf={(expected or '')[:12]!r}")
        return jsonify({"error": "csrf"}), 403

@app.context_processor
def _inject_csrf():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return {"csrf_token": tok}

SECRET_KEY = os.environ.get("DASHBOARD_SECRET", "change-me")
ADGUARD_URL = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS = os.environ.get("ADGUARD_PASS", "")
CUSTOMERS_LOG = os.environ.get("CUSTOMERS_LOG", "/var/log/harbor-customers.json")
USERS_DB = os.environ.get("USERS_DB", "/var/log/harbor-dashboard-users.json")
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
ADMIN_EMAIL = "admin@harborprivacy.com"
HOME_STATUS_TOKEN = os.environ.get("HOME_STATUS_TOKEN", "")
HOME_STATUS_FILE  = "/home/ubuntu/harbor-home-status.json"
TURNSTILE_SECRET  = os.environ.get("TURNSTILE_SECRET_KEY", "")
SIGNUP_STATS_FILE = "/home/ubuntu/harbor-backend/signup-stats.json"

def _load_signup_stats():
    try:
        with open(SIGNUP_STATS_FILE) as f:
            return json.load(f)
    except Exception:
        return {"bots_blocked": 0}

def _inc_bots_blocked():
    stats = _load_signup_stats()
    stats["bots_blocked"] = stats.get("bots_blocked", 0) + 1
    try:
        with open(SIGNUP_STATS_FILE, "w") as f:
            json.dump(stats, f)
    except Exception:
        pass

def _verify_turnstile(token, ip):
    if not TURNSTILE_SECRET:
        return True
    if not token:
        return False
    try:
        import urllib.request as _ur, urllib.parse as _up, json as _jj
        data = _up.urlencode({"secret": TURNSTILE_SECRET, "response": token, "remoteip": ip}).encode()
        req = _ur.Request("https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data, method="POST")
        with _ur.urlopen(req, timeout=5) as resp:
            return _jj.loads(resp.read()).get("success", False)
    except Exception:
        return False

# ════════════════════════════════════════════════════════════
# SECTION 04 — DATA: users / customers
# Owns: load_users, save_users, get_user, load_customers,
#       save_customers, find_customer, update_customer_email,
#       has_family_addon
# State files: USERS_DB, CUSTOMERS_LOG
# ════════════════════════════════════════════════════════════

from harbor_lib.data import (
    load_users, save_users, get_user,
    save_customers, load_customers,
    update_customer_email, find_customer, has_family_addon,
)

# ════════════════════════════════════════════════════════════
# SECTION 05 — SUPPORT CODES / RATE LIMIT
# Owns: support code gen/verify/revoke, login attempt tracking
# ════════════════════════════════════════════════════════════
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
CODE_ATTEMPTS  = {}  # {ip: {count, locked_until}}

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

def verify_support_code(client_id, code, ip=None):
    if not code:
        return False
    if ip:
        entry = CODE_ATTEMPTS.get(ip, {})
        if entry.get("locked_until", 0) > _time.time():
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
    if ip:
        ce = CODE_ATTEMPTS.get(ip, {"count": 0, "locked_until": 0})
        ce["count"] = ce.get("count", 0) + 1
        if ce["count"] >= 10:
            ce["locked_until"] = _time.time() + 900
            ce["count"] = 0
        CODE_ATTEMPTS[ip] = ce
    return False

def revoke_support_code(client_id):
    codes = _load_codes()
    codes.pop(client_id, None)
    _save_codes(codes)

# ════════════════════════════════════════════════════════════
# SECTION 06 — ADGUARD HELPERS
# Owns: all calls to AdGuard Home REST API (port 8080)
# Failures degrade to cached snapshot in agh-snapshot.json
# Timeout: AGH_TIMEOUT (default 4s)
# ════════════════════════════════════════════════════════════

from harbor_lib.agh import (
    agh_get, agh_post,
    get_allowed_clients, get_client, is_client_allowed,
    get_stats, get_client_stats,
    get_all_blocked_services, get_client_blocked_services,
    PROFILES,
    save_profile_snapshot, save_active_profile,
    set_client_blocked_services,
    add_custom_rule, get_client_rules, remove_custom_rule,
)
from harbor_lib.config import AGH_TIMEOUT, AGH_SNAPSHOT_FILE

# ════════════════════════════════════════════════════════════
# SECTION 07 — AUTH
# Owns: make_token, verify_token, @login_required, @admin_required
# Uses JWT signed with SECRET_KEY, session cookie + bearer
# ════════════════════════════════════════════════════════════

from harbor_lib.auth import make_token, verify_token

def _setup_token_for(email):
    """Stateless HMAC setup token bound to a customer record.
    Becomes invalid implicitly once the user appears in users[]."""
    import hmac, hashlib
    c = find_customer(email)
    if not c: return None
    msg = f"{email.lower()}:{c.get('date','')}".encode()
    key = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
    return hmac.new(key, msg, hashlib.sha256).hexdigest()[:32]

def _verify_setup_token(token, email):
    import hmac
    expected = _setup_token_for(email)
    return bool(expected) and hmac.compare_digest(token, expected)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        raw = request.headers.get("Cookie", "")
        tokens = []
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("hp_token="):
                tokens.append(part[len("hp_token="):])
        if not tokens:
            return redirect("/login")
        payload = None
        for t in tokens:
            p = verify_token(t)
            if p:
                payload = p
                break
        if not payload:
            return redirect("/login")
        request.user_email = payload["email"]
        request.is_admin = payload.get("admin", False)
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # Browser may have multiple hp_token cookies (host-only + domain-wide).
        # Try each one until we find a valid admin token.
        raw = request.headers.get("Cookie", "")
        tokens = []
        for part in raw.split(";"):
            part = part.strip()
            if part.startswith("hp_token="):
                tokens.append(part[len("hp_token="):])
        if not tokens:
            return redirect("/login")
        payload = None
        for t in tokens:
            p = verify_token(t)
            if p and p.get("admin"):
                payload = p
                break
        if not payload:
            return redirect("/dashboard")
        request.user_email = payload["email"]
        request.is_admin = True
        return f(*args, **kwargs)
    return decorated

# ════════════════════════════════════════════════════════════
# SECTION 08 — EMAIL
# Owns: send_email (Resend API), email-failures.json log
# Larger templates live in webhook.py (send_welcome_email etc.)
# ════════════════════════════════════════════════════════════

from harbor_lib.email import send_email, record_email_failure as _record_email_failure
from harbor_lib.config import EMAIL_FAILURES_FILE

# ════════════════════════════════════════════════════════════
# SECTION 09 — SHARED STYLE + NAV
# Owns: STYLE (HTML head + CSS), NAV_CUSTOMER, NAV_ADMIN
# Every render_template_string prepends STYLE + a NAV
# ════════════════════════════════════════════════════════════

STYLE = """<!DOCTYPE html>
<html lang="en">
<head>
<link rel="icon" type="image/svg+xml" href="/dashboard-icon.svg">
<link rel="icon" type="image/png" sizes="32x32" href="/dashboard-icon-32.png">
<link rel="apple-touch-icon" sizes="180x180" href="/dashboard-icon-180.png">
<link rel="manifest" href="/dashboard-app.webmanifest">
<link rel="stylesheet" href="https://harborprivacy.com/css/harbor-system.css">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="HP Dashboard">
<meta name="theme-color" content="#00e5c0">
<script defer src="/install-banner.js"></script>
<script>
  if ('serviceWorker' in navigator) {
    window.addEventListener('load', function() {
      navigator.serviceWorker.register('/dashboard-sw.js').catch(function(){});
    });
  }
</script>
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
  nav{padding:16px 32px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;background:linear-gradient(180deg,#111618 0%,#0c1213 100%);backdrop-filter:saturate(140%) blur(4px);}
  .logo{font-family:'DM Mono',monospace;font-size:14px;color:var(--accent);letter-spacing:0.1em;text-decoration:none;white-space:nowrap;}
  .logo span{color:var(--muted);}
  .nav-links{display:flex;gap:8px;align-items:center;flex-wrap:wrap;row-gap:6px;}
  .nav-links a{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;letter-spacing:0.06em;padding:6px 10px;border-radius:6px;transition:color 0.15s,background 0.15s;}
  .nav-links a:hover,.nav-links a.active{color:var(--accent);background:rgba(0,229,192,0.06);}
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
    nav{flex-wrap:wrap;gap:8px;padding:12px 16px;}
    .nav-links{gap:6px;font-size:10px;}
    .badge{font-size:8px;padding:2px 6px;}
    .stat-grid{grid-template-columns:1fr;}
    .wrap{padding:32px 20px 60px;}
    .wrap-sm{padding:40px 20px;}
    nav{padding:14px 20px;}
    .customer-row{grid-template-columns:1fr 80px;}
  }
</style>
<script>
// CSRF: auto-attach X-CSRF header on same-origin state-changing fetches
(function(){
  var TOKEN = "{{ csrf_token }}";
  window.__CSRF = TOKEN;
  var _f = window.fetch;
  window.fetch = function(url, opts){
    opts = opts || {};
    var m = (opts.method || 'GET').toUpperCase();
    if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') {
      var u = String(url || '');
      if (u.charAt(0) === '/' || u.indexOf(location.origin) === 0) {
        opts.headers = opts.headers || {};
        if (!opts.headers['X-CSRF'] && !opts.headers['x-csrf']) opts.headers['X-CSRF'] = TOKEN;
        if (opts.credentials === undefined) opts.credentials = 'same-origin';
      }
    }
    return _f(url, opts);
  };
})();
function toggleGroup(btn){var body=btn.nextElementSibling;var arrow=btn.querySelector('.group-arrow');if(body.style.display==='none'){body.style.display='block';arrow.innerHTML='&#9650;';}else{body.style.display='none';arrow.innerHTML='&#9660;';}}
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
<div id="timeout-warning" style="display:none;position:fixed;bottom:24px;right:24px;background:#f4eee2;border:1px solid #1f5d6b;padding:20px 24px;z-index:9999;font-family:monospace;font-size:12px;color:#1a2420;flex-direction:column;gap:12px;max-width:300px;"><span>You will be logged out in 5 minutes due to inactivity.</span><button onclick="resetTimer()" style="background:#1f5d6b;color:#ffffff;border:none;padding:8px 16px;cursor:pointer;font-family:monospace;font-size:11px;">Stay Logged In</button></div>
<nav style="flex-direction:column;align-items:stretch;gap:0;padding:0;">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);">
    <a href="/dashboard" class="logo">harbor<span>/</span>privacy</a>
    <div style="display:flex;gap:6px;flex-wrap:wrap;justify-content:flex-end;">
      {% if user_email == "tim@harborprivacy.com" %}<span class="badge badge-owner">OWNER</span>{% endif %}
      {% if is_trial %}<span class="badge badge-trial">FREE TRIAL</span>{% endif %}
      {% if plan_badge %}<span class="badge badge-{{ plan_badge.lower().replace(' ','-') }}">{{ plan_badge }}</span>{% endif %}
      {% if has_family_badge %}<span class="badge badge-family">FAMILY SAFE</span>{% endif %}
      {% if harbor_kids %}<span class="badge" style="background:#06b6d4;color:#0a0e0f;">HARBOR KIDS</span>{% endif %}
    </div>
  </div>
  <div class="nav-links" style="padding:10px 24px;border-bottom:1px solid var(--border);justify-content:flex-start;gap:20px;">
    <a href="https://harborprivacy.com" style="font-size:10px;">← Site</a>
    <a href="/dashboard" class="{{ 'active' if active == 'dashboard' else '' }}">Dashboard</a>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    <a href="/logout" style="margin-left:auto;">Sign Out</a>
  </div>
</nav>"""

NAV_ADMIN = """
<div id="timeout-warning" style="display:none;position:fixed;bottom:24px;right:24px;background:#f4eee2;border:1px solid #1f5d6b;padding:20px 24px;z-index:9999;font-family:monospace;font-size:12px;color:#1a2420;flex-direction:column;gap:12px;max-width:300px;"><span>You will be logged out in 5 minutes due to inactivity.</span><button onclick="resetTimer()" style="background:#1f5d6b;color:#ffffff;border:none;padding:8px 16px;cursor:pointer;font-family:monospace;font-size:11px;">Stay Logged In</button></div>
<nav style="flex-direction:column;align-items:stretch;gap:0;padding:0;">
  <div style="display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);">
    <a href="/admin" class="logo">harbor<span>/</span>privacy</a>
    <span class="badge badge-admin">ADMIN</span>
  </div>
  <div class="nav-links" style="padding:10px 24px;border-bottom:1px solid var(--border);justify-content:flex-start;gap:20px;">
    <a href="https://harborprivacy.com" style="font-size:10px;">← Site</a>
    <a href="/admin" class="{{ 'active' if active == 'admin' else '' }}">Customers</a>
    <a href="/social" class="{{ 'active' if active == 'social' else '' }}">Social</a>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    <a href="https://assets.harborprivacy.com/" target="_blank" rel="noopener">Assets ↗</a>
    <a href="/logout" style="margin-left:auto;">Sign Out</a>
  </div>
</nav>"""

# ════════════════════════════════════════════════════════════
# SECTION 10 — ROUTES: AUTH
# /login, /logout, /setup, /dns-whoami, /dns-check, /setup/2fa-prompt
# Public Turnstile-protected pages — exempt from CSRF guard
# ════════════════════════════════════════════════════════════

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
                        # Customer but no account yet — DO NOT bare-redirect (would let
                        # anyone who knows the email claim the account). They must use
                        # the setup link in the welcome email, which carries an HMAC token.
                        error = ("Check your welcome email for the 'Set Up Your Account' link. "
                                 "Lost it? Email support@harborprivacy.com")
                        step = "1"
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
                else:
                    # Check password -- use hmac token in hidden field to survive stateless proxy
                    import hmac, hashlib
                    PW_SIGN_KEY = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
                    pw_token = request.form.get("pw_token", "")
                    expected_token = hmac.new(PW_SIGN_KEY, email.encode(), hashlib.sha256).hexdigest() if email else ""
                    print(f"2FA debug: pw_token={pw_token!r} expected={expected_token!r} email={email!r} totp={totp_code!r} password_present={bool(password)}", flush=True)
                    print(f"2FA compare: pw_token_len={len(pw_token)} expected_len={len(expected_token)} match={pw_token==expected_token}", flush=True)
                    if pw_token and hmac.compare_digest(pw_token, expected_token):
                        pw_ok = True
                    elif password:
                        pw_ok = bcrypt.checkpw(password.encode(), user["password"].encode())
                    else:
                        pw_ok = False
                    print(f"2FA pw_ok_final: pw_ok={pw_ok!r}", flush=True)
                    if pw_ok:
                        error = ""
                    if not pw_ok:  # noqa  # noqa
                        record_failed_login(ip)
                        error = "Incorrect password."
                        step = "2"
                        show_2fa = False
                    elif user.get("totp_secret"):
                        if not totp_code:
                            import hmac as _hmac, hashlib as _hs
                            _key = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
                            pw_tok = _hmac.new(_key, email.encode(), _hs.sha256).hexdigest()
                            session["pw_verified"] = email
                            show_2fa = True
                            step = "2"
                        elif not pyotp.TOTP(user["totp_secret"]).verify(totp_code, valid_window=1):
                            error = "Invalid 2FA code."
                            show_2fa = True
                            step = "2"
                        else:
                            session.pop("pw_verified", None)
                            is_admin = email == ADMIN_EMAIL
                            token = make_token(email, is_admin=is_admin)
                            # Update last_seen
                            try:
                                import json as _json, datetime as _dt
                                lines = open(CUSTOMERS_LOG).readlines()
                                new_lines = []
                                for l in lines:
                                    l = l.strip()
                                    if not l: continue
                                    r = _json.loads(l)
                                    if r.get("email","").lower() == email.lower():
                                        r["last_seen"] = _dt.datetime.utcnow().isoformat()
                                    new_lines.append(_json.dumps(r))
                                open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
                            except: pass
                            resp = make_response(redirect("/admin" if is_admin else "/dashboard"))
                            resp.set_cookie("hp_token", "", expires=0, path="/")
                            resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
                            resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400, domain=".harborprivacy.com")
                            return resp
                    else:
                        is_admin = email == ADMIN_EMAIL
                        token = make_token(email, is_admin=is_admin)
                        # Update last_seen
                        try:
                            import json as _json, datetime as _dt
                            lines = open(CUSTOMERS_LOG).readlines()
                            new_lines = []
                            for l in lines:
                                l = l.strip()
                                if not l: continue
                                r = _json.loads(l)
                                if r.get("email","").lower() == email.lower():
                                    r["last_seen"] = _dt.datetime.utcnow().isoformat()
                                new_lines.append(_json.dumps(r))
                            open(CUSTOMERS_LOG,"w").write("\n".join(new_lines) + "\n")
                        except: pass
                        resp = make_response(redirect("/admin" if is_admin else "/dashboard"))
                        resp.set_cookie("hp_token", "", expires=0, path="/")
                        resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
                        resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400, domain=".harborprivacy.com")
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
    <input type="hidden" name="pw_token" value="{{ pw_tok }}">
    <p style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;margin-bottom:8px;">AUTHENTICATOR CODE</p>
    <input type="text" name="totp" placeholder="6-digit code" maxlength="6" autocomplete="one-time-code" autofocus>
    <input type="hidden" name="password" value="">
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
    import hmac as _hmac2, hashlib as _hs2
    _key2 = app.secret_key if isinstance(app.secret_key, bytes) else app.secret_key.encode()
    pw_tok = _hmac2.new(_key2, email.encode(), _hs2.sha256).hexdigest() if email else ""
    return render_template_string(html, step=step, email=email, error=error, show_2fa=show_2fa, pw_tok=pw_tok)

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
    import requests as _req
    ip = request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For","").split(",")[0].strip() or request.remote_addr
    org = None
    try:
        r = _req.get(f"https://ipapi.co/{ip}/json/", timeout=5)
        if r.ok:
            data = r.json()
            org = data.get("org") or data.get("as") or None
    except:
        pass
    resp = jsonify({"ip": ip, "org": org, "ok": True})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/setup", methods=["GET", "POST"])
def setup():
    # Three valid access paths:
    #   1. Authed via hp_token cookie (just clicked /confirm-trial — auto-login)
    #   2. ?st=<HMAC token> matching the customer record (from welcome email)
    #   3. ?admin=1 + ADMIN_EMAIL (legacy first-time admin setup)
    # Bare ?email=X with no proof is REJECTED to close the takeover window.
    is_admin = request.args.get("admin", "0") == "1" or request.form.get("is_admin", "0") == "1"

    cookie_email = None
    _tok = request.cookies.get("hp_token")
    if _tok:
        _p = verify_token(_tok)
        if _p: cookie_email = (_p.get("email") or "").lower()

    raw_email = (request.args.get("email", "") or request.form.get("email", "")).strip().lower()
    st = (request.args.get("st", "") or request.form.get("st", "")).strip()

    if cookie_email:
        email = cookie_email
    elif is_admin and raw_email == ADMIN_EMAIL.lower():
        email = ADMIN_EMAIL
    elif raw_email and st and _verify_setup_token(st, raw_email):
        email = raw_email
    else:
        return redirect("/login")

    # Already has a password? Don't allow re-set via this route.
    if load_users().get(email) and not is_admin:
        return redirect("/login")

    error = None

    if request.method == "POST":
        password = request.form.get("password", "")
        password2 = request.form.get("password2", "")
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
            resp.set_cookie("hp_token", "", expires=0, path="/")
            resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
            resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=86400, domain=".harborprivacy.com")
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
    resp.set_cookie("hp_token", "", expires=0, path="/")
    resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
    return resp

# ════════════════════════════════════════════════════════════
# SECTION 11 — ROUTES: CUSTOMER DASHBOARD
# /dashboard — main authenticated customer page
# CRITICAL: plan_type must be set before harbor_kids (~line 1700)
# ════════════════════════════════════════════════════════════

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
    plan_type = customer.get("plan_type", "") if customer else ""
    harbor_kids = True if (customer and plan_type != "harbor-remote-light" and is_active) else customer.get("harbor_kids", False) if customer else False
    filtering_paused = not client.get("filtering_enabled", True) if client else False
    has_family = has_family_addon(client_id) if client_id else False
    is_founder = customer.get("is_founder", False) if customer else False
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
      <h1>{{ name }} {% if is_founder %}<span class="badge" style="background:#1f5d6b;color:#ffffff;font-size:10px;vertical-align:middle;">FOUNDER</span>{% endif %}</h1>
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
  <div class="locked-overlay" style="border-color:var(--accent);background:#1f5d6b08;margin-bottom:32px;">
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
      <div class="stat-label">Queries (7 Days)</div>
    </div>
    <div class="stat">
      <div class="stat-num {% if not is_active %}muted{% endif %}">{{ blocked if is_active else '—' }}</div>
      <div class="stat-label">Blocked (7 Days)</div>
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
      {% if customer.last_seen %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">LAST ACTIVE</span>
        <span style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ customer.last_seen[:16].replace("T"," ") }} UTC</span>
      </div>
      {% endif %}
      {% endif %}
      {% if is_founder %}
      <div style="display:flex;justify-content:space-between;align-items:center;">
        <span style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);letter-spacing:0.1em;">TIER</span>
        <span class="badge" style="background:#1f5d6b;color:#ffffff;">FOUNDER</span>
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
          <input type="checkbox" {% if family_safe %}checked{% endif %} {% if not is_active %}disabled{% else %}onchange="toggleAddon('family',this.checked)"{% endif %}>
          <span class="slider" style="border-radius:24px;"></span>
        </label>
      </div>

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
          <input type="checkbox" {% if harbor_kids %}checked{% endif %} {% if not is_active %}disabled{% else %}onchange="toggleAddon('harbor_kids',this.checked)"{% endif %}>
          <span class="slider" style="border-radius:24px;"></span>
        </label>
      </div>

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
        <a href="https://harborprivacy.com/setup/android/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
        <a href="https://harborprivacy.com/docs/harbor-kids#kids-setup" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">Windows Setup</a>
      </div>
    </div>
    {% endfor %}
    {% elif harbor_kids %}
    <p style="font-size:13px;color:var(--muted);">Your Harbor Kids profile is being set up. Check back shortly or contact support@harborprivacy.com.</p>
    {% else %}
    <p style="font-size:13px;color:var(--muted);">Enable Harbor Kids in the Add-Ons section above to get started.</p>
    {% endif %}
    {% if harbor_kids and kids_profiles|length < 5 %}
    <div style="margin-top:16px;">
      <button onclick="addKidProfileCustomer()" style="background:var(--accent);color:#0a0e0f;border:none;padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;letter-spacing:0.08em;">+ Add Child Profile</button>
      <span style="font-size:12px;color:var(--muted);margin-left:8px;">{{ 5 - kids_profiles|length }} of 5 remaining</span>
    </div>
    {% elif harbor_kids and kids_profiles|length >= 5 %}
    <div style="margin-top:16px;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Maximum of 5 child profiles reached.</div>
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
    {% set blocked_in_group = services | selectattr("id", "in", blocked_services) | list %}
    <div style="margin-bottom:4px;border:1px solid var(--border);">
      <button onclick="toggleGroup(this)" style="width:100%;display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--surface);border:none;cursor:pointer;text-align:left;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;">{{ group_name.replace("_"," ") }}</span>
          {% if blocked_in_group %}<span style="font-family:'DM Mono',monospace;font-size:9px;background:var(--accent);color:var(--bg);padding:2px 6px;">{{ blocked_in_group|length }} BLOCKED</span>{% endif %}
        </div>
        <span class="group-arrow" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">&#9660;</span>
      </button>
      <div class="group-body" style="display:none;padding:12px;background:var(--bg);">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(160px,1fr));gap:8px;">
          {% for svc in services %}
          <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 12px;background:var(--surface);border:1px solid var(--border);">
            <span style="font-size:13px;color:var(--text);">{{ svc.name }}</span>
            <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
              <input type="checkbox" {% if svc.id in blocked_services %}checked{% endif %} onchange="toggleService('{{ svc.id }}',this.checked)">
              <span class="slider" style="border-radius:24px;"></span>
            </label>
          </div>
          {% endfor %}
        </div>
      </div>
    </div>
    {% endfor %}
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

async function addKidProfileCustomer(){
  const kid_num = parseInt('{{ kids_profiles|length }}') + 1;
  if(kid_num > 5){alert('Maximum of 5 child profiles reached.');return;}
  const r = await fetch('/api/addon',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({type:'harbor_kids_add',kid_num:kid_num})});
  const d = await r.json();
  if(d.ok){location.reload();}else{alert('Failed to create profile. Contact support@harborprivacy.com');}
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

# ════════════════════════════════════════════════════════════
# SECTION 12 — ROUTES: ADMIN DASHBOARD
# /admin, /admin/customer/<id>, /admin/analytics, /admin/links
# Also /api/admin/* (split between sections 16-17)
# CRITICAL: plan_type before harbor_kids in admin_customer too
# ════════════════════════════════════════════════════════════

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

    # Fetch all AGH clients ONCE and build a lookup map to avoid the per-row
    # get_client() call that was hitting AGH 276+ times per page render.
    all_clients = (agh_get("/control/clients") or {}).get("clients") or []
    clients_map = {}
    for _cl in all_clients:
        for _cid in (_cl.get("ids") or []):
            clients_map[_cid] = _cl

    html = STYLE + NAV_ADMIN + """
<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin Panel</p>
    <h1>Harbor Privacy.</h1>
  </div>

  <div class="stat-grid" style="margin-bottom:32px;">
    <div class="stat"><div class="stat-num">{{ customers|length }}</div><div class="stat-label">Active Customers</div></div>
    <div class="stat"><div class="stat-num">{{ total_queries }}</div><div class="stat-label">DNS Queries (7 Days)</div></div>
    <div class="stat"><div class="stat-num">{{ block_pct }}%</div><div class="stat-label">Network Block Rate</div></div>
  </div>

  <div style="display:flex;gap:12px;flex-wrap:wrap;margin-bottom:20px;">
    <a href="/admin/links" style="display:inline-block;background:transparent;border:1px solid var(--accent);color:var(--accent);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; Link Manager</a>
    <a href="/admin/analytics" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; DNS Analytics</a>
    <a href="/admin/logs" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; Live Logs</a>
    <a href="https://assets.harborprivacy.com/" target="_blank" rel="noopener" style="display:inline-block;background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;">&#9679; Assets ↗</a>
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
      {% set cl = clients_map.get(c.client_id, {}) %}
      <div class="customer-row" {% if c.status == 'failed' %}style="border-left:3px solid #ff4e4e;background:rgba(255,78,78,0.05);"{% endif %}>
        <div>
          <div style="font-size:14px;color:var(--text);">{{ c.name }}{% if c.status == 'failed' %} <span style="font-family:'DM Mono',monospace;font-size:10px;color:#ff4e4e;letter-spacing:0.1em;">⚠ PROVISION FAILED</span>{% endif %}</div>
          <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">{{ c.email }}</div>
          {% if c.last_seen %}<div style="font-family:'DM Mono',monospace;font-size:10px;color:#4a6a67;">Last seen: {{ c.last_seen[:16].replace('T',' ') }} UTC</div>{% endif %}
        </div>
        <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);">{{ c.client_id }}</div>
        <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">{{ c.plan }}</div>
        <div><span class="badge {% if cl and cl.parental_enabled %}badge-on{% else %}badge-off{% endif %}">{% if cl and cl.parental_enabled %}ON{% else %}OFF{% endif %}</span></div>
        <div style="display:flex;gap:6px;align-items:center;">
          <a href="/admin/customer/{{ c.client_id }}" class="btn btn-sm" style="padding:4px 10px;font-size:10px;">View →</a>
          {% if c.client_id not in ["harbor7066", "admintim1003"] and c.email not in ["admin@harborprivacy.com", "tim@harborprivacy.com"] %}
          <button class="btn btn-sm" style="background:rgba(255,107,107,0.12);color:#ff6b6b;border-color:rgba(255,107,107,0.3);" onclick="deleteCustomer('{{ c.client_id }}','{{ c.name }}',this)">✕</button>
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
<script>
async function deleteCustomer(cid, name, btn){
  if (!btn.dataset.confirmed) {
    btn.dataset.confirmed = '1';
    btn.textContent = 'Sure?';
    btn.style.background = 'rgba(255,78,78,0.3)';
    return;
  }
  btn.textContent = '...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/admin/delete-customer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid})});
    const d = await r.json();
    if(d.ok){
      btn.closest('.customer-row').remove();
    } else {
      btn.textContent = 'Error';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = 'Error';
    btn.disabled = false;
  }
}
</script>
</html>"""
    return render_template_string(html, customers=customers,
        total_queries=total_queries, block_pct=block_pct,
        clients_map=clients_map, get_client=get_client, active="admin")


@app.route("/api/signup-stats")
def signup_stats():
    try:
        with open("/home/ubuntu/harbor-backend/harbor-customers.json") as f:
            signups = sum(1 for line in f if line.strip())
    except Exception:
        signups = 0
    dash_stats = _load_signup_stats()
    try:
        with open("/home/ubuntu/harbor-booking/signup-stats.json") as f:
            booking_stats = json.load(f)
    except Exception:
        booking_stats = {}
    bots = dash_stats.get("bots_blocked", 0) + booking_stats.get("bots_blocked", 0)
    resp = jsonify({"signups": signups, "bots_blocked": bots})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/api/agh-status")
def agh_status():
    try:
        stats     = agh_get("/control/stats") or {}
        query_log = agh_get("/control/querylog?limit=100") or {}
        logs      = query_log.get("data") or []

        doh_clients = {}
        for entry in logs:
            proto     = entry.get("client_proto", "")
            client_id = entry.get("client_id") or entry.get("client", "?")
            name      = (entry.get("client_info") or {}).get("name") or client_id
            if proto in ("doh", "dot", "doq"):
                key = f"{name} ({proto})" if name != client_id else f"{client_id} ({proto})"
                doh_clients[key] = doh_clients.get(key, 0) + 1

        resp = jsonify({
            "num_dns_queries":           stats.get("num_dns_queries", 0),
            "num_blocked_filtering":     stats.get("num_blocked_filtering", 0),
            "num_replaced_safebrowsing": stats.get("num_replaced_safebrowsing", 0),
            "top_clients":               stats.get("top_clients") or [],
            "top_blocked":               (stats.get("top_blocked_domains") or [])[:5],
            "doh_clients":               doh_clients,
        })
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp
    except Exception as e:
        resp = jsonify({"error": str(e)})
        resp.headers["Access-Control-Allow-Origin"] = "*"
        return resp, 500


@app.route("/api/home-beacon")
def home_beacon_script():
    with open("/home/ubuntu/harbor-home-beacon.sh") as f:
        content = f.read()
    return content, 200, {"Content-Type": "text/plain"}


@app.route("/api/home-status", methods=["GET"])
def home_status_get():
    try:
        with open(HOME_STATUS_FILE) as f:
            data = json.load(f)
        updated = data.get("updated")
        if updated:
            age = (datetime.utcnow() - datetime.fromisoformat(updated.rstrip("Z"))).total_seconds()
            if age > 180:
                data.setdefault("homebridge", {})["ok"] = False
                data.setdefault("unbound", {})["ok"] = False
                data["stale"] = True
    except:
        data = {"homebridge": {"ok": False, "ms": 0}, "unbound": {"ok": False, "ms": 0}, "updated": None}
    import subprocess, time as _time
    t0 = _time.time() * 1000
    try:
        r = subprocess.run(["dig", "@127.0.0.1", "-p", "5335", "+time=2", "+tries=1",
                            "harborprivacy.com", "A", "+short"],
                           capture_output=True, timeout=3)
        hu_ok = r.returncode == 0 and bool(r.stdout.strip())
    except Exception:
        hu_ok = False
    data["harbor_unbound"] = {"ok": hu_ok, "ms": int(_time.time() * 1000 - t0)}
    resp = jsonify(data)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/api/home-status", methods=["POST"])
def home_status_post():
    if not HOME_STATUS_TOKEN or request.headers.get("X-Home-Token", "") != HOME_STATUS_TOKEN:
        return jsonify({"error": "unauthorized"}), 401
    data = request.get_json(silent=True) or {}
    data["updated"] = datetime.utcnow().isoformat() + "Z"
    try:
        with open(HOME_STATUS_FILE, "w") as f:
            json.dump(data, f)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    resp = jsonify({"ok": True})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/api/dns-analytics", methods=["POST"])
def log_dns_analytics():
    import json as _json, time
    ANALYTICS_FILE = "/var/log/harbor-dns-analytics.json"
    try:
        data = request.get_json(silent=True) or {}
        isp = data.get("isp", "Unknown")[:100]
        protected = bool(data.get("protected", False))
        referrer = data.get("referrer", "")[:200]
        now = time.time()
        import datetime
        dt = datetime.datetime.fromtimestamp(now)
        record = {"ts": now, "isp": isp, "protected": protected, "referrer": referrer, "hour": dt.hour, "day": dt.weekday()}
        try:
            records = _json.loads(open(ANALYTICS_FILE).read())
        except:
            records = []
        records.append(record)
        open(ANALYTICS_FILE, "w").write(_json.dumps(records))
    except Exception as e:
        pass
    return "", 204

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
      <input type="text" id="new-url" placeholder="https://..." style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;">
      <label style="display:flex;align-items:center;gap:8px;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">
        <input type="checkbox" id="new-featured" style="width:16px;height:16px;accent-color:#1f5d6b;flex-shrink:0;margin:0;"> Featured (teal highlight)
      </label>
      <button id="add-link-btn" class="btn">Add Link</button>
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
document.addEventListener('DOMContentLoaded', function(){
  document.getElementById('add-link-btn').addEventListener('click', addLink);
});
async function addLink(){
  const label = document.getElementById('new-label').value.trim();
  const icon = document.getElementById('new-icon').value.trim();
  const url = document.getElementById('new-url').value.trim();
  const featured = document.getElementById('new-featured').checked;
  if(!label || !url){ document.getElementById('add-status').textContent='Label and URL required'; return; }
  const status = document.getElementById('add-status');
  status.style.color = 'var(--accent)';
  status.textContent = 'Saving...';
  try {
    const r = await fetch('/api/admin/links', {method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify({action:'add', label, icon, url, featured})});
    const text = await r.text();
    status.textContent = 'Response: ' + text.substring(0,100);
    try {
      const d = JSON.parse(text);
      if(d.ok) location.reload();
      else { status.style.color='#ff4e4e'; status.textContent = 'Error: ' + (d.error||'Unknown'); }
    } catch(e2) { status.style.color='#ff4e4e'; status.textContent = 'Parse error: ' + text.substring(0,100); }
  } catch(e) { status.style.color='#ff4e4e'; status.textContent = 'Fetch error: ' + e.message; }
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

@app.route("/admin/customer/<client_id>")
@admin_required
def admin_customer(client_id):
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return redirect("/admin")

    client = get_client(client_id)
    rules = get_client_rules(client_id) if client_id else []
    family_safe = client.get("parental_enabled", False) if client else False
    filtering_paused = not client.get("filtering_enabled", True) if client else False
    has_family = has_family_addon(client_id) if client_id else False
    plan_type = customer.get("plan_type", "remote") if customer else "remote"
    is_active = customer.get("status", "") == "active" if customer else False
    # CRITICAL: plan_type must always be defined before harbor_kids -- do not reorder
    plan_type = customer.get("plan_type", "remote") if customer else "remote"
    is_active = customer.get("status", "") == "active" if customer else False
    harbor_kids = True if (customer and plan_type != "harbor-remote-light" and is_active) else customer.get("harbor_kids", False) if customer else False
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
    <div class="stat"><div class="stat-num">{{ cstats.total }}</div><div class="stat-label">Queries (7 Days)</div></div>
    <div class="stat"><div class="stat-num">{{ cstats.blocked }}</div><div class="stat-label">Blocked (7 Days)</div></div>
    <div class="stat"><div class="stat-num">{{ cstats.pct }}%</div><div class="stat-label">Network Block Rate</div></div>
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
        <span class="badge" style="background:#1f5d6b;color:#ffffff;">FOUNDER</span>
      </div>
      {% endif %}
    </div>

    {% if customer.email == "admin@harborprivacy.com" %}
    <div style="border-top:1px solid var(--border);margin:16px 0;"></div>
    <a href="https://dashboard.harborprivacy.com/dashboard?preview=1" target="_blank" class="btn" style="display:block;text-align:center;margin-bottom:16px;">Preview Customer Dashboard</a>
    <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:12px;">Test Plan Mode</div>
    <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;">
        <select id="planSelect" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:8px 12px;font-family:'DM Mono',monospace;font-size:12px;flex:1;">
          <option value="remote" {% if customer.plan_type == "remote" %}selected{% endif %}>Harbor Remote</option>
          <option value="harbor-remote-light" {% if customer.plan_type == "harbor-remote-light" %}selected{% endif %}>Harbor Light</option>
          <option value="install" {% if customer.plan_type == "install" %}selected{% endif %}>On-Site Install</option>
          <option value="3month" {% if customer.plan_type == "3month" %}selected{% endif %}>Remote 3-Month</option>
          <option value="6month" {% if customer.plan_type == "6month" %}selected{% endif %}>Remote 6-Month</option>
          <option value="annual" {% if customer.plan_type == "annual" %}selected{% endif %}>Remote Annual</option>
        </select>
        <button class="btn" style="padding:8px 16px;" onclick="togglePlan('{{ customer.client_id }}',document.getElementById('planSelect').value,this)">Switch</button>
      </div>
      <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--muted);margin-top:8px;">Current: {{ customer.plan_type }}</p>
    {% endif %}

    <div style="border-top:1px solid var(--border);margin:16px 0;"></div>
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;">
      <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;">Update Email</div>
      <div style="display:flex;gap:8px;">
        <button onclick="resendWelcome('{{ customer.client_id }}')" class="btn btn-sm" style="background:transparent;border-color:var(--accent);color:var(--accent);">Resend Welcome</button>
        <button onclick="reprovision('{{ customer.client_id }}')" class="btn btn-sm btn-danger">Re-provision</button>
      </div>
    </div>
    <div style="display:flex;gap:8px;">
        <input type="email" id="newEmailInput" placeholder="New email address" style="flex:1;margin:0;">
        <button class="btn btn-sm" onclick="updateEmail('{{ customer.email }}',document.getElementById('newEmailInput').value,this)">Update</button>
      </div>
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
        <input type="checkbox" {% if family_safe %}checked{% endif %} {% if not is_active %}disabled{% else %}onchange="toggleFamily(this.checked)"{% endif %}>
        <span class="slider"></span>
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
        <input type="checkbox" {% if harbor_kids %}checked{% endif %} {% if not is_active %}disabled{% else %}onchange="toggleAddon('harbor_kids',this.checked)"{% endif %}>
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
        <a href="https://harborprivacy.com/setup/android/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
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
    {% set blocked_in_group = services | selectattr("id", "in", blocked_services) | list %}
    <div style="margin-bottom:4px;border:1px solid var(--border);">
      <button onclick="toggleGroup(this)" style="width:100%;display:flex;justify-content:space-between;align-items:center;padding:10px 14px;background:var(--surface);border:none;cursor:pointer;text-align:left;">
        <div style="display:flex;align-items:center;gap:10px;">
          <span style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.15em;text-transform:uppercase;">{{ group_name.replace("_"," ") }}</span>
          {% if blocked_in_group %}<span style="font-family:'DM Mono',monospace;font-size:9px;background:var(--accent);color:var(--bg);padding:2px 6px;">{{ blocked_in_group|length }} BLOCKED</span>{% endif %}
        </div>
        <span class="group-arrow" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">&#9660;</span>
      </button>
      <div class="group-body" style="display:none;padding:12px;background:var(--bg);">
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:8px;">
          {% for svc in services %}
          <div class="toggle-row" style="padding:8px 12px;background:var(--surface);border:1px solid var(--border);">
            <div style="font-size:13px;color:var(--text);">{{ svc.name }}</div>
            <label class="toggle" style="width:44px;height:24px;flex-shrink:0;">
              <input type="checkbox" {% if svc.id in blocked_services %}checked{% endif %} onchange="toggleService('{{ svc.id }}',this.checked)">
              <span class="slider" style="border-radius:24px;"></span>
            </label>
          </div>
          {% endfor %}
        </div>
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
async function deleteCustomer(cid, name, btn){
  if (!btn.dataset.confirmed) {
    btn.dataset.confirmed = '1';
    btn.textContent = 'Sure?';
    btn.style.background = 'rgba(255,78,78,0.3)';
    return;
  }
  btn.textContent = '...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/admin/delete-customer',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid})});
    const d = await r.json();
    if(d.ok){
      btn.closest('.customer-row').remove();
    } else {
      btn.textContent = 'Error';
      btn.disabled = false;
    }
  } catch(e) {
    btn.textContent = 'Error';
    btn.disabled = false;
  }
}
async function togglePlan(cid, plan, btn){
  btn.textContent='...';btn.disabled=true;
  const r=await fetch('/api/admin/toggle-plan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid,plan_type:plan})});
  const d=await r.json();
  btn.textContent=d.ok?'Done':'Error';btn.disabled=false;
}
async function updateEmail(oldEmail, newEmail, btn){
  if(!newEmail){return;}
  btn.textContent='...';btn.disabled=true;
  const r=await fetch('/api/admin/update-email',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({old_email:oldEmail,new_email:newEmail})});
  const d=await r.json();
  btn.textContent=d.ok?'Updated':'Error';btn.disabled=false;
}
async function resendWelcome(cid){
  const btn=event.target;btn.textContent='Sending...';btn.disabled=true;
  const r=await fetch('/api/admin/resend-welcome',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid})});
  const d=await r.json();
  btn.textContent=d.ok?'Sent!':'Error';
  setTimeout(()=>{btn.textContent='Resend Welcome';btn.disabled=false;},3000);
}
async function reprovision(cid){
  const btn=event.target;btn.textContent='Working...';btn.disabled=true;
  const r=await fetch('/api/admin/reprovision',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({client_id:cid,new_email:''})});
  const d=await r.json();
  if(d.ok){btn.textContent='Done!';setTimeout(()=>{btn.textContent='Re-provision';btn.disabled=false;},3000);}
  else{btn.textContent='Error: '+d.error;setTimeout(()=>{btn.textContent='Re-provision';btn.disabled=false;},3000);}
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
    _ip = request.headers.get("X-Forwarded-For", request.remote_addr).split(",")[0].strip()
    code_valid = customer_email.endswith("@harborprivacy.com") or verify_support_code(client_id, request.args.get("code", ""), ip=_ip)
    return render_template_string(html, customer=customer, client_id=client_id,
        rules=rules, family_safe=family_safe, harbor_kids=harbor_kids, kids_profiles=get_kids_profiles(client_id), cstats=cstats,
        service_groups=service_groups, blocked_services=blocked_services,
        code_valid=code_valid, active="admin")

# ════════════════════════════════════════════════════════════
# SECTION 13 — ROUTES: SETTINGS
# /settings, /settings/password, /settings/2fa/*, /settings/data-request
# All require @login_required + CSRF token in form
# ════════════════════════════════════════════════════════════

@app.route("/settings", methods=["GET"])
@login_required
def settings():
    email = request.user_email
    user = get_user(email)
    has_2fa = bool(user.get("totp_secret")) if user else False
    is_admin = request.is_admin
    msg = request.args.get("msg", "")
    msg_ok = request.args.get("ok", "0") == "1"
    show_2fa_reset = user.get("2fa_reset", False) if user else False
    if show_2fa_reset:
        users = load_users()
        users[email].pop("2fa_reset", None)
        save_users(users)

    NAV = NAV_ADMIN if is_admin else NAV_CUSTOMER

    html = STYLE + NAV + """
<div class="wrap" style="max-width:580px;">
  <h1 style="margin-bottom:32px;">Settings.</h1>

  {% if msg %}
  <div class="{{ 'success' if msg_ok else 'error' }}">{{ msg }}</div>
  {% endif %}
  {% if show_2fa_reset %}
  <div class="error" style="display:flex;align-items:center;gap:10px;">
    <span style="font-size:18px;">&#9888;</span>
    <span>Two-factor authentication was removed when you reset your password. <a href="/settings/2fa/setup" style="color:var(--accent);">Re-enable 2FA now →</a></span>
  </div>
  {% endif %}

  <div class="card">
    <div class="card-label">Change Password</div>
    <form method="POST" action="/settings/password">
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
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
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <input type="password" name="password" placeholder="Enter password to disable" required style="margin:0;flex:1;">
      <button type="submit" class="btn btn-danger">Disable 2FA</button>
    </form>
    {% endif %}
  </div>

  {% if not is_admin %}
  <div class="card">
    <div class="card-label">Support Access</div>
    <p class="note" style="margin-bottom:16px;">If you need help, generate a temporary support code and share it with Harbor Privacy support. The code expires in 30 minutes.</p>
    <button onclick="genCode()" class="btn" style="margin-bottom:12px;">Generate Support Code</button>
    <div id="support-code-box" style="display:none;background:var(--bg);border-left:3px solid var(--accent);padding:16px;font-family:'DM Mono',monospace;font-size:24px;color:var(--accent);letter-spacing:0.3em;text-align:center;margin-bottom:8px;"></div>
    <p id="support-code-note" style="display:none;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Share this code with support. Expires in 30 minutes.</p>
  </div>

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
async function genCode(){
  const r=await fetch('/api/support-code',{method:'POST'});
  const d=await r.json();
  if(d.code){
    document.getElementById('support-code-box').style.display='block';
    document.getElementById('support-code-box').innerText=d.code;
    document.getElementById('support-code-note').style.display='block';
  }
}
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
        msg=msg, msg_ok=msg_ok, email=email, active="settings", show_2fa_reset=show_2fa_reset)

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
    <input type="hidden" name="csrf" value="{{ csrf_token }}">
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
    html_body = f"""<div style="font-family:sans-serif;max-width:560px;color:#1a2420;">
<h2 style="font-family:Georgia,serif;font-weight:400;color:#1f5d6b;">Your Harbor Privacy Data Report</h2>
<p style="color:#6b7a72;font-size:13px;">Generated: {datetime.utcnow().isoformat()} UTC</p>
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
<p style="color:#6b7a72;font-size:13px;">Questions? Email support@harborprivacy.com</p>
</div>"""
    send_email(email, "Your Harbor Privacy Data Report", html_body)
    return redirect("/settings?msg=Your+data+report+has+been+sent+to+your+email.&ok=1")

# ════════════════════════════════════════════════════════════
# SECTION 14 — ROUTES: PASSWORD RESET
# /forgot, /reset — public, token-based, CSRF-exempt
# ════════════════════════════════════════════════════════════

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
                f'<div style="font-family:sans-serif;background:#fbf7f0;color:#1a2420;padding:32px;"><h2 style="font-family:Georgia,serif;font-weight:400;">Password Reset</h2><p>Click below to reset your password. This link expires in 1 hour.</p><p><a href="{reset_url}" style="color:#1f5d6b;">{reset_url}</a></p><p style="color:#6b7a72;font-size:13px;">If you did not request this, ignore this email.</p></div>')
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
                    users[email]["2fa_reset"] = True
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

# ════════════════════════════════════════════════════════════
# SECTION 15 — ROUTES: CUSTOMER API
# /api/pause, /api/profile, /api/addon, /api/service, /api/rule,
# /api/support-code, /api/weekly-email, /api/windows/*
# All POST require CSRF (except /api/windows/* per exempt list)
# ════════════════════════════════════════════════════════════


import random as _random
WINDOWS_APP_CODES = {}

@app.route("/api/windows/send-code", methods=["POST"])
def windows_send_code():
    data = request.json
    email = data.get("email", "").lower().strip()
    if not email:
        return jsonify({"ok": False, "error": "Email required"})
    customer = find_customer(email)
    if not customer:
        return jsonify({"ok": False, "error": "No account found for that email"})
    import time as _time
    code = str(_random.randint(100000, 999999))
    WINDOWS_APP_CODES[email] = {"code": code, "expires": _time.time() + 600}
    html = f'<div style="font-family:sans-serif;max-width:560px;color:#1a2420;"><h2 style="font-family:Georgia,serif;font-weight:400;">Your Harbor Privacy Login Code</h2><p>Use this code to sign in to the Harbor Privacy Windows app:</p><p style="background:#f4eee2;border-left:3px solid #1f5d6b;padding:20px;font-family:monospace;font-size:36px;color:#1f5d6b;letter-spacing:0.4em;text-align:center;">{code}</p><p style="color:#6b7a72;font-size:13px;">Expires in 10 minutes.</p><p style="color:#6b7a72;font-size:13px;">- Tim | harborprivacy.com</p></div>'
    send_email(email, "Your Harbor Privacy Login Code", html)
    app.logger.info(f"Windows app code sent to {email}")
    return jsonify({"ok": True})

@app.route("/api/windows/verify", methods=["POST"])
def windows_verify():
    import time as _time
    data = request.json
    email = data.get("email", "").lower().strip()
    code = data.get("code", "").strip()
    entry = WINDOWS_APP_CODES.get(email)
    if not entry or entry["code"] != code or _time.time() > entry["expires"]:
        return jsonify({"ok": False, "error": "Invalid or expired code"})
    del WINDOWS_APP_CODES[email]
    customer = find_customer(email)
    if not customer:
        return jsonify({"ok": False, "error": "Account not found"})
    client_id = customer.get("client_id", "")
    doh = f"https://doh.harborprivacy.com/dns-query/{client_id}"
    kids = get_kids_profiles(client_id)
    kids_data = [{"name": k["name"], "doh": f"https://doh.harborprivacy.com/dns-query/{k['name']}"} for k in kids]
    return jsonify({
        "ok": True,
        "name": customer.get("name", ""),
        "client_id": client_id,
        "doh": doh,
        "harbor_kids": customer.get("harbor_kids", False),
        "kids_profiles": kids_data,
        "plan": customer.get("plan_type", customer.get("plan", ""))
    })

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
        kids_id = f"{client_id}kid{kid_num}"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        kid_data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        # Find next available kid slot
        existing = get_kids_profiles(client_id)
        existing_names = [k["name"] for k in existing]
        if kids_id in existing_names:
            for n in range(1, 6):
                candidate = f"{client_id}kid{n}"
                if candidate not in existing_names:
                    kids_id = candidate
                    kid_data["name"] = kids_id
                    kid_data["ids"] = [kids_id]
                    break
            else:
                return jsonify({"ok": False, "error": "Maximum 5 profiles reached"})
        ok = agh_post("/control/clients/add", kid_data)
        if ok:
            update_customer_harbor_kids_flag(client_id, True)
            try:
                import re as _re
                if _re.match(r'^[a-zA-Z0-9_-]+$', kids_id):
                    from webhook import save_ios_kids_profile, generate_android_page, add_to_allowed_clients
                    save_ios_kids_profile(kids_id, "Harbor Kids")
                    generate_android_page(kids_id)
                    add_to_allowed_clients(kids_id)
            except Exception as ex:
                log.error(f"kids profile gen error: {ex}")
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
    PROTECTED_EMAILS = {"admin@harborprivacy.com", "tim@harborprivacy.com"}
    PROTECTED_IDS = {"harbor7066", "admintim1003"}
    client_id = data.get("client_id", "")
    if client_id in PROTECTED_IDS:
        return jsonify({"ok": False, "error": "Cannot delete protected account"})
    customers = load_customers()
    customer = next((c for c in customers if c.get("client_id") == client_id), None)
    if not customer:
        return jsonify({"ok": False, "error": "Customer not found"})
    if customer.get("email") in PROTECTED_EMAILS:
        return jsonify({"ok": False, "error": "Cannot delete protected account"})
    try:
        import sys, requests as _req
        sys.path.insert(0, "/home/ubuntu/harbor-backend")
        import sys as _sys
        _sys.path.insert(0, "/home/ubuntu/harbor-backend")
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
        new_client_id = client_id
        existing = agh_get("/control/clients")
        existing_names = [c.get("name") for c in (existing.get("clients") or [])]
        if new_client_id not in existing_names:
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
        return [c for c in clients if c.get("name","").startswith(f"{client_id}kid")]
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
        kids_id = f"{client_id}kid{kid_num}"
        ss = {"enabled":True,"bing":True,"duckduckgo":True,"ecosia":True,"google":True,"pixabay":True,"yandex":True,"youtube":True}
        kid_data = {"name":kids_id,"ids":[kids_id],"tags":[],"upstreams":None,"filtering_enabled":True,"parental_enabled":True,"safebrowsing_enabled":True,"safesearch_enabled":True,"use_global_blocked_services":False,"use_global_settings":False,"ignore_querylog":False,"ignore_statistics":False,"upstreams_cache_size":0,"upstreams_cache_enabled":False,"safe_search":ss,"blocked_services":[],"blocked_services_schedule":{"time_zone":"Local"}}
        ok = agh_post("/control/clients/add", kid_data)
        if ok:
            update_customer_harbor_kids_flag(client_id, True)
            try:
                import re as _re
                if _re.match(r'^[a-zA-Z0-9_-]+$', kids_id):
                    from webhook import save_ios_kids_profile, generate_android_page, add_to_allowed_clients
                    save_ios_kids_profile(kids_id, "Harbor Kids")
                    generate_android_page(kids_id)
                    add_to_allowed_clients(kids_id)
            except Exception as ex:
                log.error(f"kids profile gen error: {ex}")
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

# ════════════════════════════════════════════════════════════
# SECTION 16 — ROUTES: ADMIN API
# /api/admin/update-email, /api/admin/toggle-plan,
# /api/admin/service, /api/admin/rule, /api/admin/delete-customer,
# /api/admin/resend-welcome, /api/admin/reprovision,
# /api/admin/addon, /api/admin/revoke-code, /api/admin/links
# All POST require @admin_required + CSRF
# ════════════════════════════════════════════════════════════

@app.route("/api/admin/update-email", methods=["POST"])
@admin_required
def api_admin_update_email():
    data = request.get_json()
    old_email = (data.get("old_email") or "").strip()
    new_email = (data.get("new_email") or "").strip().lower()
    if not old_email or not new_email or old_email == new_email:
        return jsonify({"ok": False, "error": "Invalid emails"})
    updated = update_customer_email(old_email, new_email)
    log.info(f"Admin email update: {old_email} -> {new_email} success={updated}")
    return jsonify({"ok": updated})

@app.route("/api/admin/toggle-plan", methods=["POST"])
@admin_required
def api_admin_toggle_plan():
    data = request.get_json()
    client_id = data.get("client_id", "")
    new_plan = data.get("plan_type", "remote")
    customers = load_customers()
    updated = False
    for c in customers:
        if c.get("client_id") == client_id:
            c["plan_type"] = new_plan
            c["plan"] = "remote"
            updated = True
            break
    if updated:
        save_customers(customers)
        log.info(f"Admin plan toggle: {client_id} -> {new_plan}")
    return jsonify({"ok": updated})

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


# ════════════════════════════════════════════════════════════
# SECTION 17 — ROUTES: ADMIN LOGS
# /admin/logs, /admin/logs/stream — tail of webhook + dashboard logs
# ════════════════════════════════════════════════════════════

@app.route("/admin/logs")
@admin_required
def admin_logs():
    import subprocess
    result = subprocess.run(
        ["journalctl", "-u", "harbor-dashboard", "-n", "500", "--no-pager", "--output=short"],
        capture_output=True, text=True
    )
    lines = result.stdout.strip().split("\n")
    lines.reverse()
    colored = []
    for line in lines:
        if "ERROR" in line:
            colored.append(f'<span style="color:#ff4e4e">{line}</span>')
        elif "WARNING" in line:
            colored.append(f'<span style="color:#f5a623">{line}</span>')
        elif any(x in line for x in ["reprovision","welcome","stripe","email"]):
            colored.append(f'<span style="color:#1f5d6b">{line}</span>')
        else:
            colored.append(f'<span style="color:#a8c5c1">{line}</span>')
    log_html = "\n".join(colored)
    with open("/home/ubuntu/harbor-backend/logs_template.html") as f:
        template = f.read()
    return template.replace("LOG_CONTENT_PLACEHOLDER", log_html)

@app.route("/admin/logs/stream")
@admin_required
def admin_logs_stream():
    import subprocess
    result = subprocess.run(
        ["journalctl", "-u", "harbor-dashboard", "-n", "500", "--no-pager", "--output=short"],
        capture_output=True, text=True
    )
    from flask import Response
    return Response(result.stdout, mimetype="text/plain")


# ════════════════════════════════════════════════════════════
# SECTION 18 — ROUTES: SOCIAL (admin tool)
# /social UI, /api/social/generate, /api/social/post-to-make,
# /api/social/status, /api/social/toggle
# Helpers: _build_post_prompt, _generate_image_claude/openai
# ════════════════════════════════════════════════════════════

@app.route("/social")
@admin_required
def social():
    resp = make_response(render_template_string(SOCIAL_HTML, active="social"))
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.route("/api/csrf")
def api_csrf():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return jsonify({"csrf": tok})

def _build_post_prompt(brand, topic, platforms):
    import json as _json
    if brand == "career":
        context = """Career by Harbor Privacy offers two AI tools at career.harborprivacy.com:
1. AI Cover Letter Generator ($2.99) -- paste a job posting and your background, get a tailored cover letter in 2 minutes.
2. AI Resume Review ($2.99) -- paste your resume, get ATS optimization feedback, weak language fixes, and a rewritten PDF.
Both tools delete your data within 2 hours. No account needed."""
        problem_angles = [
            "Most resumes never get seen by a human -- ATS software filters them out first because they don't match the job description keywords.",
            "The average recruiter spends 6 seconds on a resume. If yours looks like everyone else's, it's invisible.",
            "People paste their whole work history into ChatGPT and wonder why their cover letter sounds generic. Your data also sits on their servers forever.",
            "Applying to 20 jobs with the same resume and cover letter is why you're not hearing back.",
            "Your career history is personal. Most AI tools store it. Career by Harbor Privacy deletes it in 2 hours.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "career.harborprivacy.com"
        cta_ig = "Link in bio"
        cta_li = "career.harborprivacy.com"
    elif brand == "fax":
        context = """Harbor Privacy Fax is an anonymous fax service at fax.harborprivacy.com. $2.99/fax up to 10 pages. Add 20 more pages for $1.99 (up to 30 total). Optional unbranded cover page for $0.99. No account required. Documents are permanently deleted the moment delivery is confirmed. Operates under the HIPAA conduit exception. Supports PDF, images, and Word docs. Send from your phone in under 2 minutes."""
        problem_angles = [
            "Doctors, lawyers, and insurance companies still require fax. Most people don't own a fax machine.",
            "You shouldn't have to create an account just to send one medical record.",
            "Most online fax services store your documents on their servers. Harbor Privacy Fax deletes yours the moment it delivers.",
            "HIPAA still requires fax for many medical record requests. Here's how to send one from your phone.",
            "Your legal documents deserve more privacy than an email attachment. Fax is still the standard -- and now it's anonymous.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "fax.harborprivacy.com -- no account needed"
        cta_ig = "Link in bio -- send a fax from your phone"
        cta_li = "fax.harborprivacy.com"
    elif brand == "tim":
        context = """Tim Brazer is a healthcare operations leader with 20 years in diagnostic imaging and multi-site front office management at South Shore Health. Epic-credentialed in Cadence and Radiant. Currently completing an MBA with healthcare management concentration at Fisher College. Also building Harbor Privacy, a suite of privacy tools, while job searching for Practice Administrator and COO roles in Massachusetts healthcare."""
        problem_angles = [
            "Most healthcare ops leaders know Epic inside out but struggle to explain their impact in a way that lands on a resume or LinkedIn.",
            "Revenue cycle problems in diagnostic imaging rarely start in billing -- they start at the front desk. Most administrators don't see it that way.",
            "Prior auth delays, denial prevention, and patient access are all connected. The facilities that get this right treat them as one workflow.",
            "Servant leadership sounds like a buzzword until you watch a team outperform every metric because they actually trust their manager.",
            "20 years in one health system teaches you things no MBA program covers -- the unofficial workflows that actually move the needle.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = ""
        cta_ig = ""
        cta_li = "Open to connecting with healthcare leaders in Massachusetts."
    elif brand == "booking":
        context = """Harbor Booking is a free scheduling and booking platform at booking.harborprivacy.com. Includes online client booking, employee shift scheduling, PTO tracking, automatic reminders, and multi-site support. Free to use. No credit card required. Works for salons, medical offices, restaurants, and any small business."""
        problem_angles = [
            "Most small businesses are still taking appointments over the phone. That means missed calls, double bookings, and frustrated clients.",
            "Your clients want to book at 11pm when your office is closed. If you don't have online booking, you're losing them to someone who does.",
            "Scheduling employees across multiple locations in a spreadsheet is a full-time job. It doesn't have to be.",
            "No-shows cost small businesses thousands a year. Automatic reminders fix most of it.",
            "Most scheduling software charges per user or takes a cut of bookings. Harbor Booking is free.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "booking.harborprivacy.com -- free to set up"
        cta_ig = "Link in bio -- free online booking"
        cta_li = "booking.harborprivacy.com"
    elif brand == "money":
        context = """Harbor Money is personal budgeting without handing over your bank login, at money.harborprivacy.com. Forward your transaction emails (receipts, bank alerts, card notifications) -- Harbor Money parses them, categorizes spending, and tracks savings goals automatically. No bank credentials, no Plaid, no tracking. Privacy-first alternative to YNAB and Mint."""
        problem_angles = [
            "YNAB and Mint want your bank login. That single password is the keys to your kingdom -- and it lives on their servers.",
            "Plaid had a 70 million user data breach. That's the same Plaid every budgeting app uses to read your bank account.",
            "You already get transaction emails from your bank and every card. Why hand over a password when forwarding is enough?",
            "Budgeting apps die or get acquired and your bank credentials go with them. Forwarding emails leaves no credential to lose.",
            "Most personal finance apps make money by selling anonymized spending data. Yours.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "money.harborprivacy.com -- no bank login required"
        cta_ig = "Link in bio -- budgeting without bank logins"
        cta_li = "money.harborprivacy.com"
    else:
        context = """Harbor Privacy is a managed home network privacy service. Harbor Light $1.99/mo (ad and tracker blocking). Harbor Remote $5.99/mo with 30-day free trial (full privacy on any network). Blocks ads before they load, stops trackers, blocks malware. Works on every device automatically. No tech knowledge needed."""
        problem_angles = [
            "Your ISP is legally allowed to sell your browsing history. Most people have no idea.",
            "Every ad you see online is the result of someone tracking exactly what you did, when, and on what device.",
            "Kids' tablets, smart TVs, gaming consoles -- every device on your network is being tracked. Most routers do nothing about it.",
            "Ad blockers only work on one browser on one device. Your phone, your TV, your kids' iPad -- still tracked.",
            "Most people think incognito mode means private. It doesn't block your ISP from seeing everything.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "Free 30-day trial at harborprivacy.com"
        cta_ig = "Link in bio for free trial"
        cta_li = "harborprivacy.com"

    platform_rules = []
    platform_keys = []
    if platforms.get("facebook", True):
        platform_rules.append(f"- Facebook: Start with this problem hook: \"{problem}\" then 1-2 sentences explaining the solution, end with \"{cta_fb}\". 1 emoji max.")
        platform_keys.append("facebook")
    if platforms.get("instagram", True):
        platform_rules.append(f"- Instagram: Same problem-first structure, end with \"{cta_ig}\", then 6-8 relevant hashtags on a new line.")
        platform_keys.append("instagram")
    if platforms.get("linkedin", True):
        platform_rules.append(f"- LinkedIn: Problem-first, slightly more professional, 2-3 sentences, end with \"{cta_li}\".")
        platform_keys.append("linkedin")
    platform_rules.append(f"- headline: A short punchy 4-8 word image overlay headline for this post. All caps. No punctuation. Examples: STOP LOSING CLIENTS TO VOICEMAIL / YOUR DATA STAYS YOURS / FREE SCHEDULING THAT ACTUALLY WORKS")

    if not platform_keys:
        platform_keys = ["facebook", "instagram"]

    prompt = f"""Write social media posts about: {topic}

Context: {context}

Rules:
- Lead with a real problem people face, not a product feature
- Sound like a real person, not a company
- No corporate speak, no buzzwords, no em dashes
- Short and punchy -- people scroll fast
{chr(10).join(platform_rules)}

Return JSON only with keys: {", ".join(platform_keys)}"""
    return prompt, platform_keys

SOCIAL_IMAGES_ENABLED = False  # Gemini free-tier image quota is 0/day; text-only for now

def _generate_image_claude(brand, topic):
    if not SOCIAL_IMAGES_ENABLED:
        return None
    # Renamed in spirit -- now uses Gemini 2.5 Flash Image (Nano Banana).
    # Kept name for back-compat with autopost callers.
    import requests as _req
    import base64 as _b64, json as _json, time as _t, pathlib
    try:
        with open("/var/www/brazer/config.json") as _cf:
            gemini_key = _json.load(_cf).get("benny_api_key", "")
    except Exception as e:
        print(f"_generate_image: config read failed: {e!r}", flush=True)
        return None
    if not gemini_key:
        return None
    scene_map = {
        "career": f"Clean light-themed social tile for a privacy-first AI career tool. Soft teal (#34d399) accents, minimal geometric shapes, professional optimistic mood, no text, no people. Topic: {topic}",
        "fax":    f"Dark-themed social tile for an anonymous fax service. Very dark background (#0a0e0f), teal accent (#00e5c0), minimal medical-document iconography, no text, no people. Topic: {topic}",
        "booking":f"Warm amber-themed social tile for a free scheduling app. Dark warm background, amber (#f59e0b) accents, calendar/clock motifs, no text, no people. Topic: {topic}",
        "money":  f"Calm green-themed social tile for a privacy-first personal budgeting app. Dark green background, sage accents (#7faa86), minimal envelope/coin/chart motifs, no text, no people. Topic: {topic}",
        "tim":    f"Professional blue-themed LinkedIn tile for a healthcare operations leader. Dark navy background, soft blue (#4a9edd) accents, minimal abstract shapes, no text, no people. Topic: {topic}",
        "harbor": f"Dark-themed social tile for a home network privacy service. Very dark background (#0a0e0f), teal accent (#00e5c0), clean geometric grid lines, tech and privacy theme, no text, no people. Topic: {topic}",
    }
    img_prompt = scene_map.get(brand, scene_map["harbor"])
    try:
        r = _req.post(
            f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-image:generateContent?key={gemini_key}",
            headers={"Content-Type": "application/json"},
            json={"contents": [{"parts": [{"text": img_prompt + "\n\nGenerate a 1:1 square image suitable for Instagram. Return only the image."}]}]},
            timeout=60)
        print(f"_generate_image: gemini_status={r.status_code} body_preview={r.text[:200]!r}", flush=True)
        rj = r.json()
        parts = (rj.get("candidates") or [{}])[0].get("content", {}).get("parts", [])
        for p in parts:
            inline = p.get("inlineData") or p.get("inline_data")
            if inline and inline.get("data"):
                raw = _b64.b64decode(inline["data"])
                img_dir = pathlib.Path("/var/www/network/social-images")
                img_dir.mkdir(exist_ok=True)
                fname = f"social-{brand}-{int(_t.time())}.png"
                (img_dir / fname).write_bytes(raw)
                return f"https://dashboard.harborprivacy.com/social-images/{fname}"
        print(f"_generate_image: no inline image in response: {rj}", flush=True)
    except Exception as e:
        print(f"_generate_image: EXC {e!r}", flush=True)
    return None

def _generate_image_openai(brand, topic):
    if not SOCIAL_IMAGES_ENABLED:
        return None
    import requests as _req
    openai_key = os.environ.get("OPENAI_API_KEY", "")
    if not openai_key:
        return None
    import random as _random
    scenes = {
        "career": [
            f"Photorealistic lifestyle photograph, young professional woman reviewing documents at a bright cafe table, coffee and laptop nearby, confident optimistic mood, natural light, cinematic, topic: {topic}",
            f"Photorealistic lifestyle photograph, man in business casual at a standing desk in a modern open office, looking confident, warm light, shallow depth of field, topic: {topic}",
            f"Photorealistic lifestyle photograph, person celebrating at their desk, fist pump moment, home office with plants and natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, close-up of hands typing on a laptop on a clean wooden desk, coffee mug and notebook beside it, warm morning light, topic: {topic}",
            f"Photorealistic lifestyle photograph, diverse professional team in a bright modern conference room, collaborative mood, natural light, topic: {topic}",
        ],
        "fax": [
            f"Photorealistic lifestyle photograph, doctor's office reception desk, medical folders and forms organized neatly, calm clinical atmosphere, soft light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person's hands on a clean desk beside an envelope and printed document, private calm atmosphere, soft sidelight, topic: {topic}",
            f"Photorealistic lifestyle photograph, attorney's office desk with legal documents, pen and coffee, professional serious mood, warm lamp light, topic: {topic}",
            f"Photorealistic lifestyle photograph, medical records room, organized filing system, clean and professional, soft overhead light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person at a home desk carefully folding a document into an envelope, focused calm expression, natural window light, topic: {topic}",
        ],
        "booking": [
            f"Photorealistic lifestyle photograph, modern hair salon interior, stylists working with clients in background, clean bright atmosphere, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, busy restaurant front of house, host stand with organized reservation book, warm evening light, topic: {topic}",
            f"Photorealistic lifestyle photograph, yoga studio reception area, clean minimal desk, plants and natural light, welcoming calm atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, small medical clinic waiting room, organized and welcoming, warm light, a receptionist at the desk smiling, topic: {topic}",
            f"Photorealistic lifestyle photograph, spa reception desk with candles and fresh flowers, elegant calm atmosphere, warm soft light, topic: {topic}",
            f"Photorealistic lifestyle photograph, auto repair shop front desk, organized professional, owner smiling confidently, topic: {topic}",
        ],
        "tim": [
            f"Photorealistic lifestyle photograph, healthcare administrator walking confidently through a hospital corridor, professional attire, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, medical office manager at a desk reviewing printed reports, focused professional expression, warm light, topic: {topic}",
            f"Photorealistic lifestyle photograph, healthcare team huddle in a bright conference room, collaborative leadership mood, topic: {topic}",
            f"Photorealistic lifestyle photograph, radiology department hallway, professional in scrubs walking purposefully, clean clinical light, topic: {topic}",
            f"Photorealistic lifestyle photograph, hospital administrator shaking hands with a colleague, confident professional setting, natural light, topic: {topic}",
        ],
        "harbor": [
            f"Photorealistic lifestyle photograph, family watching TV together in a cozy living room, warm evening light, relaxed safe atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, parent helping child with homework on a kitchen table, warm home environment, natural light, topic: {topic}",
            f"Photorealistic lifestyle photograph, person relaxing on a couch with a book, phone face-down on coffee table, calm private mood, warm lamp light, topic: {topic}",
            f"Photorealistic lifestyle photograph, home office setup, person working focused at a clean desk, plants and natural light, peaceful productive atmosphere, topic: {topic}",
            f"Photorealistic lifestyle photograph, couple sitting together at a kitchen table with coffee, comfortable home morning atmosphere, warm natural light, topic: {topic}",
        ],
        "auto": [
            f"Photorealistic lifestyle photograph, minimal modern workspace, person focused at a clean desk, coffee and plant, natural morning light, topic: {topic}",
            f"Photorealistic lifestyle photograph, entrepreneur at a standing desk in a bright loft office, confident mood, topic: {topic}",
            f"Photorealistic lifestyle photograph, clean home office with organized bookshelf, person typing at laptop, warm focused atmosphere, topic: {topic}",
        ],
    }
    scene_list = scenes.get(brand, scenes["harbor"])
    img_prompt = _random.choice(scene_list)
    try:
        r = _req.post("https://api.openai.com/v1/images/generations",
            headers={"Authorization": f"Bearer {openai_key}", "Content-Type": "application/json"},
            json={"model": "gpt-image-1", "prompt": img_prompt, "n": 1, "size": "1024x1024", "quality": "medium"},
            timeout=90)
        import base64 as _b64, time as _t, pathlib
        resp_json = r.json()
        if "error" in resp_json:
            import logging; logging.getLogger(__name__).error(f"OpenAI image error: {resp_json['error']}")
            return None
        img_b64 = resp_json["data"][0]["b64_json"]
        img_data = _b64.b64decode(img_b64)
        img_dir = pathlib.Path("/var/www/network/social-images")
        img_dir.mkdir(exist_ok=True)
        fname = f"social-{brand}-{int(_t.time())}.png"
        (img_dir / fname).write_bytes(img_data)
        return f"https://dashboard.harborprivacy.com/social-images/{fname}"
    except Exception:
        return None

@app.route("/api/social/generate", methods=["POST"])
@admin_required
def social_generate():
    import requests as _req, json as _json
    data = request.json or {}
    topic = data.get("topic", "home network privacy")
    brand = data.get("brand", "harbor")
    platforms = data.get("platforms", {"facebook": True, "instagram": True, "linkedin": True})

    prompt, platform_keys = _build_post_prompt(brand, topic, platforms)

    gen_error = None
    try:
        r = _req.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": os.environ.get("ANTHROPIC_API_KEY",""), "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 600, "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        print(f"social_generate: anthropic_status={r.status_code} body_preview={r.text[:300]!r}", flush=True)
        rj = r.json()
        if "content" not in rj:
            api_msg = (rj.get("error") or {}).get("message") or rj.get("message") or str(rj)
            raise RuntimeError(api_msg)
        content = rj["content"][0]["text"]
        content = content.strip().lstrip("```json").rstrip("```").strip()
        posts = _json.loads(content)
    except Exception as e:
        print(f"social_generate: EXC brand={brand} topic={topic!r} err={e!r}", flush=True)
        gen_error = str(e) or "Generation failed."
        posts = {k: "" for k in platform_keys}

    if gen_error:
        return jsonify({"error": gen_error}), 502

    image_url = _generate_image_claude(brand, topic)
    if not image_url:
        image_url = _generate_image_openai(brand, topic)

    headline = posts.get("headline", "")
    if not headline:
        # fallback: first sentence of facebook post
        fb = posts.get("facebook", "")
        headline = fb.split(".")[0] if fb else topic

    return jsonify({
        "facebook": posts.get("facebook", ""),
        "instagram": posts.get("instagram", ""),
        "linkedin": posts.get("linkedin", ""),
        "image_url": image_url,
        "headline": headline
    })

# ════════════════════════════════════════════════════════════
# SECTION 19 — ROUTES: TRIAL SIGNUP /begin
# Public Turnstile-protected endpoint. Creates AGH client,
# iOS profile, Android page, QR, then sends welcome email.
# Dedup welcome via webhook.is_processed("welcome:{email}").
# ════════════════════════════════════════════════════════════

@app.route("/begin", methods=["POST"])
def begin_trial():
    """Trial signup — now a 2-step flow:
       1. /begin       validate + send confirmation email (NO provisioning yet)
       2. /confirm-trial/<token>   actually creates the AGH client + sends welcome
    """
    import json as _json
    import re as _re_email
    import secrets as _secrets, time as _time
    try:
        data = request.get_json(silent=True) or {}
        email = (data.get("email") or request.form.get("email", "")).strip().lower()
        EMAIL_RE = _re_email.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
        if not email or not EMAIL_RE.match(email) or len(email) > 254:
            return jsonify({"error": "Valid email required"}), 400

        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

        # Per-IP signup rate limit: max 3 attempts per hour
        if not _signup_rate_ok(ip, limit=1, window=3600):
            if request.is_json:
                return jsonify({"ok": False, "error": "rate_limited",
                                "redirect": "https://adblock.harborprivacy.com/slow-down.html"}), 429
            return redirect("https://adblock.harborprivacy.com/slow-down.html")

        # Disposable domain block
        try:
            with open("/home/ubuntu/harbor-backend/disposable-domains.txt") as _df:
                DISPOSABLE_DOMAINS = {ln.strip().lower() for ln in _df if ln.strip() and not ln.startswith("#")}
        except Exception:
            DISPOSABLE_DOMAINS = set()
        email_domain = email.split("@")[-1]
        if email_domain in DISPOSABLE_DOMAINS:
            return jsonify({"error": "Please use a permanent email address."}), 400

        # Honeypot - real browsers leave hidden field empty, bots fill everything
        if (data.get("website") or request.form.get("website", "")).strip():
            log.warning(f"honeypot tripped from {ip} for {email}")
            _inc_bots_blocked()
            return jsonify({"ok": True, "message": "Check your email to confirm your signup."})
        # Min form-fill time - bots submit instantly
        try:
            fts = int(data.get("fts") or request.form.get("fts", "0"))
        except Exception:
            fts = 0
        if fts and (int(_time.time()*1000) - fts) < 3000:
            log.warning(f"fast-submit bot from {ip} for {email}")
            _inc_bots_blocked()
            return jsonify({"ok": True, "message": "Check your email to confirm your signup."})

        # Turnstile (defense in depth — known to be solver-bypassable but still helpful)
        ts = data.get("cf_turnstile_response") or request.form.get("cf-turnstile-response", "")
        if not _verify_turnstile(ts, ip):
            _inc_bots_blocked()
            record_failed_login(ip)
            return jsonify({"error": "CAPTCHA verification failed. Please try again."}), 400

        # Duplicate check — now reads the REAL customer log
        try:
            with open("/var/log/harbor-customers.json") as f:
                for ln in f:
                    try:
                        c = _json.loads(ln)
                    except Exception: continue
                    if c.get("email", "").lower() == email and c.get("status") == "active":
                        if request.is_json:
                            return jsonify({"ok": False, "error": "already_exists",
                                            "redirect": "https://adblock.harborprivacy.com/already-member.html"}), 409
                        return redirect("https://adblock.harborprivacy.com/already-member.html")
        except Exception: pass

        # Don't provision yet. Issue a pending-signup record + confirmation email.
        token = _secrets.token_urlsafe(32)
        _save_pending_signup(token, email=email, ip=ip,
                             created_at=int(_time.time()))
        _send_signup_confirmation(email, token)
        _record_signup_attempt(ip)

        if request.is_json:
            return jsonify({"ok": True,
                            "message": "Check your email to confirm your signup."})
        return redirect("https://harborprivacy.com/confirm-your-email.html")
    except Exception as e:
        log.error(f"/begin error: {e}")
        return jsonify({"error": "Something went wrong. Please try again."}), 500


# ── Signup-rate-limit + pending-signups helpers ─────────────
_SIGNUP_ATTEMPTS = {}      # ip -> [ts, ts, ...]  rolling hour
_PENDING_FILE = "/var/log/harbor-pending-signups.json"

def _signup_rate_ok(ip, limit=3, window=3600):
    import time as _t
    now = _t.time()
    rec = [t for t in _SIGNUP_ATTEMPTS.get(ip, []) if (now - t) < window]
    _SIGNUP_ATTEMPTS[ip] = rec
    return len(rec) < limit

def _record_signup_attempt(ip):
    import time as _t
    _SIGNUP_ATTEMPTS.setdefault(ip, []).append(_t.time())

def _save_pending_signup(token, **fields):
    import json as _json, os
    pending = _load_pending()
    pending[token] = fields
    # Prune expired (>24h)
    import time as _t
    now = _t.time()
    pending = {k: v for k, v in pending.items() if (now - v.get("created_at", 0)) < 24*3600}
    try:
        with open(_PENDING_FILE, "w") as f:
            _json.dump(pending, f)
        os.chmod(_PENDING_FILE, 0o600)
    except Exception as e:
        log.error(f"pending save: {e}")

def _load_pending():
    import json as _json
    try:
        with open(_PENDING_FILE) as f:
            return _json.load(f)
    except Exception:
        return {}

def _send_signup_confirmation(email, token):
    """Send the click-to-confirm email. Until they click, no AGH client gets created."""
    from webhook import send_email
    confirm_url = f"https://adblock.harborprivacy.com/confirm-trial/{token}"
    html = f"""<div style="font-family:sans-serif;max-width:560px;color:#1a2420;">
<h1 style="font-family:'DM Serif Display',Georgia,serif;font-weight:400;color:#1a2420;font-size:24px;letter-spacing:-.01em;margin:0 0 10px;">Confirm your Harbor Privacy account</h1>
<p>Hi there,</p>
<p>Tap the button below to activate your 30-day free trial. The link expires in 24 hours.</p>
<p style="margin:24px 0;"><a href="{confirm_url}" style="display:inline-block;background:#1f5d6b;color:#ffffff;padding:14px 28px;text-decoration:none;font-weight:600;letter-spacing:.02em;border-radius:8px;font-size:15px;">Activate my trial &rarr;</a></p>
<p style="font-size:13px;color:#6b7a72;">Or paste this link into your browser:<br><span style="font-family:'DM Mono',monospace;font-size:12px;word-break:break-all;color:#1f5d6b;">{confirm_url}</span></p>
<p style="font-size:13px;color:#6b7a72;margin-top:24px;">Didn't sign up? You can safely ignore this email.</p>
</div>"""
    send_email(email, "Confirm your Harbor Privacy account", html)


@app.route("/confirm-trial/<token>")
def confirm_trial(token):
    """Activate a pending trial: provision AGH client + send welcome email."""
    import json as _json, time as _t
    from webhook import (generate_client_id, create_adguard_client, save_ios_profile,
                         log_customer, send_welcome_email, add_to_allowed_clients,
                         generate_android_page, generate_qr_code, schedule_wipe)
    # Atomic claim FIRST — defends against email-scanner prefetch races
    # (Gmail, Outlook ATP, Mimecast, Proofpoint all prefetch link contents).
    pending = _load_pending()
    entry = pending.pop(token, None)
    if not entry:
        return "Confirmation link expired or already used.", 410
    try:
        with open(_PENDING_FILE, "w") as _f:
            _json.dump(pending, _f)
    except Exception: pass
    if _t.time() - entry.get("created_at", 0) > 24 * 3600:
        return "This link expired. Please sign up again.", 410

    email = entry["email"]
    # Double-check no one snuck a duplicate provisioning through
    try:
        with open("/var/log/harbor-customers.json") as f:
            for ln in f:
                try:
                    c = _json.loads(ln)
                except Exception: continue
                if c.get("email", "").lower() == email and c.get("status") == "active":
                    pending.pop(token, None)
                    _json.dump(pending, open(_PENDING_FILE, "w"))
                    return redirect("https://adblock.harborprivacy.com/already-member.html")
    except Exception: pass

    name = email.split("@")[0].capitalize()
    client_id = generate_client_id(name, email)
    plan = "trial"; plan_type = "light"

    create_adguard_client(client_id, name)
    add_to_allowed_clients(client_id)
    save_ios_profile(client_id, name)
    generate_android_page(client_id)
    generate_qr_code(client_id)

    profile_url = f"https://harborprivacy.com/profiles/{client_id}.mobileconfig"
    log_customer(client_id, name, email, plan, stripe_customer_id="",
                 plan_type=plan_type, is_trial=True, status="active")
    schedule_wipe(client_id, delay=30 * 24 * 3600)
    setup_url = f"https://dashboard.harborprivacy.com/setup?email={email}&st={_setup_token_for(email) or ''}"
    send_welcome_email(email, name, client_id, plan,
                       profile_url=profile_url, plan_type=plan_type,
                       setup_url=setup_url)

    # Token was already claimed above; redirect to /setup on the dashboard
    # subdomain. Cookie alone wouldn't cross subdomains so we also set
    # domain=.harborprivacy.com, and the URL carries email+st (HMAC) as a
    # fallback if the cookie is stripped en route.
    st = _setup_token_for(email) or ""
    auth = make_token(email, is_admin=False)
    setup_redirect = f"https://dashboard.harborprivacy.com/setup?email={email}&st={st}"
    resp = make_response(redirect(setup_redirect))
    resp.set_cookie("hp_token", auth, domain=".harborprivacy.com",
                    httponly=True, secure=True, samesite="Lax", max_age=86400)
    return resp



# ── ROUTES: CONTACT FORM ────────────────────────────────────
_CONTACT_ATTEMPTS = {}  # ip -> [ts...]
def _contact_rate_ok(ip, limit=3, window=3600):
    import time as _t
    now = _t.time()
    rec = [t for t in _CONTACT_ATTEMPTS.get(ip, []) if (now - t) < window]
    _CONTACT_ATTEMPTS[ip] = rec
    return len(rec) < limit

@app.route("/api/contact", methods=["POST", "OPTIONS"])
def api_contact():
    import time as _t, re as _re
    if request.method == "OPTIONS":
        r = make_response("", 204)
        r.headers["Access-Control-Allow-Origin"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        r.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return r
    data = request.get_json(silent=True) or request.form
    name = (data.get("name") or "").strip()[:120]
    email = (data.get("email") or "").strip().lower()[:254]
    phone = (data.get("phone") or "").strip()[:40]
    message = (data.get("message") or "").strip()[:5000]
    ip = request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()

    EMAIL_RE = _re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
    if not name or not email or not EMAIL_RE.match(email) or not message:
        return jsonify({"ok": False, "error": "Name, email, and message required."}), 400
    if not _contact_rate_ok(ip):
        return jsonify({"ok": False, "error": "Too many messages. Try again in an hour."}), 429
    # Honeypot
    if (data.get("website") or "").strip():
        log.warning(f"contact honeypot tripped from {ip}")
        return jsonify({"ok": True})  # silent success
    # Min fill time
    try: fts = int(data.get("fts") or 0)
    except: fts = 0
    if fts and (int(_t.time()*1000) - fts) < 3000:
        log.warning(f"contact fast-submit from {ip}")
        return jsonify({"ok": True})

    from webhook import send_email
    safe = lambda x: x.replace("<", "&lt;").replace(">", "&gt;")
    body = (f"<div style=\"font-family:sans-serif\">"
            f"<h3>New contact message</h3>"
            f"<p><b>Name:</b> {safe(name)}<br>"
            f"<b>Email:</b> {safe(email)}<br>"
            f"<b>Phone:</b> {safe(phone) or '(none)'}<br>"
            f"<b>IP:</b> {ip}</p>"
            f"<hr><pre style=\"white-space:pre-wrap;font-family:inherit\">{safe(message)}</pre>"
            f"</div>")
    ok = send_email("support@harborprivacy.com", f"Contact: {name}", body)
    resp = jsonify({"ok": bool(ok)})
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp, (200 if ok else 500)



# ── ROUTES: SECURITY + SYSTEM INFO WIDGETS ──────────────────
_SEC_CACHE = {"ts": 0, "data": None}
_SYS_CACHE = {"ts": 0, "data": None}

def _run_cscli(*args):
    import subprocess, json as _json
    try:
        r = subprocess.run(["sudo", "/usr/bin/cscli", *args, "-o", "json"],
                           capture_output=True, timeout=8, text=True)
        return _json.loads(r.stdout) if r.stdout.strip() else []
    except Exception:
        return []

@app.route("/api/security-status")
def api_security_status():
    import time as _t
    now = _t.time()
    if _SEC_CACHE["data"] and (now - _SEC_CACHE["ts"]) < 30:
        d = _SEC_CACHE["data"]
    else:
        decisions = _run_cscli("decisions", "list")
        alerts_24h = _run_cscli("alerts", "list", "--since", "24h")
        # Decisions list returns nested structure
        bans = []
        for a in decisions:
            for dec in a.get("decisions", []):
                if dec.get("type") == "ban":
                    bans.append({
                        "ip": dec.get("value"),
                        "scenario": dec.get("scenario", "").replace("crowdsecurity/", ""),
                        "country": a.get("source", {}).get("cn", "?"),
                        "duration": dec.get("duration", "")[:8],
                    })
        # Scenario counts in last 24h
        scn = {}
        for a in alerts_24h:
            name = (a.get("scenario") or "").replace("crowdsecurity/", "")
            if name: scn[name] = scn.get(name, 0) + 1
        top_scenarios = sorted(scn.items(), key=lambda x: -x[1])[:5]
        d = {
            "active_bans": len(bans),
            "bans": bans[:8],
            "alerts_24h": len(alerts_24h),
            "top_scenarios": top_scenarios,
            "updated": int(now),
        }
        _SEC_CACHE.update({"ts": now, "data": d})
    resp = jsonify(d)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

@app.route("/api/system-info")
def api_system_info():
    import time as _t, os as _os, shutil as _sh, subprocess as _sp
    now = _t.time()
    if _SYS_CACHE["data"] and (now - _SYS_CACHE["ts"]) < 15:
        d = _SYS_CACHE["data"]
    else:
        # uptime
        try:
            with open("/proc/uptime") as f: up_sec = float(f.read().split()[0])
        except: up_sec = 0
        days = int(up_sec // 86400); hours = int((up_sec % 86400) // 3600); mins = int((up_sec % 3600) // 60)
        uptime_str = (f"{days}d " if days else "") + f"{hours}h {mins}m"
        # load
        try: la = _os.getloadavg()
        except: la = (0, 0, 0)
        # memory
        mem = {}
        try:
            for ln in open("/proc/meminfo"):
                k, v = ln.split(":")
                mem[k.strip()] = int(v.split()[0]) * 1024
        except: pass
        mem_total = mem.get("MemTotal", 1); mem_avail = mem.get("MemAvailable", 0)
        mem_used_pct = round((mem_total - mem_avail) / mem_total * 100, 1)
        # disk
        try:
            du = _sh.disk_usage("/")
            disk_pct = round(du.used / du.total * 100, 1)
            disk_used_gb = round(du.used / 1024**3, 1); disk_total_gb = round(du.total / 1024**3, 1)
        except: disk_pct = 0; disk_used_gb = disk_total_gb = 0
        # services
        services = ["harbor-dashboard","harbor-booking","harbor-fax","harbor-webhook",
                    "harbor-career","brazer-dashboard","nginx","crowdsec",
                    "crowdsec-firewall-bouncer","fail2ban","AdGuardHome"]
        svc = {}
        for sv in services:
            try:
                r = _sp.run(["systemctl","is-active",sv],capture_output=True,timeout=2,text=True)
                svc[sv] = r.stdout.strip()
            except: svc[sv] = "?"
        d = {
            "uptime": uptime_str,
            "load": {"1m": round(la[0],2), "5m": round(la[1],2), "15m": round(la[2],2)},
            "mem_pct": mem_used_pct,
            "mem_used_gb": round((mem_total - mem_avail) / 1024**3, 1),
            "mem_total_gb": round(mem_total / 1024**3, 1),
            "disk_pct": disk_pct,
            "disk_used_gb": disk_used_gb,
            "disk_total_gb": disk_total_gb,
            "services": svc,
            "updated": int(now),
        }
        _SYS_CACHE.update({"ts": now, "data": d})
    resp = jsonify(d)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

_INTEG_CACHE = {"ts": 0, "data": None}

@app.route("/api/integrity")
def api_integrity():
    import time as _t, os as _os, json as _j
    now = _t.time()
    if _INTEG_CACHE["data"] and (now - _INTEG_CACHE["ts"]) < 60:
        d = _INTEG_CACHE["data"]
    else:
        path = "/var/log/harbor-integrity.json"
        d = {"aide": None, "rkhunter": None, "chkrootkit": None, "updated": int(now)}
        try:
            if _os.path.exists(path):
                with open(path) as f: d.update(_j.load(f))
        except Exception as e:
            d["error"] = str(e)
        _INTEG_CACHE.update({"ts": now, "data": d})
    resp = jsonify(d)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp


@app.route("/api/social/post-to-make", methods=["POST"])
@admin_required
def post_to_make():
    import requests as _req
    data = request.json or {}
    image_url = data.get("image_url", "")
    facebook_text = data.get("facebook_text", "")
    instagram_text = data.get("instagram_text", "")
    brand = data.get("brand", "harbor")
    MAKE_WEBHOOK = "https://hook.us2.make.com/decgvbes5ixew3jqibnt5gr30ps7t3as"
    try:
        r = _req.post(MAKE_WEBHOOK, json={
            "image_url": image_url,
            "facebook_text": facebook_text,
            "instagram_text": instagram_text,
            "brand": brand
        }, timeout=30)
        return jsonify({"ok": True, "status": r.status_code})
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ════════════════════════════════════════════════════════════
# SECTION 20 — ROUTES: SOCIAL AUTOPOST
# /api/social/autopost — cron-fired, protected by AUTOPOST_SECRET
# Cycles through brands (harbor/career/fax/booking) and topics
# ════════════════════════════════════════════════════════════

@app.route("/api/social/autopost", methods=["POST"])
def social_autopost():
    import requests as _req, json as _json
    secret = request.headers.get("X-Autopost-Secret", "")
    expected = os.environ.get("AUTOPOST_SECRET", "")
    if not expected:
        log.error("AUTOPOST_SECRET not set — rejecting autopost")
        return jsonify({"error": "server misconfigured"}), 503
    if not secrets.compare_digest(secret, expected):
        return jsonify({"error": "unauthorized"}), 401
    import random as _random
    _brand_cycle = ["harbor", "career", "fax", "booking", "money"]
    brand = request.json.get("brand") if request.json and request.json.get("brand") else _random.choice(_brand_cycle)
    topics_harbor = [
        "ISP tracking your browsing history",
        "ad blocking on every home device",
        "kids online safety and parental controls",
        "malware and phishing protection",
        "home network privacy without tech knowledge",
        "trackers following you across every device",
        "why incognito mode is not actually private",
        "smart TVs spying on your viewing habits",
        "why your router is not protecting you",
        "DNS privacy and why it matters",
        "blocking ads before they load on every device",
        "parental controls that actually work at the network level",
        "what your ISP knows about your family",
        "gaming consoles and privacy risks",
        "how advertisers track you across every device",
        "why public WiFi is dangerous and how to stay safe",
        "what happens to your data when you use free apps",
    ]
    topics_booking = [
        "let clients book appointments online 24/7",
        "stop losing customers to phone tag",
        "employee scheduling that actually works",
        "time tracking for small business owners",
        "PTO management without spreadsheets",
        "shift scheduling made simple",
        "reduce no-shows with automatic reminders",
        "one app for booking and employee scheduling",
        "free booking software for small businesses",
        "how Harbor Booking compares to Calendly",
        "salon scheduling software that is actually free",
        "medical office scheduling made simple",
        "restaurant staff scheduling without the headache",
        "how to set up online booking in 5 minutes",
        "why your business needs online booking in 2026",
    ]
    topics_career = [
        "ATS resume filtering",
        "tailoring your resume to the job description",
        "cover letter that actually matches the job posting",
        "why you are not hearing back after applying",
        "AI resume review and feedback",
        "privacy when using AI career tools",
        "job search data privacy",
        "how to write a cover letter that gets interviews",
        "resume keywords that beat ATS screening",
        "why generic cover letters get ignored",
        "how to explain a career gap on your resume",
        "the 6-second resume rule and how to beat it",
        "tailoring your resume for remote jobs",
        "what recruiters actually look for in a resume",
        "how AI is changing the job application process",
    ]
    topics_fax = [
        "send a fax anonymously without an account",
        "HIPAA conduit exception and what it means for medical records",
        "why lawyers still use fax in 2026",
        "send medical records without a fax machine",
        "no phone line needed to send a fax",
        "your fax document is deleted the moment it delivers",
        "anonymous fax for legal documents",
        "privacy-first faxing for healthcare professionals",
        "why fax is still the most trusted way to send sensitive documents",
        "send a fax from your phone in under 2 minutes",
        "no account required to send a fax",
        "how to send medical records securely",
        "HIPAA-friendly fax service with no stored documents",
    ]
    topics_money = [
        "budgeting without giving up your bank login",
        "why Plaid is a privacy risk",
        "track spending by forwarding receipts and bank alerts",
        "the YNAB and Mint problem -- they need your bank password",
        "savings goals without a bank connection",
        "privacy-first personal finance",
        "what happens to your bank login when a budgeting app dies",
        "categorize spending automatically from email",
        "private alternative to Mint and YNAB",
        "why most budgeting apps sell your spending data",
        "set up budgeting in 5 minutes with no bank credentials",
        "track multiple credit cards from one inbox",
    ]
    import random
    if brand == "career":
        topic = random.choice(topics_career)
    elif brand == "fax":
        topic = random.choice(topics_fax)
    elif brand == "booking":
        topic = random.choice(topics_booking)
    elif brand == "money":
        topic = random.choice(topics_money)
    else:
        topic = random.choice(topics_harbor)
    platforms = {"facebook": True, "instagram": True, "linkedin": True}
    prompt, platform_keys = _build_post_prompt(brand, topic, platforms)
    try:
        r = _req.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": os.environ.get("ANTHROPIC_API_KEY",""), "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-haiku-4-5-20251001", "max_tokens": 600, "messages": [{"role": "user", "content": prompt}]},
            timeout=30)
        content = r.json()["content"][0]["text"]
        content = content.strip().lstrip("```json").rstrip("```").strip()
        posts = _json.loads(content)
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    image_url = _generate_image_claude(brand, topic)
    if not image_url:
        image_url = _generate_image_openai(brand, topic)
    log_path = f"/var/log/harbor-autopost-{brand}.json"
    try:
        with open(log_path, "w") as f:
            _json.dump({"topic": topic, "brand": brand, "posts": posts, "image_url": image_url}, f)
    except Exception:
        pass

    # Forward to Make.com webhook for FB and IG posting
    make_url = "https://hook.us2.make.com/decgvbes5ixew3jqibnt5gr30ps7t3as"
    fb_text = posts.get("facebook", "")
    ig_text = posts.get("instagram", "")
    make_errors = []

    if fb_text and image_url:
        try:
            _req.post(make_url, json={"text": fb_text, "image_url": image_url, "platform": "facebook"}, timeout=30)
        except Exception as e:
            make_errors.append(f"fb: {str(e)}")

    if ig_text and image_url:
        try:
            _req.post(make_url, json={"text": ig_text, "image_url": image_url, "platform": "instagram"}, timeout=30)
        except Exception as e:
            make_errors.append(f"ig: {str(e)}")

    return jsonify({"ok": True, "topic": topic, "posts": posts, "image_url": image_url, "make_errors": make_errors})

@app.route("/api/social/status")
@admin_required
def social_status():
    enabled = not os.path.exists("/var/log/harbor-social-paused")
    return jsonify({"enabled": enabled})

@app.route("/api/social/toggle", methods=["POST"])
@admin_required
def social_toggle():
    paused = "/var/log/harbor-social-paused"
    if os.path.exists(paused):
        os.remove(paused)
        return jsonify({"enabled": True})
    else:
        open(paused, 'w').close()
        return jsonify({"enabled": False})

SOCIAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Social Scheduler -- Harbor Privacy</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Serif+Display:ital@0;1&family=DM+Sans:wght@300;400;500&display=swap" rel="stylesheet">
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<link rel="manifest" href="/social-app.webmanifest">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
<meta name="apple-mobile-web-app-title" content="HP Social">
<meta name="theme-color" content="#00e5c0">
<link rel="apple-touch-icon" href="/social-icon-192.png">
<script>
if ("serviceWorker" in navigator) {
  navigator.serviceWorker.register("/social-sw.js").catch(function(){});
}
(function(){
  var TOKEN = "{{ csrf_token }}";
  window.__CSRF = TOKEN;
  var _f = window.fetch;
  window.__originalFetch = _f;
  window.__refreshCSRF = async function(){
    try {
      var r = await _f("/api/csrf", {credentials:"same-origin"});
      var j = await r.json();
      if (j && j.csrf) { window.__CSRF = j.csrf; return j.csrf; }
    } catch(e){}
    return "";
  };
  window.fetch = async function(url, opts){
    opts = opts || {};
    var m = (opts.method || 'GET').toUpperCase();
    if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') {
      var u = String(url || '');
      if (u.charAt(0) === '/' || u.indexOf(location.origin) === 0) {
        opts.headers = opts.headers || {};
        var cur = window.__CSRF || "";
        if (!cur) cur = await window.__refreshCSRF();
        if (!opts.headers['X-CSRF'] && !opts.headers['x-csrf']) opts.headers['X-CSRF'] = cur;
        if (!opts.headers['X-CSRF']) opts.headers['X-CSRF'] = cur;
        if (opts.credentials === undefined) opts.credentials = 'same-origin';
        var resp = await _f(url, opts);
        if (resp.status === 403) {
          var fresh = await window.__refreshCSRF();
          if (fresh) {
            opts.headers['X-CSRF'] = fresh;
            return _f(url, opts);
          }
        }
        return resp;
      }
    }
    return _f(url, opts);
  };
})();
</script>
<style>
:root{--bg:#0a0e0f;--surface:#111618;--border:#1e2a2d;--accent:#00e5c0;--text:#e8f0ef;--muted:#6b8a87;--accent-hover:#00ffda;}
.career-mode{--bg:#f7f9f8;--surface:#ffffff;--border:#d4e8e2;--accent:#34d399;--text:#0f2921;--muted:#4b7263;}
.tim-mode{--bg:#0f1923;--surface:#121e28;--border:#1e3040;--accent:#4a9edd;--text:#e8eef3;--muted:#7a9bb5;}
.booking-mode{--bg:#0f0e09;--surface:#1a1700;--border:#2a2510;--accent:#f59e0b;--text:#f5f0e8;--muted:#8a7d5a;}
*{box-sizing:border-box;margin:0;padding:0;}
body{background:var(--bg);color:var(--text);font-family:"DM Sans",sans-serif;line-height:1.7;transition:background 0.3s,color 0.3s;}
body::before{content:"";position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:0.3;pointer-events:none;z-index:0;}
nav{padding:0;border-bottom:1px solid var(--border);position:sticky;top:0;z-index:10;background:var(--surface);}
.nav-top{display:flex;align-items:center;justify-content:space-between;padding:14px 24px;border-bottom:1px solid var(--border);}
.logo{font-family:"DM Mono",monospace;font-size:14px;color:var(--accent);letter-spacing:0.1em;text-decoration:none;}
.logo span{color:var(--muted);}
.nav-links{display:flex;gap:20px;align-items:center;padding:10px 24px;}
.nav-links a{font-family:"DM Mono",monospace;font-size:11px;color:var(--muted);text-decoration:none;letter-spacing:0.06em;}
.nav-links a:hover,.nav-links a.active{color:var(--accent);}
.badge-admin{background:#7c3aed;color:#fff;font-family:"DM Mono",monospace;font-size:9px;padding:2px 8px;letter-spacing:0.1em;}
.container{max-width:860px;margin:0 auto;padding:32px 20px;position:relative;z-index:1;}
h1{font-family:"DM Serif Display",serif;font-size:34px;font-weight:400;margin-bottom:6px;}
.sub{color:var(--muted);font-size:14px;margin-bottom:28px;}
.card{background:var(--surface);border:1px solid var(--border);padding:24px;margin-bottom:20px;border-radius:10px;}
label{font-family:"DM Mono",monospace;font-size:11px;color:var(--accent);letter-spacing:0.15em;display:block;margin-bottom:10px;}
input,textarea,select{width:100%;background:var(--bg);border:1px solid var(--border);color:var(--text);font-family:"DM Mono",monospace;font-size:13px;padding:10px 14px;margin-bottom:16px;outline:none;border-radius:2px;}
input:focus,textarea:focus{border-color:var(--accent);}
.btn{background:var(--accent);color:var(--bg);border:none;padding:14px 28px;font-family:"DM Mono",monospace;font-size:13px;letter-spacing:0.08em;cursor:pointer;font-weight:700;border-radius:8px;transition:opacity 0.2s;}
.btn:hover{opacity:0.88;}
.btn:disabled{background:var(--muted);cursor:not-allowed;opacity:0.6;}
.btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);padding:12px 20px;font-family:"DM Mono",monospace;font-size:11px;cursor:pointer;border-radius:2px;transition:all 0.2s;}
.btn-outline:hover{border-color:var(--accent);color:var(--accent);}
.btn-copy{background:transparent;border:1px solid var(--accent);color:var(--accent);padding:10px 18px;font-family:"DM Mono",monospace;font-size:11px;cursor:pointer;border-radius:2px;margin-top:8px;transition:background 0.2s;}
.btn-copy:hover{background:rgba(0,229,192,0.08);}
.btn-linkedin{background:#0a66c2;color:#fff;border:none;padding:14px 24px;font-family:"DM Mono",monospace;font-size:11px;letter-spacing:0.08em;cursor:pointer;border-radius:2px;display:inline-flex;align-items:center;gap:8px;font-weight:600;transition:background 0.2s;}
.btn-linkedin:hover{background:#0958a8;}
.btn-linkedin svg{width:16px;height:16px;fill:#fff;flex-shrink:0;}
.post-box{background:var(--bg);border:1px solid var(--border);padding:16px;font-size:14px;color:var(--text);line-height:1.7;white-space:pre-wrap;min-height:80px;margin-bottom:8px;border-radius:2px;cursor:text;}
.post-box:focus{outline:1px solid var(--accent);}
.img-preview{width:100%;max-width:360px;border:1px solid var(--border);display:block;margin:12px 0;border-radius:2px;}
.platform-label{font-family:"DM Mono",monospace;font-size:10px;color:var(--muted);letter-spacing:0.15em;margin-bottom:8px;}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid var(--border);border-top-color:var(--accent);border-radius:50%;animation:spin 0.8s linear infinite;vertical-align:middle;margin-right:8px;}
@keyframes spin{to{transform:rotate(360deg);}}
.topics{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:14px;}
.topic-chip{background:transparent;border:1px solid var(--border);color:var(--muted);padding:9px 16px;font-family:"DM Mono",monospace;font-size:12px;cursor:pointer;letter-spacing:0.04em;border-radius:8px;transition:all 0.15s;}
.topic-chip:hover,.topic-chip.selected{border-color:var(--accent);color:var(--accent);background:rgba(0,229,192,0.05);}
.brand-switcher{display:grid;grid-template-columns:repeat(5,1fr);gap:0;margin-bottom:28px;border:1px solid var(--border);border-radius:10px;overflow:hidden;}
.brand-btn{padding:13px 6px;font-family:"DM Mono",monospace;font-size:11px;letter-spacing:0.06em;cursor:pointer;border:none;border-right:1px solid var(--border);background:transparent;color:var(--muted);transition:all 0.2s;white-space:nowrap;}
.brand-btn:last-child{border-right:none;}
.brand-btn.active{background:var(--accent);color:var(--bg);font-weight:600;}
.platform-row{display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);}
.platform-row:last-child{border-bottom:none;}
.platform-name{font-size:14px;color:var(--text);display:flex;align-items:center;gap:8px;}
.platform-icon{font-size:16px;}
.toggle-btn{font-family:"DM Mono",monospace;font-size:10px;padding:6px 16px;border:1px solid var(--accent);color:var(--accent);background:transparent;cursor:pointer;border-radius:2px;letter-spacing:0.1em;transition:all 0.2s;min-width:48px;}
.toggle-btn.off{border-color:var(--border);color:var(--muted);}
.results-grid{display:grid;gap:20px;}
.platform-card{background:var(--bg);border:1px solid var(--border);border-radius:10px;padding:18px;}
.action-bar{display:flex;gap:10px;flex-wrap:wrap;align-items:center;margin-top:20px;padding-top:20px;border-top:1px solid var(--border);}
.status-msg{font-family:monospace;font-size:12px;color:var(--muted);flex:1;min-width:0;}
.status-msg.ok{color:var(--accent);}
.status-msg.err{color:#f87171;}
.autopost-bar{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;}
.char-count{font-family:"DM Mono",monospace;font-size:10px;color:var(--muted);text-align:right;margin-top:4px;}
</style>
</head>
<body>
<nav>
  <div class="nav-top">
    <a href="/admin" class="logo">harbor<span>/</span>privacy</a>
    <span class="badge-admin">ADMIN</span>
  </div>
  <div class="nav-links">
    <a href="https://harborprivacy.com" style="font-size:10px;">&#8592; Site</a>
    <a href="/admin">Customers</a>
    <a href="/social" class="active">Social</a>
    <a href="/settings">Settings</a>
    <a href="/logout" style="margin-left:auto;">Sign Out</a>
  </div>
</nav>

<div class="container">
  <h1 id="pageTitle">Social Scheduler</h1>
  <p class="sub" id="pageSub">Generate posts for Facebook, Instagram, and LinkedIn.</p>

  <!-- Brand tabs -->
  <div class="brand-switcher">
    <button class="brand-btn active" id="btnHarbor" onclick="setBrand('harbor')">HARBOR DNS</button>
    <button class="brand-btn" id="btnCareer" onclick="setBrand('career')">CAREER</button>
    <button class="brand-btn" id="btnFax" onclick="setBrand('fax')">FAX</button>
    <button class="brand-btn" id="btnBooking" onclick="setBrand('booking')">BOOKING</button>
    <button class="brand-btn" id="btnMoney" onclick="setBrand('money')">MONEY</button>
    <button class="brand-btn" id="btnTim" onclick="setBrand('tim')">TIM BRAZER</button>
    <button class="brand-btn" id="btnAuto" onclick="setBrand('auto')">AUTO</button>
  </div>

  <!-- Auto-post toggle (hidden for tim brand) -->
  <div class="card" id="autopostCard">
    <div class="autopost-bar">
      <div>
        <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;margin-bottom:4px;">DAILY AUTO-POST</div>
        <div style="font-size:13px;color:var(--muted);" id="autoPostLabel">Loading...</div>
      </div>
      <button id="toggleBtn" onclick="toggleAutoPost()" style="background:transparent;border:1px solid var(--border);color:var(--muted);padding:10px 20px;font-family:'DM Mono',monospace;font-size:11px;cursor:pointer;letter-spacing:0.08em;">...</button>
    </div>
  </div>

  <!-- Compose card -->
  <div class="card">
    <label>TOPIC</label>
    <div class="topics" id="topicChips"></div>
    <input type="text" id="topicInput" placeholder="Or type a custom topic...">

    <label style="margin-top:4px;">PLATFORMS</label>
    <div id="platformRows">
      <div class="platform-row" id="rowFacebook">
        <span class="platform-name"><span class="platform-icon">&#128196;</span> Facebook</span>
        <button onclick="togglePlatform(this,'facebook')" data-platform="facebook" data-on="true" class="toggle-btn">ON</button>
      </div>
      <div class="platform-row" id="rowInstagram">
        <span class="platform-name"><span class="platform-icon">&#128247;</span> Instagram</span>
        <button onclick="togglePlatform(this,'instagram')" data-platform="instagram" data-on="true" class="toggle-btn">ON</button>
      </div>
      <div class="platform-row" id="rowLinkedin">
        <span class="platform-name"><span class="platform-icon">&#128188;</span> LinkedIn</span>
        <button onclick="togglePlatform(this,'linkedin')" data-platform="linkedin" data-on="false" class="toggle-btn off">OFF</button>
      </div>
    </div>

    <div style="margin-top:20px;">
      <button class="btn" id="generateBtn" onclick="generate()" style="width:100%;padding:16px;">&#9889; Generate Post</button>
    </div>
  </div>

  <!-- Results -->
  <div id="resultsCard" style="display:none;">

    <!-- Image first on mobile (hidden: image generation disabled) -->
    <div class="card" id="imgCard" style="display:none;">
      <div class="platform-label" style="margin-bottom:12px;">GENERATED IMAGE</div>
      <div id="imgLoading" style="font-family:monospace;font-size:12px;color:var(--muted);display:none;padding:20px 0;"><span class="spinner"></span>Generating image...</div>
      <div id="imgOverlayWrap" style="display:none;position:relative;width:100%;border-radius:10px;overflow:hidden;aspect-ratio:1/1;">
        <img id="imgPreview" style="width:100%;height:100%;object-fit:cover;display:block;">
        <div id="imgOverlay" style="position:absolute;inset:0;display:flex;flex-direction:column;justify-content:flex-start;align-items:flex-start;padding:14px;">
          <div id="imgOverlayTop" style="font-family:'DM Mono',monospace;font-size:10px;letter-spacing:0.15em;color:rgba(255,255,255,0.9);text-transform:uppercase;background:rgba(0,0,0,0.35);padding:4px 10px;border-radius:20px;">harbor privacy</div>
          <div id="imgOverlayHook" style="display:none;"></div>
          <div id="imgOverlaySub" style="display:none;"></div>
        </div>
      </div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;">
        <a id="imgDownload" class="btn-copy" style="display:none;text-decoration:none;" download="harbor-post.png">&#8595; Download</a>
      </div>
    </div>

    <!-- Platform results -->
    <div class="results-grid">
      <div class="platform-card" id="fbSection">
        <div class="platform-label">&#128196; FACEBOOK</div>
        <div class="post-box" id="fbPost" contenteditable="true"></div>
        <div class="char-count" id="fbCount">0 chars</div>
        <button class="btn-copy" onclick="copyText('fbPost', this)">Copy</button>
      </div>
      <div class="platform-card" id="igSection">
        <div class="platform-label">&#128247; INSTAGRAM</div>
        <div class="post-box" id="igPost" contenteditable="true"></div>
        <div class="char-count" id="igCount">0 chars</div>
        <button class="btn-copy" onclick="copyText('igPost', this)">Copy</button>
      </div>
      <div class="platform-card" id="liSection">
        <div class="platform-label">&#128188; LINKEDIN</div>
        <div class="post-box" id="liPost" contenteditable="true"></div>
        <div class="char-count" id="liCount">0 chars</div>
        <div style="display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;align-items:center;">
          <button class="btn-copy" onclick="copyText('liPost', this)">Copy</button>
          <button class="btn-linkedin" onclick="openLinkedIn()">
            <svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/></svg>
            Open LinkedIn
          </button>
        </div>
      </div>
    </div>

    <!-- Action bar -->
    <div class="card" style="margin-top:20px;">
      <div class="action-bar">
        <button class="btn-outline" onclick="generate()">&#8635; Regenerate</button>
        <button class="btn" id="postMakeBtn" onclick="postToMake()" id="fbigOnly" style="display:none;">&#8679; Post FB + IG</button>
        <span class="status-msg" id="makeStatus"></span>
      </div>
    </div>
  </div>
</div>

<script>
var currentBrand = "harbor";
var currentImageUrl = "";

var harborTopics = [
  "ISP selling your browsing history",
  "ad blockers only work on one device",
  "kids tablet tracking",
  "incognito mode myth",
  "smart TV data collection",
  "malware on home networks",
  "free trial offer"
];
var bookingTopics = [
  "let clients book appointments online 24/7",
  "stop losing customers to phone tag",
  "employee scheduling that actually works",
  "time tracking for small business owners",
  "PTO management without spreadsheets",
  "shift scheduling made simple",
  "reduce no-shows with automatic reminders",
  "one app for booking and employee scheduling",
  "free booking software for small businesses",
  "salon scheduling software that is actually free",
  "medical office scheduling made simple",
  "how to set up online booking in 5 minutes",
  "why your business needs online booking in 2026"
];
var careerTopics = [
  "ATS filtering out your resume",
  "sending the same resume everywhere",
  "blank cover letter problem",
  "AI tools storing your resume data",
  "not hearing back after applying",
  "resume keyword matching",
  "job search privacy"
];
var faxTopics = [
  "Send a fax anonymously -- no account needed",
  "HIPAA conduit exception explained",
  "Why lawyers still fax in 2026",
  "Send medical records from your phone",
  "No phone line needed",
  "Your fax document is deleted on delivery",
  "Anonymous fax for legal documents",
  "Privacy-first faxing for healthcare"
];
var timTopics = [
  "Servant leadership in healthcare operations",
  "Why front-end ops make or break revenue cycle",
  "20 years in diagnostic imaging -- what I learned",
  "Epic Cadence and Radiant -- real world tips",
  "Building a privacy startup while job searching",
  "Healthcare operations and patient access",
  "MBA lessons applied to healthcare management",
  "Transformational leadership in multi-site ops",
  "Why I founded Harbor Privacy",
  "Practice administrator skills that matter most"
];
var moneyTopics = [
  "Budgeting without your bank login",
  "Why Plaid is a privacy risk",
  "Forward receipts -- we do the rest",
  "Private alternative to Mint and YNAB",
  "Track spending from email alerts",
  "Savings goals without a bank connection",
  "Categorize spending automatically",
  "What happens when a budgeting app dies"
];

function setBrand(brand) {
  currentBrand = brand;
  var isCareer = brand === "career";
  var isTim = brand === "tim";
  var isAuto = brand === "auto";
  var isBooking = brand === "booking";
  document.body.className = isCareer ? "career-mode" : isTim ? "tim-mode" : isBooking ? "booking-mode" : "";
  ["harbor","booking","career","fax","money","tim","auto"].forEach(function(b) {
    document.getElementById("btn" + b.charAt(0).toUpperCase() + b.slice(1)).className =
      "brand-btn" + (brand === b ? " active" : "");
  });
  var titles = {
    harbor: ["Social Scheduler", "Harbor Privacy DNS -- Facebook & Instagram."],
    booking: ["Harbor Booking", "Scheduling app posts -- small business, appointments, workforce."],
    career: ["Career by Harbor", "Career tool posts -- light theme, problem-first."],
    fax: ["Harbor Fax", "Fax service posts -- anonymous, HIPAA, privacy angle."],
    money: ["Harbor Money", "Budgeting without bank logins -- privacy-first personal finance."],
    tim: ["Tim Brazer", "Personal LinkedIn content -- healthcare ops & leadership."],
    booking: ["Harbor Booking", "Free scheduling platform -- salons, clinics, small business."],
    auto: ["Auto-Post", "Daily automated posting settings."]
  };
  document.getElementById("pageTitle").textContent = titles[brand][0];
  document.getElementById("pageSub").textContent = titles[brand][1];
  // Topic chips
  var topicMap = {harbor: harborTopics, career: careerTopics, fax: faxTopics, booking: bookingTopics, money: moneyTopics, tim: timTopics, auto: []};
  renderChips(topicMap[brand] || []);
  if ((topicMap[brand] || []).length) document.getElementById("topicInput").value = topicMap[brand][0];
  // Platform toggles for tim -- LinkedIn only on by default
  if (isBooking) {
    setPlatformVisible("facebook", true);
    setPlatformVisible("instagram", true);
    setPlatformVisible("linkedin", true);
    setPlatformOn("facebook", true);
    setPlatformOn("instagram", true);
    setPlatformOn("linkedin", false);
  } else if (isTim) {
    setPlatformVisible("facebook", false);
    setPlatformVisible("instagram", false);
    setPlatformVisible("linkedin", true);
    setPlatformOn("linkedin", true);
  } else {
    setPlatformVisible("facebook", true);
    setPlatformVisible("instagram", true);
    setPlatformVisible("linkedin", brand !== "harbor");
    setPlatformOn("facebook", true);
    setPlatformOn("instagram", true);
  }
  // Post button visibility
  document.getElementById("postMakeBtn").style.display = (isTim || isBooking) ? "none" : "inline-flex";
  document.getElementById("autopostCard").style.display = (isTim || isBooking || isAuto) ? "none" : "block";
  document.getElementById("resultsCard").style.display = "none";
}

function setPlatformVisible(p, show) {
  var row = document.getElementById("row" + p.charAt(0).toUpperCase() + p.slice(1));
  if (row) row.style.display = show ? "flex" : "none";
}
function setPlatformOn(p, on) {
  var btn = document.querySelector("[data-platform='" + p + "']");
  if (!btn) return;
  btn.dataset.on = on.toString();
  btn.textContent = on ? "ON" : "OFF";
  btn.className = "toggle-btn" + (on ? "" : " off");
}

function renderChips(topics) {
  var el = document.getElementById("topicChips");
  el.innerHTML = "";
  topics.forEach(function(t) {
    var btn = document.createElement("button");
    btn.className = "topic-chip";
    btn.textContent = t;
    btn.onclick = function() {
      document.querySelectorAll(".topic-chip").forEach(function(c){c.classList.remove("selected");});
      btn.classList.add("selected");
      document.getElementById("topicInput").value = t;
    };
    el.appendChild(btn);
  });
}

function togglePlatform(btn, platform) {
  var on = btn.dataset.on === "true";
  btn.dataset.on = (!on).toString();
  btn.textContent = on ? "OFF" : "ON";
  btn.className = "toggle-btn" + (on ? " off" : "");
}

function updateCharCount(boxId, countId, limit) {
  var text = document.getElementById(boxId).textContent || "";
  var el = document.getElementById(countId);
  el.textContent = text.length + " chars" + (limit ? " / " + limit : "");
  el.style.color = (limit && text.length > limit) ? "#f87171" : "var(--muted)";
}

async function generate() {
  var btn = document.getElementById("generateBtn");
  var topic = document.getElementById("topicInput").value || harborTopics[0];
  var platforms = {};
  document.querySelectorAll("[data-platform]").forEach(function(b) {
    platforms[b.dataset.platform] = b.dataset.on === "true";
  });
  // Tim brand always LinkedIn only
  if (currentBrand === "tim") { platforms = {facebook: false, instagram: false, linkedin: true}; }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Generating...';
  document.getElementById("resultsCard").style.display = "none";
  document.getElementById("imgLoading").style.display = "none";
  document.getElementById("imgPreview").style.display = "none";
  document.getElementById("imgDownload").style.display = "none";
  document.getElementById("makeStatus").textContent = "";
  document.getElementById("makeStatus").className = "status-msg";

  try {
    var r = await fetch("/api/social/generate", {
      method: "POST",
      headers: {"Content-Type":"application/json","X-CSRF":window.__CSRF||""},
      credentials: "same-origin",
      body: JSON.stringify({topic: topic, brand: currentBrand, platforms: platforms, csrf: window.__CSRF||""})
    });
    if (!r.ok) {
      var errText = "";
      try { var err = await r.json(); errText = err.error || ("HTTP " + r.status); } catch(e) { errText = "HTTP " + r.status; }
      document.getElementById("makeStatus").className = "status-msg error";
      document.getElementById("makeStatus").textContent = "Generate failed: " + errText;
      document.getElementById("generateBtn").disabled = false;
      document.getElementById("generateBtn").innerHTML = "Generate Posts";
      return;
    }
    var data = await r.json();
    var showFb = platforms.facebook !== false;
    var showIg = platforms.instagram !== false;
    var showLi = platforms.linkedin === true;
    document.getElementById("fbSection").style.display = showFb ? "block" : "none";
    document.getElementById("igSection").style.display = showIg ? "block" : "none";
    document.getElementById("liSection").style.display = showLi ? "block" : "none";
    if (showFb) { document.getElementById("fbPost").textContent = data.facebook || ""; updateCharCount("fbPost","fbCount",63206); }
    if (showIg) { document.getElementById("igPost").textContent = data.instagram || ""; updateCharCount("igPost","igCount",2200); }
    if (showLi) { document.getElementById("liPost").textContent = data.linkedin || ""; updateCharCount("liPost","liCount",3000); }
    document.getElementById("resultsCard").style.display = "block";
    document.getElementById("imgLoading").style.display = "none";
    // Image generation disabled (Gemini free-tier quota exhausted) -- always hide
    document.getElementById("imgCard").style.display = "none";
    if (data.image_url && currentBrand !== "tim") {
      var img = document.getElementById("imgPreview");
      // Pull text before setting src so it's ready when image loads
      var fbText = document.getElementById("fbPost").textContent || "";
      var sentences = fbText.split(/(?<=[.!?])\s+/);
      var hook = sentences[0] || "";
      var sub = sentences[1] || "";
      document.getElementById("imgOverlayHook").textContent = hook;
      document.getElementById("imgOverlaySub").textContent = sub;
      var brandLabels = {harbor:"harbor privacy", career:"career by harbor", fax:"harbor fax", booking:"harbor booking", tim:"tim brazer", auto:"harbor privacy"};
      document.getElementById("imgOverlayTop").textContent = brandLabels[currentBrand] || "harbor privacy";
      img.onerror = function() { document.getElementById("imgOverlayWrap").style.display="block"; document.getElementById("imgOverlayWrap").textContent="Image load failed."; };
      img.onload = function() {
        document.getElementById("imgOverlayWrap").style.display = "block";
        currentImageUrl = data.image_url;
        // Canvas composite for download
        var dl = document.getElementById("imgDownload");
        var canvas = document.createElement("canvas");
        canvas.width = img.naturalWidth;
        canvas.height = img.naturalHeight;
        var ctx = canvas.getContext("2d");
        ctx.drawImage(img, 0, 0);
        // Gradient scrim
        var grad = ctx.createLinearGradient(0, 0, 0, canvas.height);
        grad.addColorStop(0, "rgba(0,0,0,0.18)");
        grad.addColorStop(0.3, "rgba(0,0,0,0.05)");
        grad.addColorStop(0.7, "rgba(0,0,0,0.55)");
        grad.addColorStop(1, "rgba(0,0,0,0.82)");
        ctx.fillStyle = grad;
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        // Brand label top
        ctx.fillStyle = "rgba(255,255,255,0.7)";
        ctx.font = "bold " + Math.round(canvas.width * 0.025) + "px monospace";
        ctx.fillText((brandLabels[currentBrand] || "harbor privacy").toUpperCase(), canvas.width * 0.06, canvas.height * 0.07);
        // Hook text bottom
        var hookSize = Math.round(canvas.width * 0.065);
        ctx.fillStyle = "#ffffff";
        ctx.font = "bold " + hookSize + "px serif";
        ctx.shadowColor = "rgba(0,0,0,0.5)";
        ctx.shadowBlur = 8;
        // Word wrap hook
        var words = hook.split(" ");
        var lines = [];
        var line = "";
        var maxW = canvas.width * 0.88;
        words.forEach(function(w) {
          var test = line + (line ? " " : "") + w;
          if (ctx.measureText(test).width > maxW && line) { lines.push(line); line = w; }
          else { line = test; }
        });
        if (line) lines.push(line);
        var lineH = hookSize * 1.25;
        var totalH = lines.length * lineH + (sub ? hookSize * 0.8 : 0);
        var startY = canvas.height * 0.78 - totalH / 2;
        lines.forEach(function(l, i) { ctx.fillText(l, canvas.width * 0.06, startY + i * lineH); });
        // Sub text
        if (sub) {
          ctx.font = Math.round(canvas.width * 0.038) + "px sans-serif";
          ctx.fillStyle = "rgba(255,255,255,0.85)";
          ctx.fillText(sub.length > 60 ? sub.substring(0,57)+"..." : sub, canvas.width * 0.06, startY + lines.length * lineH + hookSize * 0.6);
        }
        canvas.toBlob(function(blob) {
          dl.href = URL.createObjectURL(blob);
          dl.style.display = "inline-block";
        }, "image/png");
      };
      img.crossOrigin = "anonymous";
      img.src = data.image_url + "?t=" + Date.now();
    }
  } catch(e) {
    alert("Error: " + e.message);
    document.getElementById("imgLoading").style.display = "none";
  } finally {
    btn.disabled = false;
    btn.innerHTML = "&#9889; Generate Post + Image";
  }
}

function copyText(id, btn) {
  var text = document.getElementById(id).textContent;
  navigator.clipboard.writeText(text).then(function() {
    var orig = btn.textContent;
    btn.textContent = "Copied!";
    setTimeout(function() { btn.textContent = orig; }, 2000);
  });
}

function openLinkedIn() {
  var text = encodeURIComponent(document.getElementById("liPost").textContent || "");
  // Try LinkedIn app deep link first, fall back to web share
  var appUrl = "linkedin://";
  var webUrl = "https://www.linkedin.com/feed/?shareActive=true";
  // Copy to clipboard then open
  navigator.clipboard.writeText(document.getElementById("liPost").textContent || "").then(function() {
    var status = document.getElementById("makeStatus");
    status.className = "status-msg ok";
    status.textContent = "Copied! Opening LinkedIn...";
    setTimeout(function() {
      window.location.href = appUrl;
      setTimeout(function() { window.open(webUrl, "_blank"); }, 1200);
    }, 400);
  });
}

async function postToMake() {
  var btn = document.getElementById("postMakeBtn");
  var status = document.getElementById("makeStatus");
  var imageUrl = currentImageUrl || document.getElementById("imgPreview").src;
  var fbText = document.getElementById("fbPost").textContent;
  var igText = document.getElementById("igPost").textContent;
  if (!fbText && !igText) { status.textContent = "No post content."; return; }
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Posting...';
  status.textContent = "";
  try {
    var r = await fetch("/api/social/post-to-make", {
      method: "POST",
      headers: {"Content-Type":"application/json"},
      body: JSON.stringify({image_url: imageUrl, facebook_text: fbText, instagram_text: igText, brand: currentBrand})
    });
    var data = await r.json();
    if (data.ok) {
      status.className = "status-msg ok";
      status.textContent = "&#10003; Posted to Make!";
    } else {
      status.className = "status-msg err";
      status.textContent = "Error: " + (data.error || "unknown");
    }
  } catch(e) {
    status.className = "status-msg err";
    status.textContent = "Failed: " + e.message;
  } finally {
    btn.disabled = false;
    btn.innerHTML = "&#8679; Post FB + IG";
  }
}


async function loadStatus() {
  try {
    var r = await fetch("/api/social/status");
    var data = await r.json();
    updateToggleUI(data.enabled);
  } catch(e) {}
}

function updateToggleUI(enabled) {
  var btn = document.getElementById("toggleBtn");
  var label = document.getElementById("autoPostLabel");
  if (enabled) {
    btn.textContent = "Turn Off";
    btn.style.borderColor = "var(--accent)";
    btn.style.color = "var(--accent)";
    label.textContent = "Harbor: 9am daily -- Career: 12pm daily";
  } else {
    btn.textContent = "Turn On";
    btn.style.borderColor = "var(--border)";
    btn.style.color = "var(--muted)";
    label.textContent = "Auto-posting is paused";
  }
}

async function toggleAutoPost() {
  var r = await fetch("/api/social/toggle", {method: "POST"});
  var data = await r.json();
  updateToggleUI(data.enabled);
}

setBrand("harbor");
loadStatus();
</script>
</body>
</html>"""

# ============================================================
# start.harborprivacy.com magic-link auth
# ============================================================
START_TOKENS_PATH = "/var/log/harbor-start-tokens.json"
HARBOR_HOME_IPS = {"75.67.22.175"}
START_TOKEN_TTL = 90 * 24 * 3600
START_RECIPIENT = "admin@harborprivacy.com"
_START_RATELIMIT = {}

def _load_start_tokens():
    try:
        with open(START_TOKENS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}

def _save_start_tokens(d):
    try:
        with open(START_TOKENS_PATH, "w") as f:
            json.dump(d, f)
    except Exception:
        pass

def _start_cors(resp):
    resp.headers["Access-Control-Allow-Origin"] = "https://start.harborprivacy.com"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Vary"] = "Origin"
    return resp

def _client_ip():
    return request.headers.get("X-Real-IP") or request.headers.get("X-Forwarded-For", "").split(",")[0].strip() or request.remote_addr or ""

# ════════════════════════════════════════════════════════════
# SECTION 21 — ROUTES: START MAGIC (brazer startpage auth)
# /api/start-magic, /api/start-verify
# Magic-link email auth for start.brazer.us
# CSRF-exempt (own token in URL)
# ════════════════════════════════════════════════════════════

@app.route("/api/start-magic", methods=["POST", "OPTIONS"])
def api_start_magic():
    if request.method == "OPTIONS":
        return _start_cors(make_response("", 204))
    ip = _client_ip()
    now = int(_time.time())
    last = _START_RATELIMIT.get(ip, 0)
    if now - last < 300:
        return _start_cors(jsonify({"ok": False, "error": "rate_limited"}))
    data = request.get_json(silent=True) or {}
    ts = data.get("cf_turnstile_response") or data.get("turnstile") or ""
    if not _verify_turnstile(ts, ip):
        return _start_cors(jsonify({"ok": False, "error": "captcha"}))
    tokens = _load_start_tokens()
    tokens = {k: v for k, v in tokens.items() if v.get("expires", 0) > now}
    token = secrets.token_urlsafe(32)
    tokens[token] = {"created": now, "expires": now + START_TOKEN_TTL, "ip": ip}
    _save_start_tokens(tokens)
    _START_RATELIMIT[ip] = now
    link = f"https://start.harborprivacy.com/?access={token}"
    html = f'<p>Click to access start.harborprivacy.com (valid 90 days):</p><p><a href="{link}">{link}</a></p><p style="color:#666;font-size:12px">Requested from IP {ip}</p>'
    send_email(START_RECIPIENT, "Harbor Start access link", html)
    return _start_cors(jsonify({"ok": True}))

@app.route("/api/start-verify", methods=["POST", "OPTIONS"])
def api_start_verify():
    if request.method == "OPTIONS":
        return _start_cors(make_response("", 204))
    data = request.get_json(silent=True) or {}
    token = data.get("token", "")
    ip = _client_ip()
    now = int(_time.time())
    tokens = _load_start_tokens()
    entry = tokens.get(token)
    if not entry or entry.get("expires", 0) < now:
        if token in tokens:
            del tokens[token]
            _save_start_tokens(tokens)
        return _start_cors(jsonify({"ok": False}))
    if ip in HARBOR_HOME_IPS:
        entry["expires"] = now + START_TOKEN_TTL
        tokens[token] = entry
        _save_start_tokens(tokens)
    return _start_cors(jsonify({"ok": True, "expires": entry["expires"]}))

# ════════════════════════════════════════════════════════════
# SECTION 22 — HEALTH
# /health — simple "ok" for monitoring
# ════════════════════════════════════════════════════════════

@app.route("/health")
def health():
    return {"status": "ok"}

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DASHBOARD_PORT", 7000)), debug=False)
