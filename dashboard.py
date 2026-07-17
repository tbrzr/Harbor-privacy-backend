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

import os, json, secrets, logging, re
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
    "/api/adblock-checkout", # public Stripe embedded-checkout, CORS-scoped
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
def _inject_is_admin():
    try:
        from flask import request as _r
        return {"is_admin": bool(getattr(_r, "is_admin", False))}
    except Exception:
        return {"is_admin": False}

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


def _login_redirect():
    # Preserve the page the user was heading to (e.g. /social or /leads from
    # a PWA start_url) so login can send them back instead of dumping them
    # on /admin or /dashboard.
    from urllib.parse import quote
    nxt = request.full_path if request.query_string else request.path
    if nxt and nxt.startswith("/") and not nxt.startswith("//") and nxt not in ("/", "/login", "/logout"):
        return redirect("/login?next=" + quote(nxt, safe=""))
    return redirect("/login")

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
            return _login_redirect()
        payload = None
        for t in tokens:
            p = verify_token(t)
            if p:
                payload = p
                break
        if not payload:
            return _login_redirect()
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
            return _login_redirect()
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
<script defer src="https://stats.harborprivacy.com/script.js" data-website-id="51ad61cf-3e3b-4d74-818b-98df4af99183"></script>
<script>
  // SW disabled 2026-06-01 - earlier version caused a refresh loop. The
  // killswitch SW at /dashboard-sw.js will uninstall any leftover SW on
  // first visit. Re-register here only after we re-introduce a working SW.
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.getRegistrations().then(rs => rs.forEach(r => r.unregister())).catch(()=>{});
  }
</script>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="hp-is-admin" content="{{ 'yes' if is_admin else 'no' }}">
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate">
<meta http-equiv="Pragma" content="no-cache">
<meta http-equiv="Expires" content="0">
<title>{% block title %}Harbor Privacy Dashboard{% endblock %}</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@300;400;500&family=DM+Sans:wght@300;400;500&family=DM+Serif+Display:ital@0;1&display=swap" rel="stylesheet">
<style>
  :root{--bg:#0a0e0f;--surface:#111618;--surface-2:#151c1e;--border:#1e2a2d;--border-soft:#192325;--accent:#00e5c0;--accent-dim:rgba(0,229,192,0.10);--text:#e8f0ef;--muted:#6b8a87;--danger:#ff4e4e;--radius:14px;--radius-sm:10px;--shadow:0 1px 2px rgba(0,0,0,0.3),0 10px 28px -14px rgba(0,0,0,0.55);}
  *{margin:0;padding:0;box-sizing:border-box;}
  body{background:var(--bg);color:var(--text);font-family:'DM Sans',sans-serif;font-weight:300;line-height:1.7;min-height:100vh;}
  body::before{content:'';position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:0.3;pointer-events:none;z-index:0;}
  nav{padding:16px 32px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;position:sticky;top:0;z-index:10;background:linear-gradient(180deg,#111618 0%,#0c1213 100%);backdrop-filter:saturate(140%) blur(4px);}
  .logo{font-family:'DM Mono',monospace;font-size:14px;color:var(--accent);letter-spacing:0.1em;text-decoration:none;white-space:nowrap;}
  .logo span{color:var(--muted);}
  .nav-links{display:flex;gap:8px;align-items:center;flex-wrap:wrap;row-gap:6px;}
  .nav-links a{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;letter-spacing:0.06em;padding:6px 10px;border-radius:6px;transition:color 0.15s,background 0.15s;}
  .nav-links a:hover,.nav-links a.active{color:var(--accent);background:rgba(0,229,192,0.06);}
  .nav-drop{position:relative;}
  .nav-drop-menu{display:none;position:absolute;top:calc(100% + 4px);left:0;background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:6px;min-width:170px;z-index:70;flex-direction:column;gap:2px;box-shadow:0 8px 24px rgba(0,0,0,0.35);}
  .nav-drop.open .nav-drop-menu{display:flex;}
  .nav-drop-menu a{display:block;padding:8px 10px;white-space:nowrap;}
  .wrap{max-width:960px;margin:0 auto;padding:48px 32px 80px;position:relative;z-index:1;}
  .wrap-sm{max-width:500px;margin:0 auto;padding:60px 32px;position:relative;z-index:1;}
  .card{background:linear-gradient(180deg,var(--surface),#0f1517);border:1px solid var(--border);border-radius:var(--radius);padding:32px;margin-bottom:20px;box-shadow:var(--shadow);}
  .card-label{font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;}
  h1{font-family:'DM Serif Display',serif;font-size:40px;font-weight:400;line-height:1.1;}
  h2{font-family:'DM Serif Display',serif;font-size:26px;font-weight:400;margin-bottom:12px;}
  input,select{background:var(--bg);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);font-family:'DM Sans',sans-serif;font-size:14px;padding:12px 16px;outline:none;width:100%;margin-bottom:12px;transition:border 0.2s,box-shadow 0.2s;}
  input:focus,select:focus{border-color:var(--accent);box-shadow:0 0 0 3px var(--accent-dim);}
  input::placeholder{color:var(--muted);}
  input:disabled{opacity:0.4;cursor:not-allowed;}
  .btn{background:var(--accent);color:var(--bg);padding:12px 24px;border-radius:var(--radius-sm);font-family:'DM Mono',monospace;font-size:12px;letter-spacing:0.08em;border:none;cursor:pointer;font-weight:500;text-decoration:none;display:inline-block;transition:background 0.2s,transform 0.1s,box-shadow 0.2s;}
  .btn:hover{background:#00ffda;box-shadow:0 6px 18px -8px rgba(0,229,192,0.6);}
  .btn:active{transform:translateY(1px);}
  .ghost{display:inline-block;background:transparent;border:1px solid var(--accent);color:var(--accent);font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;padding:8px 16px;border-radius:var(--radius-sm);text-decoration:none;cursor:pointer;transition:background 0.2s;}
  .ghost:hover{background:var(--accent-dim);}
  .ghost.dim{border-color:var(--border);color:var(--muted);}
  .ghost.dim:hover{border-color:var(--accent);color:var(--accent);background:transparent;}
  .sec-head{display:flex;align-items:center;gap:9px;font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;}
  .sec-head svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
  .btn-sm{padding:6px 14px;font-size:10px;}
  .btn-outline{background:transparent;border:1px solid var(--border);color:var(--muted);}
  .btn-outline:hover{border-color:var(--accent);color:var(--accent);background:transparent;}
  .btn-danger{background:var(--danger);}
  .btn-danger:hover{background:#ff6b6b;}
  .btn-disabled{background:var(--border);color:var(--muted);cursor:not-allowed;pointer-events:none;}
  .stat-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;margin-bottom:20px;box-shadow:var(--shadow);}
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
  .badge{font-family:'DM Mono',monospace;font-size:9px;padding:3px 9px;border-radius:999px;letter-spacing:0.1em;font-weight:500;vertical-align:middle;}
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
  .profile-btn{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius-sm);color:var(--text);padding:16px;cursor:pointer;text-align:center;font-family:'DM Mono',monospace;font-size:12px;transition:border-color 0.2s,background 0.2s;}
  .profile-btn:hover{border-color:var(--accent);}
  .profile-active{border-color:var(--accent) !important;background:rgba(0,229,192,0.08) !important;}
  .doh-box{background:var(--bg);border-left:3px solid var(--accent);border-radius:var(--radius-sm);padding:16px;font-family:'DM Mono',monospace;font-size:13px;color:var(--accent);word-break:break-all;margin:12px 0;}
  .doh-box.locked{border-left-color:var(--border);color:var(--muted);filter:blur(4px);user-select:none;}
  .error{color:var(--danger);font-family:'DM Mono',monospace;font-size:12px;margin-bottom:16px;padding:12px 16px;border:1px solid var(--danger);border-radius:var(--radius-sm);background:rgba(255,78,78,0.06);}
  .success{color:var(--accent);font-family:'DM Mono',monospace;font-size:12px;margin-bottom:16px;padding:12px 16px;border:1px solid var(--accent);border-radius:var(--radius-sm);background:var(--accent-dim);}
  .note{font-size:14px;color:var(--muted);line-height:1.6;}
  .locked-overlay{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);padding:20px 24px;display:flex;align-items:center;gap:16px;margin-bottom:20px;box-shadow:var(--shadow);}
  .locked-icon{font-size:24px;flex-shrink:0;}
  .locked-text{font-size:14px;color:var(--muted);}
  .locked-text strong{color:var(--text);display:block;margin-bottom:4px;}
  .customer-grid{display:grid;gap:1px;background:var(--border);border:1px solid var(--border);border-radius:var(--radius);overflow:hidden;box-shadow:var(--shadow);}
  .customer-row{background:var(--surface);padding:18px 24px;display:grid;grid-template-columns:1fr 140px 110px 80px 100px;gap:16px;align-items:center;transition:background 0.15s;}
  .customer-row:hover{background:var(--surface-2);}
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
// Skip the inactivity auto-logout for admin in installed PWAs; a parked app
// icon would otherwise always reopen on the login page.
var HP_NO_TIMEOUT=(function(){try{var m=document.querySelector('meta[name="hp-is-admin"]');return m&&m.getAttribute('content')==='yes'&&window.matchMedia('(display-mode: standalone)').matches;}catch(e){return false;}})();
function resetTimer(){if(HP_NO_TIMEOUT)return;clearTimeout(timer);clearTimeout(warnTimer);warned=false;var w=document.getElementById("timeout-warning");if(w)w.style.display="none";warnTimer=setTimeout(showWarning,WARNING);timer=setTimeout(function(){window.location.href="/logout";},TIMEOUT);}
function showWarning(){if(warned)return;warned=true;var w=document.getElementById("timeout-warning");if(w)w.style.display="flex";}
document.addEventListener("click",function(e){document.querySelectorAll(".nav-drop.open").forEach(function(d){if(!d.contains(e.target))d.classList.remove("open");});});
document.addEventListener("mousemove",resetTimer);
document.addEventListener("keypress",resetTimer);
document.addEventListener("click",resetTimer);
document.addEventListener("touchstart",resetTimer);
window.addEventListener("load",resetTimer);
</script>

<style id="hp-injected-styles">

@supports(padding:env(safe-area-inset-bottom)){}


@media print{}

/* Dashboard bottom tab bar (fix: override element selector nav{position:sticky;top:0}) */
:root{--hp-bnav-h:0px;}
@media all and (display-mode:standalone) and (max-width:768px){:root{--hp-bnav-h:108px;}}
nav.hp-bottom-tabs{display:none;position:fixed !important;top:auto !important;left:0 !important;right:0 !important;bottom:0 !important;border-bottom:0 !important;background:rgba(17,22,24,0.96) !important;border-top:1px solid #1e2a2d !important;padding:6px 4px calc(6px + env(safe-area-inset-bottom)) 4px !important;justify-content:space-around !important;align-items:stretch !important;z-index:60 !important;backdrop-filter:saturate(160%) blur(14px);-webkit-backdrop-filter:saturate(160%) blur(14px);}
@media all and (display-mode:standalone) and (max-width:768px){nav.hp-bottom-tabs{display:flex !important;}}
nav.hp-bottom-tabs .hp-bottom-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:6px 4px;color:#6b8a87;text-decoration:none;font-family:'DM Mono',monospace;font-size:9px;letter-spacing:.08em;font-weight:600;background:transparent;border:0;cursor:pointer;min-height:44px;-webkit-tap-highlight-color:transparent;transition:color .12s;}
nav.hp-bottom-tabs .hp-bottom-tab svg{stroke:currentColor;}
nav.hp-bottom-tabs .hp-bottom-tab.active{color:#00e5c0;}
nav.hp-bottom-tabs .hp-bottom-tab:active{transform:scale(.94);}

/* hp-hm-zoom-lift: lift native .hm-zoom above .hp-bottom-tabs in PWA standalone on phones */
@media all and (display-mode:standalone) and (max-width:768px){
  .hm-zoom{bottom:calc(108px + env(safe-area-inset-bottom)) !important;}
}
</style>
<script id="hp-injected-scripts">
(function(){
// Bottom tab bar (admin-gated via meta tag)
function bnav(){
  if(document.getElementById('hp-bottom-tabs'))return;
  var meta=document.querySelector('meta[name="hp-is-admin"]');
  var isAdmin=meta && meta.getAttribute('content')==='yes';
  var p=location.pathname;
  function tab(label,href,active,icon,external){
    var a=document.createElement('a');a.className='hp-bottom-tab'+(active?' active':'');a.href=href;
    if(external){a.target='_blank';a.rel='noopener';}
    a.innerHTML=icon+'<span>'+label+'</span>';return a;
  }
  var I={
    dash:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="9"/><rect x="14" y="3" width="7" height="5"/><rect x="14" y="12" width="7" height="9"/><rect x="3" y="16" width="7" height="5"/></svg>',
    help:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="10"/><path d="M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>',
    settings:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>',
    signout:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>',
    customers:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>',
    assets:'<svg viewBox="0 0 24 24" width="22" height="22" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>'
  };
  var ts=[];
  ts.push(tab('Dashboard','/dashboard',p==='/dashboard'||p==='/',I.dash));
  if(isAdmin){ts.push(tab('Customers','/admin',p.indexOf('/admin')===0,I.customers));ts.push(tab('Assets','https://assets.harborprivacy.com/',false,I.assets,true));}
  ts.push(tab('Help','https://harborprivacy.com/docs.html',false,I.help,true));
  ts.push(tab('Settings','/settings',p.indexOf('/settings')===0,I.settings));
  ts.push(tab('Sign Out','/logout',false,I.signout));
  var n=document.createElement('nav');n.id='hp-bottom-tabs';n.className='hp-bottom-tabs';n.setAttribute('aria-label','Primary');
  ts.forEach(function(t){n.appendChild(t);});
  document.body.appendChild(n);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bnav);else bnav();
})();
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
    <a href="/linkedin" class="{{ 'active' if active == 'linkedin' else '' }}">LinkedIn</a>
    <a href="/leads" class="{{ 'active' if active == 'leads' else '' }}">Leads</a>
    <div class="nav-drop">
      <a href="#" onclick="this.parentNode.classList.toggle('open');return false;" class="{% if active in ('links','analytics','logs','scan','etsy') %}active{% endif %}">Tools &#9662;</a>
      <div class="nav-drop-menu">
        <a href="/admin/links" class="{{ 'active' if active == 'links' else '' }}">Link Manager</a>
        <a href="/etsy" class="{{ 'active' if active == 'etsy' else '' }}">Etsy Listings</a>
        <a href="/admin/analytics" class="{{ 'active' if active == 'analytics' else '' }}">DNS Analytics</a>
        <a href="/admin/logs" class="{{ 'active' if active == 'logs' else '' }}">Live Logs</a>
        <a href="/admin/scan" class="{{ 'active' if active == 'scan' else '' }}">Harbor Scan</a>
      </div>
    </div>
    <a href="/settings" class="{{ 'active' if active == 'settings' else '' }}">Settings</a>
    <a href="https://assets.harborprivacy.com/" target="_blank" rel="noopener">Assets ↗</a>
    <a href="/logout" style="margin-left:auto;">Sign Out</a>
  </div>
</nav>"""

# Shared topnav + PWA bottom tabs for the light (cream) admin pages:
# /social, /social/sent, /social/pages, /leads, /linkedin.
# Render with nav_active set to 'social', 'leads', or 'linkedin'.
# Relies on the host page defining --ink/--mute/--teal/--line CSS vars
# (all five cream templates share the same palette).
NAV_LIGHT = """
<style>
.topnav{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin:-4px 0 18px;padding-bottom:14px;border-bottom:1px solid var(--line);}
.topnav .brand{font-family:ui-monospace,Menlo,monospace;font-weight:600;font-size:14px;color:var(--ink);text-decoration:none;letter-spacing:1px;}
.topnav .brand span{color:var(--teal);margin:0 2px;}
.topnav .links{display:flex;gap:16px;flex-wrap:wrap;}
.topnav .links a{font-size:13px;color:var(--mute);text-decoration:none;}
.topnav .links a.active{color:var(--teal);font-weight:600;}
.lt-tabs{display:none;}
.lt-tabs a{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:2px;padding:6px 4px;color:var(--mute);text-decoration:none;font-family:ui-monospace,Menlo,monospace;font-size:9px;letter-spacing:.08em;font-weight:600;min-height:44px;-webkit-tap-highlight-color:transparent;}
.lt-tabs a.active{color:var(--teal);}
.lt-tabs svg{width:22px;height:22px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
@media all and (display-mode:standalone) and (max-width:768px){
  .topnav .links{display:none;}
  body{padding-bottom:calc(80px + env(safe-area-inset-bottom));}
  .lt-tabs{position:fixed;left:0;right:0;bottom:0;display:flex;justify-content:space-around;align-items:stretch;background:#fbf7f1;border-top:1px solid var(--line);padding:6px 4px calc(6px + env(safe-area-inset-bottom)) 4px;z-index:60;}
}
</style>
<div class="topnav">
  <a href="/admin" class="brand">harbor<span>/</span>privacy</a>
  <div class="links">
    <a href="/admin">Customers</a>
    <a href="/social" class="{{ 'active' if nav_active == 'social' else '' }}">Social</a>
    <a href="/linkedin" class="{{ 'active' if nav_active == 'linkedin' else '' }}">LinkedIn</a>
    <a href="/leads" class="{{ 'active' if nav_active == 'leads' else '' }}">Leads</a>
    <a href="/settings">Settings</a>
    <a href="https://assets.harborprivacy.com/" target="_blank" rel="noopener">Assets</a>
    <a href="/logout">Sign out</a>
  </div>
</div>
<nav class="lt-tabs" aria-label="Primary">
  <a href="/social" class="{{ 'active' if nav_active == 'social' else '' }}"><svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg><span>Social</span></a>
  <a href="/leads" class="{{ 'active' if nav_active == 'leads' else '' }}"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="6"/><circle cx="12" cy="12" r="2"/></svg><span>Leads</span></a>
  <a href="/linkedin" class="{{ 'active' if nav_active == 'linkedin' else '' }}"><svg viewBox="0 0 24 24"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4 12.5-12.5z"/></svg><span>LinkedIn</span></a>
  <a href="/admin"><svg viewBox="0 0 24 24"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg><span>Customers</span></a>
  <a href="/logout"><svg viewBox="0 0 24 24"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg><span>Sign out</span></a>
</nav>
"""

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

@app.route("/clear")
def browser_reset():
    """One-shot URL that emits Clear-Site-Data so iOS Safari / Chrome /
    Firefox nuke ALL storage for this origin (cookies, caches, localStorage,
    IndexedDB, registered service workers). Safe to hit anytime; if you
    weren't stuck, you just get logged out.

    Renders a tiny page that auto-redirects to /login after 1.5s so the
    user lands on a fresh, working dashboard."""
    html = (
        "<!doctype html><meta charset=utf-8>"
        "<title>Resetting...</title>"
        "<meta http-equiv=refresh content='1.5;url=/login'>"
        "<style>body{font-family:-apple-system,sans-serif;text-align:center;"
        "padding:80px 24px;color:#1a2420;background:#fbf7f0}"
        ".s{font-family:'DM Mono',ui-monospace,Menlo,monospace;font-size:12px;"
        "color:#1f5d6b;letter-spacing:.18em;margin-bottom:18px}"
        "h1{font-family:'DM Serif Display',Georgia,serif;font-weight:400;"
        "font-size:32px;margin:0 0 12px}"
        "p{color:#6b7a72;font-size:14px;margin:0}</style>"
        "<div class=s>HARBOR / DASHBOARD</div>"
        "<h1>Browser storage cleared.</h1>"
        "<p>Reloading the login page...</p>"
    )
    resp = make_response(html)
    resp.headers["Clear-Site-Data"] = '"cache", "cookies", "storage", "executionContexts"'
    resp.headers["Cache-Control"]   = "no-store"
    return resp

@app.route("/login", methods=["GET", "POST"])
def login():
    # Step 1: email only
    # Step 2: password (or setup if new)

    step = request.args.get("step", "1")
    email = request.args.get("email", "").lower().strip()
    error = None
    show_2fa = False

    # Internal-path-only post-login destination (from PWA start_url etc.)
    nxt = (request.form.get("next") or request.args.get("next") or "").strip()
    if not (nxt.startswith("/") and not nxt.startswith("//") and ":" not in nxt):
        nxt = ""

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
            ip = request.headers.get("X-Real-IP", request.remote_addr)
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
                    if pw_token and hmac.compare_digest(pw_token, expected_token):
                        pw_ok = True
                    elif password:
                        pw_ok = bcrypt.checkpw(password.encode(), user["password"].encode())
                    else:
                        pw_ok = False
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
                            resp = make_response(redirect(nxt or ("/admin" if is_admin else "/dashboard")))
                            resp.set_cookie("hp_token", "", expires=0, path="/")
                            resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
                            resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=2592000 if is_admin else 86400, domain=".harborprivacy.com")
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
                        resp = make_response(redirect(nxt or ("/admin" if is_admin else "/dashboard")))
                        resp.set_cookie("hp_token", "", expires=0, path="/")
                        resp.set_cookie("hp_token", "", expires=0, path="/", domain=".harborprivacy.com")
                        resp.set_cookie("hp_token", token, httponly=True, secure=True, samesite="Lax", max_age=2592000 if is_admin else 86400, domain=".harborprivacy.com")
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
    <input type="hidden" name="next" value="{{ nxt }}">
    <input type="email" name="email" placeholder="Your email address" value="{{ email }}" required autocomplete="email" autofocus>
    <button type="submit" class="btn" style="width:100%;">Continue →</button>
  </form>
  {% else %}
  <form method="POST">
    <input type="hidden" name="action" value="login">
    <input type="hidden" name="next" value="{{ nxt }}">
    <input type="hidden" name="email" value="{{ email }}">
    <div style="background:var(--surface);border:1px solid var(--border);padding:12px 16px;margin-bottom:16px;font-family:'DM Mono',monospace;font-size:13px;color:var(--muted);display:flex;justify-content:space-between;align-items:center;">
      <span>{{ email }}</span>
      <a href="/login{% if nxt %}?next={{ nxt|urlencode }}{% endif %}" style="font-size:11px;color:var(--accent);text-decoration:none;">Change</a>
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
    return render_template_string(html, step=step, email=email, error=error, show_2fa=show_2fa, pw_tok=pw_tok, nxt=nxt)

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
    <div class="sec-head"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Your DoH Address</div>
    <div class="doh-box" id="doh-address">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
    <button onclick="copyDoH()" class="ghost" style="margin-top:8px;" id="copy-btn">Copy Address</button>
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
      <a href="https://adblock.harborprivacy.com/profiles/{{ client_id }}.mobileconfig" class="ghost">Download iOS Profile</a>
      <a href="https://adblock.harborprivacy.com/setup/android/{{ client_id }}" target="_blank" class="ghost dim">Android Setup + QR</a>
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
    <div class="locked-icon"><svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="var(--accent)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
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
    <div class="sec-head"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Account Info</div>
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
    <div class="sec-head"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/></svg>Your Private DNS Address</div>
    {% if is_active %}
    <div class="doh-box" id="doh-address">https://doh.harborprivacy.com/dns-query/{{ client_id }}</div>
    <button onclick="copyDoH()" class="ghost" style="margin-top:8px;" id="copy-btn">Copy Address</button>
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
      <a href="https://adblock.harborprivacy.com/profiles/{{ client_id }}.mobileconfig" class="ghost">Download iOS Profile</a>
      <a href="https://adblock.harborprivacy.com/setup/android/{{ client_id }}" target="_blank" class="ghost dim">Android Setup + QR</a>
    </div>
    <p class="note" style="margin-top:12px;">Use this address in your DNS over HTTPS settings. <a href="https://harborprivacy.com/docs/getting-started" style="color:var(--accent);">Setup guide →</a></p>
    {% else %}
    <div class="doh-box locked">https://doh.harborprivacy.com/dns-query/••••••••••</div>
    <p class="note">Your personal DNS address will appear here once your subscription is active.</p>
    {% endif %}
  </div>

  <!-- UPGRADE CARD — monthly only -->
  {% if plan_badge == "MONTHLY" and is_active %}
  <div class="card" style="border-color:#1e3a35;background:rgba(0,229,192,0.03);margin-bottom:20px;">
    <div class="card-label" style="color:var(--accent);">Save with Annual</div>
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;margin-top:8px;">
      <div>
        <div style="font-family:'DM Mono',monospace;font-size:12px;color:var(--text);">Annual — $26.99/yr</div>
        <div style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Just $2.25/mo, billed once a year</div>
      </div>
      <a href="https://billing.stripe.com/p/login/3cI28qfUX5Tp5rn80T6kg00" target="_blank" style="background:var(--accent);color:var(--bg);font-family:'DM Mono',monospace;font-size:11px;padding:6px 14px;text-decoration:none;white-space:nowrap;">Switch →</a>
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
        <a href="https://adblock.harborprivacy.com/profiles/{{ kp.name }}.mobileconfig" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#8659; iOS/Mac Profile</a>
        <a href="https://adblock.harborprivacy.com/setup/android/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
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

  <div class="card" style="margin-top:20px;border:1px solid var(--accent);background:linear-gradient(180deg,var(--surface) 0%,var(--bg) 100%);">
    <div style="display:flex;align-items:center;gap:16px;flex-wrap:wrap;">
      <div style="flex-shrink:0;width:48px;height:48px;background:rgba(31,93,107,0.08);display:flex;align-items:center;justify-content:center;border-radius:8px;">
        <img src="https://scan.harborprivacy.com/scan-favicon.svg" alt="Harbor Scan" style="width:32px;height:32px;">
      </div>
      <div style="flex:1;min-width:200px;">
        <div style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:6px;">New from Harbor</div>
        <div style="font-size:16px;color:var(--text);font-weight:500;margin-bottom:4px;">Harbor Scan &mdash; remove your name from data brokers</div>
        <div style="font-size:13px;color:var(--muted);line-height:1.5;">Spokeo, Whitepages, BeenVerified, and 13 more. Automated CCPA opt-outs. Verified removal.</div>
      </div>
      <a href="https://scan.harborprivacy.com" target="_blank" rel="noopener" style="display:inline-block;background:var(--accent);color:var(--bg);padding:10px 18px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.08em;text-decoration:none;flex-shrink:0;">Join Waitlist &rarr;</a>
    </div>
  </div>


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
<style>
.qa-row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px;}
.qa{display:inline-flex;align-items:center;gap:8px;background:var(--surface);border:1px solid var(--border);border-radius:999px;color:var(--muted);padding:9px 16px;font-family:'DM Mono',monospace;font-size:11px;letter-spacing:0.06em;text-decoration:none;transition:border-color .2s,color .2s,background .2s,transform .1s;}
.qa:hover{border-color:var(--accent);color:var(--accent);background:var(--accent-dim);}
.qa:active{transform:translateY(1px);}
.qa.primary{border-color:var(--accent);color:var(--accent);}
.qa svg{width:14px;height:14px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
.cust-name{font-size:14px;color:var(--text);}
.cust-sub{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);margin-top:2px;}
.cust-seen{font-family:'DM Mono',monospace;font-size:10px;color:#4a6a67;margin-top:2px;}
.cust-cid{font-family:'DM Mono',monospace;font-size:12px;color:var(--accent);}
.cust-plan{font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-transform:capitalize;}
.cust-del{display:inline-flex;align-items:center;justify-content:center;width:30px;height:30px;border-radius:8px;background:rgba(255,107,107,0.10);color:#ff6b6b;border:1px solid rgba(255,107,107,0.25);cursor:pointer;font-size:12px;line-height:1;transition:background .15s;}
.cust-del:hover{background:rgba(255,107,107,0.22);}
.view-btn{padding:5px 12px;font-size:10px;}
</style>
<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin Panel</p>
    <h1>Harbor Privacy.</h1>
  </div>

  <div class="stat-grid" style="margin-bottom:32px;">
    <div class="stat"><div class="stat-num">{{ customers|length }}</div><div class="stat-label">Active Customers</div></div>
    <div class="stat"><div class="stat-num">{{ total_queries_display }}</div><div class="stat-label">DNS Queries (7 Days)</div></div>
    <div class="stat"><div class="stat-num">{{ block_pct }}%</div><div class="stat-label">Network Block Rate</div></div>
  </div>

  <div class="qa-row">
    <a href="/admin/links" class="qa primary"><svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.07 0l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.07 0l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>Link Manager</a>
    <a href="/admin/analytics" class="qa"><svg viewBox="0 0 24 24"><path d="M3 3v18h18"/><path d="M7 14l3-3 4 4 5-6"/></svg>DNS Analytics</a>
    <a href="/admin/logs" class="qa"><svg viewBox="0 0 24 24"><path d="M22 12h-4l-3 9L9 3l-3 9H2"/></svg>Live Logs</a>
    <a href="/admin/scan" class="qa"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Harbor Scan</a>
    <a href="https://assets.harborprivacy.com/" target="_blank" rel="noopener" class="qa"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg>Assets</a>
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
          <div class="cust-name">{{ c.name }}{% if c.status == 'failed' %} <span style="font-family:'DM Mono',monospace;font-size:10px;color:#ff4e4e;letter-spacing:0.1em;">&#9888; PROVISION FAILED</span>{% endif %}</div>
          <div class="cust-sub">{{ c.email }}</div>
          {% if c.last_seen %}<div class="cust-seen">Last seen: {{ c.last_seen[:16].replace('T',' ') }} UTC</div>{% endif %}
        </div>
        <div class="cust-cid">{{ c.client_id }}</div>
        <div class="cust-plan">{{ c.plan }}</div>
        <div><span class="badge {% if cl and cl.parental_enabled %}badge-on{% else %}badge-off{% endif %}">{% if cl and cl.parental_enabled %}ON{% else %}OFF{% endif %}</span></div>
        <div style="display:flex;gap:6px;align-items:center;">
          <a href="/admin/customer/{{ c.client_id }}" class="btn btn-sm view-btn">View &rarr;</a>
          {% if c.client_id not in ["harbor7066", "admintim1003"] and c.email not in ["admin@harborprivacy.com", "tim@harborprivacy.com"] %}
          <button class="cust-del" onclick="deleteCustomer('{{ c.client_id }}','{{ c.name }}',this)">&#10005;</button>
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
        total_queries=total_queries, total_queries_display=f"{total_queries:,}",
        block_pct=block_pct,
        clients_map=clients_map, get_client=get_client, active="admin")


# ── Adblock embedded Stripe Checkout (no payment links) ──────
# Mints an embedded Checkout Session from a price id so pricing.html /
# adblock.html can show an in-page modal. mode=subscription means the existing
# webhook checkout.session.completed provisioning runs unchanged; metadata
# carries plan_type so the right badge/feature gating applies.
ADBLOCK_PLANS = {
    "light":  ("price_1TE36NCOrGNrBgIf2T8ApaAG", "harbor-remote-light"),
    "remote": ("price_1TCTlYCOrGNrBgIf4euUONmf", "remote"),
    "annual": ("price_1TenLxCOrGNrBgIfCi4l3lU3", "annual"),
}
_ADBLOCK_ORIGINS = ("https://harborprivacy.com", "https://www.harborprivacy.com",
                    "https://adblock.harborprivacy.com")

def _adblock_cors(resp):
    origin = request.headers.get("Origin", "")
    resp.headers["Access-Control-Allow-Origin"] = origin if origin in _ADBLOCK_ORIGINS else "https://harborprivacy.com"
    resp.headers["Vary"] = "Origin"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
    return resp

@app.route("/api/adblock-checkout", methods=["POST", "OPTIONS"])
def adblock_checkout():
    if request.method == "OPTIONS":
        return _adblock_cors(make_response("", 204))
    # Live Stripe checkout session creation had no rate limit at all -- same
    # class of gap as the 2026-06-25 card-testing incident.
    _ckip = request.headers.get("X-Real-IP", request.remote_addr or "")
    if not _signup_rate_ok(f"adblock-checkout:{_ckip}", limit=6, window=60):
        return _adblock_cors(make_response(jsonify({"error": "Too many requests. Try again later."}), 429))
    _record_signup_attempt(f"adblock-checkout:{_ckip}")
    import requests as _req
    secret = os.environ.get("STRIPE_SECRET", "")
    if not secret:
        return _adblock_cors(make_response(jsonify({"error": "billing unavailable"}), 503))
    plan = ((request.get_json(silent=True) or {}).get("plan") or "").strip().lower()
    if plan not in ADBLOCK_PLANS:
        return _adblock_cors(make_response(jsonify({"error": "invalid plan"}), 400))
    price_id, plan_type = ADBLOCK_PLANS[plan]
    form = {
        "mode": "subscription",
        "ui_mode": "embedded",
        "line_items[0][price]": price_id,
        "line_items[0][quantity]": "1",
        "return_url": "https://harborprivacy.com/welcome-paid?session_id={CHECKOUT_SESSION_ID}",
        "metadata[plan_type]": plan_type,
        "metadata[harbor_product]": "adblock",
        "subscription_data[metadata][plan_type]": plan_type,
    }
    try:
        r = _req.post("https://api.stripe.com/v1/checkout/sessions",
                      data=form, auth=(secret, ""), timeout=20)
        j = r.json()
    except Exception as e:
        return _adblock_cors(make_response(jsonify({"error": str(e)}), 502))
    if r.status_code >= 400 or "client_secret" not in j:
        msg = (j.get("error") or {}).get("message", "stripe error")
        return _adblock_cors(make_response(jsonify({"error": msg}), 400))
    return _adblock_cors(make_response(jsonify({"client_secret": j["client_secret"]})))


@app.route("/api/decal-request", methods=["POST", "OPTIONS"])
def decal_request():
    """Public lead form from the apex sticker shop: a business requests a free
    'powered by Harbor Booking' window decal. Records the lead and emails Tim.
    Reuses the adblock CORS scope (same harborprivacy.com origins)."""
    if request.method == "OPTIONS":
        return _adblock_cors(make_response("", 204))
    import json as _j, time as _t, html as _html
    _decal_ip = request.headers.get("X-Real-IP", request.remote_addr or "")
    if not _signup_rate_ok(f"decal:{_decal_ip}", limit=5, window=3600):
        return _adblock_cors(make_response(jsonify({"error": "Too many requests. Try again later."}), 429))
    _record_signup_attempt(f"decal:{_decal_ip}")
    data = request.get_json(silent=True) or {}
    biz   = (data.get("biz") or "").strip()[:120]
    email = (data.get("email") or "").strip()[:160]
    link  = (data.get("link") or "").strip()[:300]
    msg   = (data.get("msg") or "").strip()[:1500]
    if not biz or "@" not in email:
        return _adblock_cors(make_response(jsonify({"error": "business name and a valid email are required"}), 400))
    rec = {"ts": int(_t.time()), "biz": biz, "email": email, "link": link, "msg": msg,
           "ip": request.headers.get("X-Real-IP", request.remote_addr or "")}
    try:
        with open("/home/ubuntu/harbor-decal-requests.jsonl", "a") as f:
            f.write(_j.dumps(rec, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"decal request log failed: {e!r}", flush=True)
    try:
        from webhook import send_email
        e_ = lambda s: _html.escape(s or "")
        body = (f"<div style='font-family:sans-serif;color:#1a2420;max-width:560px;'>"
                f"<h2 style='font-family:Georgia,serif;font-weight:400;'>New Booking decal request</h2>"
                f"<p><strong>Business:</strong> {e_(biz)}</p>"
                f"<p><strong>Email:</strong> {e_(email)}</p>"
                f"<p><strong>Booking link:</strong> {e_(link) or '(none yet)'}</p>"
                f"<p><strong>Notes:</strong><br>{e_(msg).replace(chr(10), '<br>') or '(none)'}</p></div>")
        send_email("info@harborprivacy.com", f"Booking decal request - {biz}", body)
    except Exception as e:
        print(f"decal request email failed: {e!r}", flush=True)
    return _adblock_cors(make_response(jsonify({"ok": True})))


# Sticker shop cart: maps the apex cart to one Stripe Checkout Session so a
# customer can preorder several designs in a single checkout (the per-design
# Payment Links only do one item each).
STICKER_PRICES = {
    "my-dns-is-mine":                "price_1TgwcQCOrGNrBgIfXcWKrbwE",
    "i-read-it":                     "price_1TgwcRCOrGNrBgIfn5Di9P3J",
    "no-logs":                       "price_1TgwcSCOrGNrBgIfeo6apQWS",
    "not-the-product":               "price_1TgwcSCOrGNrBgIfyv6QNfLS",
    "cookies-declined":              "price_1TgwcTCOrGNrBgIfSaapM7h9",
    "i-host-my-own":                 "price_1TgwcUCOrGNrBgIfleuSGfRM",
    "trackers-hate-this":            "price_1TgwcVCOrGNrBgIfyzZfLBuc",
    "encrypted-at-harbor":           "price_1TgwcWCOrGNrBgIfa5PcigoM",
    "ask-me-about-my-dns":           "price_1TgwcXCOrGNrBgIfZds7rm3E",
    "hello-my-name-is-redacted":     "price_1Tgy7zCOrGNrBgIfBmxk39cv",
    "hello-my-data-is-not-for-sale": "price_1Tgy7yCOrGNrBgIfS5NdqedI",
    "pack":                          "price_1TgwcXCOrGNrBgIfO3ygVLVY",
}

@app.route("/api/sticker-checkout", methods=["POST", "OPTIONS"])
def sticker_checkout():
    if request.method == "OPTIONS":
        return _adblock_cors(make_response("", 204))
    # Same gap as adblock-checkout: live Stripe session creation, no rate limit.
    _ckip = request.headers.get("X-Real-IP", request.remote_addr or "")
    if not _signup_rate_ok(f"sticker-checkout:{_ckip}", limit=6, window=60):
        return _adblock_cors(make_response(jsonify({"error": "Too many requests. Try again later."}), 429))
    _record_signup_attempt(f"sticker-checkout:{_ckip}")
    import requests as _req
    secret = os.environ.get("STRIPE_SECRET", "")
    if not secret:
        return _adblock_cors(make_response(jsonify({"error": "billing unavailable"}), 503))
    cart = (request.get_json(silent=True) or {}).get("cart") or []
    form = {
        "mode": "payment",
        "success_url": "https://harborprivacy.com/stickers?ok=1",
        "cancel_url": "https://harborprivacy.com/stickers",
        "shipping_address_collection[allowed_countries][0]": "US",
        "custom_text[submit][message]": "Preorder. Ships in 2 to 3 weeks; we email you the day it goes out.",
    }
    idx = 0
    for item in cart:
        slug = str((item or {}).get("id", ""))
        try:
            qty = int((item or {}).get("qty", 1))
        except Exception:
            qty = 1
        if slug in STICKER_PRICES and 1 <= qty <= 50:
            form[f"line_items[{idx}][price]"] = STICKER_PRICES[slug]
            form[f"line_items[{idx}][quantity]"] = str(qty)
            idx += 1
    if idx == 0:
        return _adblock_cors(make_response(jsonify({"error": "cart is empty"}), 400))
    try:
        r = _req.post("https://api.stripe.com/v1/checkout/sessions",
                      data=form, auth=(secret, ""), timeout=20)
        j = r.json()
    except Exception as e:
        return _adblock_cors(make_response(jsonify({"error": str(e)}), 502))
    if r.status_code >= 400 or "url" not in j:
        msg = (j.get("error") or {}).get("message", "stripe error")
        return _adblock_cors(make_response(jsonify({"error": msg}), 400))
    return _adblock_cors(make_response(jsonify({"url": j["url"]})))


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


@app.route("/api/dns-analytics", methods=["POST", "OPTIONS"])
def log_dns_analytics():
    import json as _json, time
    if request.method == "OPTIONS":
        r = make_response("", 204)
        r.headers["Access-Control-Allow-Origin"] = "*"
        r.headers["Access-Control-Allow-Methods"] = "POST, OPTIONS"
        r.headers["Access-Control-Allow-Headers"] = "Content-Type"
        return r
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
    resp = make_response("", 204)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    return resp

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
    return render_template_string(html, active="analytics")

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
      <input type="text" id="new-icon" placeholder="Icon slug (adblock, booking, career, dashboard, fax, help, money, neighbor, privacy, resume, scan, start)" style="background:var(--bg);border:1px solid var(--border);color:var(--text);padding:12px;font-family:'DM Mono',monospace;font-size:12px;">
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
    return render_template_string(html, links=enumerate(links), active="links")

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
        <a href="https://adblock.harborprivacy.com/profiles/{{ kp.name }}.mobileconfig" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#8659; iOS/Mac Profile</a>
        <a href="https://adblock.harborprivacy.com/setup/android/{{ kp.name }}" target="_blank" style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);border:1px solid var(--accent);padding:4px 10px;text-decoration:none;">&#9632; Android QR</a>
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
    _ip = request.headers.get("X-Real-IP", request.remote_addr)
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
<style>
.set-eyebrow{font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;}
.set-head{display:flex;align-items:center;gap:9px;font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:16px;}
.set-head svg{width:15px;height:15px;stroke:currentColor;fill:none;stroke-width:2;stroke-linecap:round;stroke-linejoin:round;}
.support-box{background:var(--bg);border-left:3px solid var(--accent);border-radius:var(--radius-sm);padding:16px;font-family:'DM Mono',monospace;font-size:24px;color:var(--accent);letter-spacing:0.3em;text-align:center;margin-bottom:8px;}
</style>
<div class="wrap" style="max-width:580px;">
  <div style="margin-bottom:32px;">
    <p class="set-eyebrow">Account</p>
    <h1>Settings.</h1>
  </div>

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
    <div class="set-head"><svg viewBox="0 0 24 24"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>Change Password</div>
    <form method="POST" action="/settings/password">
      <input type="hidden" name="csrf" value="{{ csrf_token }}">
      <input type="password" name="current" placeholder="Current password" required>
      <input type="password" name="new_pw" placeholder="New password (min 8 characters)" required minlength="8">
      <input type="password" name="confirm" placeholder="Confirm new password" required>
      <button type="submit" class="btn">Update Password</button>
    </form>
  </div>

  <div class="card">
    <div class="set-head"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/></svg>Two-Factor Authentication</div>
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
    <div class="set-head"><svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="10"/><circle cx="12" cy="12" r="4"/><line x1="4.93" y1="4.93" x2="9.17" y2="9.17"/><line x1="14.83" y1="14.83" x2="19.07" y2="19.07"/><line x1="14.83" y1="9.17" x2="19.07" y2="4.93"/><line x1="9.17" y1="14.83" x2="4.93" y2="19.07"/></svg>Support Access</div>
    <p class="note" style="margin-bottom:16px;">If you need help, generate a temporary support code and share it with Harbor Privacy support. The code expires in 30 minutes.</p>
    <button onclick="genCode()" class="btn" style="margin-bottom:12px;">Generate Support Code</button>
    <div id="support-code-box" class="support-box" style="display:none;"></div>
    <p id="support-code-note" style="display:none;font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);">Share this code with support. Expires in 30 minutes.</p>
  </div>

  <div class="card">
    <div class="set-head"><svg viewBox="0 0 24 24"><rect x="2" y="4" width="20" height="16" rx="2"/><path d="M22 6l-10 7L2 6"/></svg>Weekly Stats Email</div>
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
    <div class="set-head"><svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>Your Data</div>
    <p class="note" style="margin-bottom:16px;">Request a report of everything Harbor Privacy holds about you. We'll email it within 24 hours.</p>
    <div style="display:flex;gap:12px;flex-wrap:wrap;">
      <a href="/settings/data-request" class="btn btn-outline">Request My Data</a>
      <a href="https://billing.stripe.com/p/login/3cI28qfUX5Tp5rn80T6kg00" target="_blank" class="btn btn-outline">Manage Subscription</a>
    </div>
  </div>
  {% else %}
  <div class="card">
    <div class="set-head"><svg viewBox="0 0 24 24"><path d="M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2"/><circle cx="12" cy="7" r="4"/></svg>Admin Account</div>
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

FORGOT_ATTEMPTS = {}  # {"ip"|email: [ts,...]} -- no rate limit existed at all before

def _forgot_rate_ok(key, limit=3, window=3600):
    now = _time.time()
    rec = [t for t in FORGOT_ATTEMPTS.get(key, []) if (now - t) < window]
    FORGOT_ATTEMPTS[key] = rec
    if len(rec) >= limit:
        return False
    rec.append(now)
    FORGOT_ATTEMPTS[key] = rec
    return True

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    email = request.args.get("email", "")
    sent = False
    if request.method == "POST":
        email = request.form.get("email", "").lower().strip()
        ip = request.headers.get("X-Real-IP", request.remote_addr)
        # Rate-limited requests still show the same "sent" response as a real
        # send would -- silently dropping the email without changing the
        # response keeps this from becoming an account-existence oracle.
        allowed = _forgot_rate_ok(f"ip:{ip}") and _forgot_rate_ok(f"email:{email}")
        user = get_user(email) if allowed else None
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
WINDOWS_SEND_ATTEMPTS = {}   # {ip: [ts,...]} -- throttle code-send emails
WINDOWS_VERIFY_ATTEMPTS = {}  # {ip: {count, locked_until}} -- throttle code-guessing

def _windows_send_rate_ok(ip, limit=3, window=3600):
    now = _time.time()
    rec = [t for t in WINDOWS_SEND_ATTEMPTS.get(ip, []) if (now - t) < window]
    WINDOWS_SEND_ATTEMPTS[ip] = rec
    return len(rec) < limit

def _windows_verify_rate_ok(ip):
    entry = WINDOWS_VERIFY_ATTEMPTS.get(ip, {})
    return entry.get("locked_until", 0) <= _time.time()

def _windows_verify_record_failure(ip):
    entry = WINDOWS_VERIFY_ATTEMPTS.get(ip, {"count": 0, "locked_until": 0})
    entry["count"] = entry.get("count", 0) + 1
    if entry["count"] >= 10:
        entry["locked_until"] = _time.time() + 900
        entry["count"] = 0
    WINDOWS_VERIFY_ATTEMPTS[ip] = entry

@app.route("/api/windows/send-code", methods=["POST"])
def windows_send_code():
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    if not _windows_send_rate_ok(ip):
        return jsonify({"ok": False, "error": "Too many requests. Try again later."}), 429
    data = request.json
    email = data.get("email", "").lower().strip()
    if not email:
        return jsonify({"ok": False, "error": "Email required"})
    customer = find_customer(email)
    if not customer:
        WINDOWS_SEND_ATTEMPTS.setdefault(ip, []).append(_time.time())
        return jsonify({"ok": False, "error": "No account found for that email"})
    code = str(_random.randint(100000, 999999))
    WINDOWS_APP_CODES[email] = {"code": code, "expires": _time.time() + 600, "attempts": 0}
    WINDOWS_SEND_ATTEMPTS.setdefault(ip, []).append(_time.time())
    html = f'<div style="font-family:sans-serif;max-width:560px;color:#1a2420;"><h2 style="font-family:Georgia,serif;font-weight:400;">Your Harbor Privacy Login Code</h2><p>Use this code to sign in to the Harbor Privacy Windows app:</p><p style="background:#f4eee2;border-left:3px solid #1f5d6b;padding:20px;font-family:monospace;font-size:36px;color:#1f5d6b;letter-spacing:0.4em;text-align:center;">{code}</p><p style="color:#6b7a72;font-size:13px;">Expires in 10 minutes.</p><p style="color:#6b7a72;font-size:13px;">- Tim | harborprivacy.com</p></div>'
    send_email(email, "Your Harbor Privacy Login Code", html)
    app.logger.info(f"Windows app code sent to {email}")
    return jsonify({"ok": True})

@app.route("/api/windows/verify", methods=["POST"])
def windows_verify():
    # Was a straight code == comparison with no attempt limit at all -- a 6-digit
    # code (900k possibilities) with no throttling is brute-forceable well within
    # its 10-minute expiry. Mirrors the existing verify_support_code() pattern:
    # per-code attempt cap + a secondary per-IP lockout.
    ip = request.headers.get("X-Real-IP", request.remote_addr)
    if not _windows_verify_rate_ok(ip):
        return jsonify({"ok": False, "error": "Too many attempts. Try again later."}), 429
    data = request.json
    email = data.get("email", "").lower().strip()
    code = data.get("code", "").strip()
    entry = WINDOWS_APP_CODES.get(email)
    if not entry or _time.time() > entry["expires"] or entry.get("attempts", 0) >= 5:
        WINDOWS_APP_CODES.pop(email, None)
        _windows_verify_record_failure(ip)
        return jsonify({"ok": False, "error": "Invalid or expired code"})
    if entry["code"] != code:
        entry["attempts"] = entry.get("attempts", 0) + 1
        _windows_verify_record_failure(ip)
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
        profile_url = f"https://adblock.harborprivacy.com/profiles/{client_id}.mobileconfig"
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

SOCIAL_MANIFEST = "/home/ubuntu/harbor-design-system/assets/social/manifest.json"
SOCIAL_HISTORY  = "/home/ubuntu/.social-post-history.jsonl"
SOCIAL_POSTED   = "/home/ubuntu/.social-posted.json"

# Meta Graph API: set these in the harbor-dashboard systemd override to enable
# one-tap "Post to Page". META_PAGE_TOKEN is a long-lived Page access token with
# pages_manage_posts; META_PAGE_ID is the Harbor Facebook Page id.
META_PAGE_ID    = os.environ.get("META_PAGE_ID", "")
META_PAGE_TOKEN = os.environ.get("META_PAGE_TOKEN", "")
# IG Business account id linked to the Page. Uses the same META_PAGE_TOKEN, which
# must also carry instagram_basic + instagram_content_publish.
META_IG_ID      = os.environ.get("META_IG_ID", "")
# Meta's servers fetch the image by URL, so it must be public (the assets host is
# login-walled). This unauthenticated dashboard route serves the rendered card.
# ── Pinterest one-tap publish ───────────────────────────────
# v5 API. Token values live in /etc/harbor-dashboard.env (same file as META_*).
# Refresh-on-demand: refresh tokens last ~1yr, access tokens expire, so we mint a
# fresh access token per publish from the refresh token, falling back to a static
# PINTEREST_ACCESS_TOKEN if the refresh creds are not set.
PINTEREST_APP_ID        = os.environ.get("PINTEREST_APP_ID", "")
PINTEREST_APP_SECRET    = os.environ.get("PINTEREST_APP_SECRET", "")
PINTEREST_ACCESS_TOKEN  = os.environ.get("PINTEREST_ACCESS_TOKEN", "")
PINTEREST_REFRESH_TOKEN = os.environ.get("PINTEREST_REFRESH_TOKEN", "")
PINTEREST_BOARD_ID      = os.environ.get("PINTEREST_BOARD_ID", "")

# ── X (Twitter) one-tap publish ─────────────────────────────
# OAuth 1.0a user context (stdlib-signed, no extra deps). All four values live in
# /etc/harbor-dashboard.env. The app must have Read+Write permission.
X_API_KEY       = os.environ.get("X_API_KEY")       or os.environ.get("TWITTER_API_KEY", "")
X_API_SECRET    = os.environ.get("X_API_SECRET")    or os.environ.get("TWITTER_API_SECRET", "")
X_ACCESS_TOKEN  = os.environ.get("X_ACCESS_TOKEN")  or os.environ.get("TWITTER_ACCESS_TOKEN", "")
X_ACCESS_SECRET = os.environ.get("X_ACCESS_SECRET") or os.environ.get("TWITTER_ACCESS_SECRET", "")

SOCIAL_PUBLIC_BASE = "https://dashboard.harborprivacy.com/social/public"

def _load_posted():
    import json as _json
    try:
        with open(SOCIAL_POSTED) as _f:
            return _json.load(_f)
    except Exception:
        return {}

def _save_posted(d):
    import json as _json
    with open(SOCIAL_POSTED, "w") as _f:
        _json.dump(d, _f, indent=2)


def _entry_status(e):
    """A manifest entry's review status. Legacy entries have no 'status' key, so
    they are treated as already approved -> the existing 219-post pool stays live
    with zero migration. Only AI drafts are stamped 'pending' at creation, so only
    they ever need approval before they can be scheduled or auto-published."""
    return e.get("status") or "approved"


def _review_decision(action, entry):
    """DECISION POINT — yours to write (learning-mode contribution).

    Called by POST /api/social/review when you tap Approve or Reject on a pending
    draft. It must return what to do with the entry:

        return "approved"  -> draft becomes schedulable / auto-publishable
        return "rejected"  -> draft stays in the manifest but is hidden + never
                              fires (an audit trail of what you killed)
        return None        -> the entry is DELETED from the manifest entirely
                              (clean pool, but no record it ever existed)

    Args:
        action: "approve" or "reject" (the button the user tapped)
        entry:  the manifest entry dict (read-only; for gating on its fields)

    Trade-offs worth weighing:
      - Reject == "rejected" keeps a paper trail but the pool grows forever; the
        social-refresh prune only trims old AI posts, not rejected ones.
      - Reject == None (delete) keeps the library clean but you lose the record,
        and the image file on disk is orphaned until the 14-day junk sweep.
      - You can also REFUSE an approve here (e.g. return "pending" / None if the
        entry has no image, or a sticker post with an empty body) so a malformed
        draft can never reach the live pool just because you fat-fingered Approve.

    This is the one piece that defines how strict your gate is, which is exactly
    the brand-risk call native.no makes for you. Everything else is wired.
    """
    # Default policy (change anytime): reject hard-deletes to keep the pool clean;
    # approve goes live but is refused for an imageless draft so a broken card can
    # never reach the feed by a fat-fingered Approve.
    if action == "reject":
        return None
    if not entry.get("img"):
        return None
    return "approved"

# brand -> filter category for generated sets
SOCIAL_BRAND_CAT = {"harbor":"Harbor","career":"Career","fax":"Fax",
                    "booking":"Booking","money":"Money","scan":"Scan",
                    "burn":"Burn","tips":"Tips"}

SOCIAL_HISTORY_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>Sent posts</title>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:680px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:26px;margin:6px 0 18px;}
a.row{display:flex;gap:14px;align-items:center;background:#fff;border:1px solid var(--line);border-radius:14px;padding:12px;margin-bottom:12px;text-decoration:none;color:inherit;}
a.row.dead{opacity:.55;pointer-events:none;}
.row img{width:64px;height:64px;border-radius:10px;object-fit:cover;border:1px solid var(--line);background:#f3eee6;flex:0 0 auto;}
.row .meta{min-width:0;}
.row .title{font-size:16px;font-weight:600;line-height:1.25;margin-bottom:4px;overflow:hidden;text-overflow:ellipsis;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;}
.row .when{font-size:13px;color:var(--mute);}
.badge{display:inline-block;font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:2px;text-transform:uppercase;color:var(--teal);border:1px solid var(--teal);border-radius:999px;padding:2px 8px;margin-left:8px;vertical-align:middle;}
.empty{color:var(--mute);text-align:center;padding:40px 0;}
.chev{margin-left:auto;flex:0 0 auto;width:18px;height:18px;stroke:var(--mute);fill:none;stroke-width:2;}
</style></head><body>
""" + NAV_LIGHT + """
<div class="eyebrow">Harbor social</div>
<h1>Sent posts</h1>
{% if not hist %}<div class="empty">No posts sent yet. They show up here after the next scheduled send.</div>{% endif %}
{% for r in hist %}
<a class="row {{ '' if r.available else 'dead' }}" href="/social/post/{{ r.id }}">
  {% if r.available %}<img src="/social/img/{{ r.id }}" alt="" loading="lazy">{% else %}<img alt="">{% endif %}
  <div class="meta">
    <div class="title">{{ r.title }}{% if r.category %}<span class="badge">{{ r.category }}</span>{% endif %}</div>
    <div class="when">{{ r.when }}{% if not r.available %} &middot; archived{% endif %}</div>
  </div>
  <svg class="chev" viewBox="0 0 24 24"><path d="M9 18l6-6-6-6"/></svg>
</a>
{% endfor %}
</body></html>"""


@app.route("/social/sent")
@admin_required
def social_sent():
    import json as _json, time as _time
    try:
        with open(SOCIAL_MANIFEST) as _f:
            man_ids = {e.get("id") for e in _json.load(_f).get("entries", [])}
    except Exception:
        man_ids = set()
    hist = []
    try:
        with open(SOCIAL_HISTORY) as _f:
            lines = _f.readlines()[-200:]
        for ln in reversed(lines):
            try:
                r = _json.loads(ln)
            except Exception:
                continue
            if str(r.get("code")) != "200":
                continue
            hdr = r.get("hdr", "")
            r["title"] = hdr.split(" -> ")[0].split(" / ", 1)[-1] if hdr else r.get("id", "")
            r["when"] = _time.strftime("%b %-d, %-I:%M %p", _time.localtime(r.get("ts", 0)))
            r["available"] = r.get("id") in man_ids
            hist.append(r)
    except Exception:
        pass
    resp = make_response(render_template_string(SOCIAL_HISTORY_HTML, hist=hist, nav_active="social"))
    resp.headers["Cache-Control"] = "no-store"
    return resp

SOCIAL_LIBRARY_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>Social library</title>
<link rel="apple-touch-icon" sizes="180x180" href="/social-icon-180.png">
<link rel="manifest" href="/social-app.webmanifest">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Harbor Social">
<meta name="theme-color" content="#1f5d6b">
<script>if('serviceWorker' in navigator){navigator.serviceWorker.getRegistrations().then(function(rs){rs.forEach(function(r){r.unregister();});}).catch(function(){});}</script>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:880px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:26px;margin:6px 0 4px;}
.sub{color:var(--mute);font-size:14px;margin:0 0 16px;}
.bar{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin-bottom:14px;}
.genwrap{position:relative;}
.genlist{display:none;position:absolute;top:calc(100% + 6px);left:0;z-index:50;background:#fff;border:1px solid var(--line);border-radius:14px;padding:10px;min-width:220px;flex-direction:column;gap:8px;box-shadow:0 12px 32px rgba(26,36,32,0.14);}
.genwrap.open .genlist{display:flex;}
.genlist .btn{justify-content:flex-start;width:100%;}
.genlist select{width:100%;border:1.5px solid var(--line);border-radius:12px;padding:10px;font:14px/1.4 -apple-system,system-ui,sans-serif;color:var(--ink);background:var(--surface-2,#f6f1e7);}
.btn{display:inline-flex;align-items:center;justify-content:center;gap:8px;border:none;border-radius:12px;padding:11px 16px;font-size:14px;font-weight:600;cursor:pointer;background:var(--teal);color:#fff;text-decoration:none;}
.btn.alt{background:#fff;color:var(--teal);border:1.5px solid var(--teal);}
.btn:active{opacity:.85;}.btn[disabled]{opacity:.6;cursor:default;}
.btn svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:16px;}
.chip{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--mute);background:#fff;border:1px solid var(--line);border-radius:999px;padding:6px 12px;cursor:pointer;}
.schedq{background:#fff;border:1px solid var(--line);border-radius:14px;padding:14px 16px;margin-bottom:16px;}
.schedq .qh{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:2px;text-transform:uppercase;color:var(--teal);margin-bottom:10px;}
.schedrow{display:flex;align-items:center;gap:12px;padding:8px 0;border-top:1px solid var(--line);}
.schedrow:first-of-type{border-top:none;}
.schedrow img{width:44px;height:44px;border-radius:8px;object-fit:cover;background:#f3eee6;flex:0 0 auto;}
.schedrow .si{flex:1;min-width:0;}
.schedrow .st{display:block;font-size:14px;font-weight:600;color:inherit;text-decoration:none;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
.schedrow .sm{font-size:12px;color:var(--mute);margin-top:2px;}
.schedrow .scancel{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:1px;text-transform:uppercase;color:var(--mute);background:#fff;border:1px solid var(--line);border-radius:999px;padding:6px 12px;cursor:pointer;flex:0 0 auto;}
.chip.active{color:#fff;background:var(--teal);border-color:var(--teal);}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:12px;}
.card{display:flex;flex-direction:column;background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden;}
.card.posted{opacity:.62;}
.card .thumb{display:block;aspect-ratio:1/1;width:100%;object-fit:cover;background:#f3eee6;border-bottom:1px solid var(--line);}
.card .body{padding:12px;display:flex;flex-direction:column;gap:8px;flex:1;}
.card .title{font-size:15px;font-weight:600;line-height:1.3;color:inherit;text-decoration:none;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;}
.card .badges{display:flex;gap:6px;align-items:center;flex-wrap:wrap;}
.badge{display:inline-block;font-family:ui-monospace,Menlo,monospace;font-size:10px;letter-spacing:1px;text-transform:uppercase;color:var(--teal);border:1px solid var(--teal);border-radius:999px;padding:2px 8px;}
.badge.done{color:#2e7d32;border-color:#2e7d32;}
.card .acts{display:flex;gap:8px;margin-top:auto;}
.card .acts a,.card .acts button{flex:1;font-size:13px;padding:9px;border-radius:10px;}
.mark{background:#fff;color:var(--teal);border:1.5px solid var(--teal);font-weight:600;cursor:pointer;}
.mark.on{background:#eef5ee;color:#2e7d32;border-color:#2e7d32;}
.count{color:var(--mute);font-size:13px;margin-left:auto;}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:#2d2d2d;color:#fff;padding:12px 20px;border-radius:999px;font-size:14px;opacity:0;transition:.25s;pointer-events:none;z-index:9;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style></head><body>
""" + NAV_LIGHT + """
<div class="eyebrow">Harbor social</div>
<h1>Post library</h1>
<p class="sub">Pick a post, copy the caption and image, and schedule it. Mark posts as used so you do not repeat.</p>
<div class="bar">
  <div class="genwrap" id="genWrap">
    <button class="btn" id="genBtn" onclick="document.getElementById('genWrap').classList.toggle('open')">
      <svg viewBox="0 0 24 24"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
      Generate
      <svg viewBox="0 0 24 24" style="width:14px;height:14px;"><path d="M6 9l6 6 6-6"/></svg>
    </button>
    <div class="genlist">
      <button class="btn alt" onclick="genSet(this)">
        <svg viewBox="0 0 24 24"><path d="M21 2v6h-6"/><path d="M3 12a9 9 0 0 1 15-6.7L21 8"/><path d="M3 22v-6h6"/><path d="M21 12a9 9 0 0 1-15 6.7L3 16"/></svg>
        New post set
      </button>
      <button class="btn alt" onclick="genSet(this,'tips')">
        <svg viewBox="0 0 24 24"><path d="M9 18h6"/><path d="M10 22h4"/><path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V18h6v-1.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></svg>
        Tips set
      </button>
      <button class="btn alt" onclick="genReel(this)">
        <svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="2.2"/><line x1="7" y1="2" x2="7" y2="22"/><line x1="17" y1="2" x2="17" y2="22"/><line x1="2" y1="12" x2="22" y2="12"/><line x1="2" y1="7" x2="7" y2="7"/><line x1="2" y1="17" x2="7" y2="17"/><line x1="17" y1="7" x2="22" y2="7"/><line x1="17" y1="17" x2="22" y2="17"/></svg>
        Reel
      </button>
      <select id="petNiche" title="Pet niche">
        <option value="">Pets: rotate niche</option>
        <option value="walkers">Dog walkers</option>
        <option value="groomers">Groomers</option>
        <option value="sitters">Pet sitters</option>
        <option value="mobile">Mobile groomers</option>
      </select>
      <button class="btn alt" onclick="genReel(this,'pets')">
        <svg viewBox="0 0 24 24"><circle cx="11" cy="4" r="2"/><circle cx="18" cy="8" r="2"/><circle cx="20" cy="16" r="2"/><circle cx="4" cy="8" r="2"/><path d="M14.7 16.8a4 4 0 0 0-5.4 0c-1.5 1.4-3.3 2.2-3.3 4 0 1.6 1.4 2.4 3 2.4 1.2 0 1.8-.5 3-.5s1.8.5 3 .5c1.6 0 3-.8 3-2.4 0-1.8-1.8-2.6-3.3-4z"/></svg>
        Pet reel
      </button>
      <button class="btn alt" onclick="genStickerReel(this)" title="Randomized Etsy sticker product reel">
        <svg viewBox="0 0 24 24"><rect x="3" y="6" width="18" height="12" rx="2.5" transform="rotate(-6 12 12)"/><path d="M16 6.5l3 3"/></svg>
        Sticker reel
      </button>
      <button class="btn alt" onclick="genStickerReel(this,'tiktok')" title="Sticker reel with TikTok-safe layout (CTA lifted above the caption bar, link-in-bio)">
        <svg viewBox="0 0 24 24"><path d="M9 3v12.5a3.5 3.5 0 1 1-3.5-3.5"/><path d="M9 6a5 5 0 0 0 5 5V8a2.2 2.2 0 0 1-2.2-2.2V3H9z"/></svg>
        TikTok reel
      </button>
      <button class="btn alt" onclick="genCardsSet(this)" title="Regenerate the full sticker-slogan card set (varied layouts) and push them live to /social">
        <svg viewBox="0 0 24 24"><rect x="3" y="4" width="13" height="16" rx="2"/><path d="M8 9h6M8 13h4"/><path d="M19 7v11a2 2 0 0 1-2 2H8"/></svg>
        Cards set
      </button>
      <button class="btn alt" onclick="genCardsReel(this)" title="Reel that animates the promo card layouts (dark quote, receipt, stat, outline, compare) with Ken Burns motion">
        <svg viewBox="0 0 24 24"><rect x="2" y="3" width="20" height="18" rx="2.2"/><line x1="7" y1="3" x2="7" y2="21"/><line x1="17" y1="3" x2="17" y2="21"/><polygon points="11,9 15,12 11,15"/></svg>
        Cards reel
      </button>
    </div>
  </div>
  <a class="btn alt" href="/social/pages">Apex pages</a>
  <a class="btn alt" href="/social/sent">Sent log</a>
  <span class="count"><b id="visCount">0</b> posts</span>
</div>
<div class="schedq" id="reviewq" style="{{ '' if pending else 'display:none' }};border-left:3px solid #c98a52;">
  <div class="qh" style="color:#c98a52;">Pending review (<span id="reviewCount">{{ pending|length }}</span>)</div>
  {% for p in pending %}
  <div class="schedrow" id="reviewrow-{{ p.id }}">
    <a href="/social/post/{{ p.id }}"><img src="/social/img/{{ p.id }}" alt="" loading="lazy"></a>
    <div class="si">
      <a class="st" href="/social/post/{{ p.id }}">{{ p.title }}</a>
      <div class="sm">{{ p.category }} · AI draft</div>
    </div>
    <button class="scancel" style="border-color:#2e7d32;color:#2e7d32;" onclick="review('{{ p.id }}','approve')">Approve</button>
    <button class="scancel" onclick="review('{{ p.id }}','reject')">Reject</button>
  </div>
  {% endfor %}
</div>
<div class="schedq" id="schedq" style="{{ '' if scheduled else 'display:none' }}">
  <div class="qh">Scheduled (<span id="schedCount">{{ scheduled|length }}</span>)</div>
  {% for s in scheduled %}
  <div class="schedrow" id="schedrow-{{ s.id }}">
    <a href="/social/post/{{ s.id }}"><img src="/social/img/{{ s.id }}" alt="" loading="lazy"></a>
    <div class="si">
      <a class="st" href="/social/post/{{ s.id }}">{{ s.title }}</a>
      <div class="sm"><span data-when="{{ s.scheduled_for }}">…</span> · {{ s.plat_label }}</div>
    </div>
    <button class="scancel" onclick="cancelSched('{{ s.id }}')">Cancel</button>
  </div>
  {% endfor %}
</div>

<div class="chips" id="chips">
  <span class="chip active" data-cat="__all" onclick="filt(this)">All</span>
  {% for c in cats %}<span class="chip" data-cat="{{ c }}" onclick="filt(this)">{{ c }}</span>{% endfor %}
  <span class="chip" data-cat="__unposted" onclick="filt(this)">Unposted</span>
</div>
<div class="grid" id="grid">
{% for e in entries %}
  <div class="card{% if e.posted %} posted{% endif %}" data-cat="{{ e.category }}" data-posted="{{ '1' if e.posted else '0' }}">
    <a href="/social/post/{{ e.id }}"><img class="thumb" src="/social/img/{{ e.id }}" alt="" loading="lazy"></a>
    <div class="body">
      <a class="title" href="/social/post/{{ e.id }}">{{ e.title }}</a>
      <div class="badges"><span class="badge">{{ e.category }}</span><span class="badge done" style="{{ '' if e.posted else 'display:none' }}">Posted</span></div>
      <div class="acts">
        <a class="btn alt" href="/social/post/{{ e.id }}">Open</a>
        <button class="mark{% if e.posted %} on{% endif %}" data-id="{{ e.id }}" onclick="mark(this)">{{ 'Posted' if e.posted else 'Mark posted' }}</button>
      </div>
    </div>
  </div>
{% endfor %}
</div>
<div class="toast" id="toast"></div>
<script>
var CSRF="{{ csrf_token }}";
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show');},1800);}
// render scheduled times in the viewer's local timezone
document.querySelectorAll('#schedq [data-when]').forEach(function(el){
  var ep=parseInt(el.dataset.when,10);
  if(ep) el.textContent=new Date(ep*1000).toLocaleString([],{weekday:'short',month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});
});
async function review(id,action){
  var btns=document.querySelectorAll('#reviewrow-'+id+' button');
  if(action==='approve') btns.forEach(function(b){b.disabled=true;});
  try{
    if(action==='approve') toast('Approved, posting...');
    var r=await fetch('/api/social/review',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:id,action:action})});
    var j=await r.json();
    if(!j.ok){toast(j.error||'Review failed');btns.forEach(function(b){b.disabled=false;});return;}
    var row=document.getElementById('reviewrow-'+id); if(row) row.remove();
    var left=document.querySelectorAll('#reviewq .schedrow').length;
    document.getElementById('reviewCount').textContent=left;
    if(!left) document.getElementById('reviewq').style.display='none';
    if(action==='approve'){
      var posted=j.posted||[],failed=j.failed||[];
      var msg=posted.length?('Posted to '+posted.join(' + ')):'Approved';
      if(failed.length) msg+=' (failed: '+failed.map(function(f){return f.platform;}).join(', ')+')';
      toast(msg);
      setTimeout(function(){location.reload();},900);
    } else {
      toast('Rejected');
    }
  }catch(e){toast('Review failed');btns.forEach(function(b){b.disabled=false;});}
}
async function cancelSched(id){
  try{
    var r=await fetch('/api/social/schedule',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:id,when:null})});
    var j=await r.json();
    if(!j.ok){toast(j.error||'Could not cancel');return;}
    var row=document.getElementById('schedrow-'+id); if(row) row.remove();
    var left=document.querySelectorAll('#schedq .schedrow').length;
    document.getElementById('schedCount').textContent=left;
    if(!left) document.getElementById('schedq').style.display='none';
    toast('Schedule cancelled');
  }catch(e){toast('Could not cancel');}
}
function recount(){document.getElementById('visCount').textContent=document.querySelectorAll('.card:not([style*="display: none"])').length;}
function filt(el){
  document.querySelectorAll('.chip').forEach(function(c){c.classList.remove('active');});
  el.classList.add('active');
  var cat=el.dataset.cat;
  document.querySelectorAll('.card').forEach(function(c){
    var show=true;
    if(cat==='__unposted') show=c.dataset.posted==='0';
    else if(cat!=='__all') show=c.dataset.cat===cat;
    c.style.display=show?'':'none';
  });
  recount();
}
async function mark(btn){
  var id=btn.dataset.id; var on=btn.classList.contains('on'); var want=!on;
  try{
    var r=await fetch('/api/social/posted',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:id,posted:want})});
    var j=await r.json(); if(!j.ok) throw 0;
    var card=btn.closest('.card');
    btn.classList.toggle('on',j.posted); btn.textContent=j.posted?'Posted':'Mark posted';
    card.dataset.posted=j.posted?'1':'0'; card.classList.toggle('posted',j.posted);
    card.querySelector('.badge.done').style.display=j.posted?'':'none';
    toast(j.posted?'Marked as posted':'Marked unposted');
  }catch(e){toast('Could not update');}
}
async function genSet(b,only){
  var label=b.textContent.trim(); b.disabled=true; b.textContent='Generating...';
  try{
    var body={count:5}; if(only){body.only=only;}
    var r=await fetch('/api/social/generate-set',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify(body)});
    var j=await r.json();
    if(j.ok){toast('Added '+j.added+' new posts'); setTimeout(function(){location.reload();},900);}
    else{toast(j.error||'Generation failed'); b.disabled=false; b.textContent=label;}
  }catch(e){toast('Generation failed'); b.disabled=false; b.textContent=label;}
}
async function genReel(b,mode){
  var label=b.textContent.trim(); b.disabled=true; b.textContent='Building reel...';
  var payload=mode?{mode:mode}:{};
  if(mode==='pets'){var sel=document.getElementById('petNiche'); if(sel&&sel.value)payload.niche=sel.value;}
  try{
    var r=await fetch('/api/social/generate-reel',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify(payload)});
    var j=await r.json();
    if(j.ok){toast(mode==='pets'?'Pet reel built':'Reel built'); setTimeout(function(){location.reload();},900);}
    else{toast(j.error||'Reel build failed'); b.disabled=false; b.textContent=label;}
  }catch(e){toast('Reel build failed (timeout?)'); b.disabled=false; b.textContent=label;}
}
async function genStickerReel(b,mode){
  var label=b.textContent.trim(); b.disabled=true; b.textContent='Building reel...';
  try{
    var r=await fetch('/api/social/generate-sticker-reel',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({mode:mode||''})});
    var j=await r.json();
    if(j.ok){toast(mode==='tiktok'?'TikTok reel built':'Sticker reel built'); setTimeout(function(){location.reload();},900);}
    else{toast(j.error||'Reel build failed'); b.disabled=false; b.textContent=label;}
  }catch(e){toast('Reel build failed (timeout?)'); b.disabled=false; b.textContent=label;}
}
async function genCardsSet(b){
  var label=b.textContent.trim(); b.disabled=true; b.textContent='Building cards...';
  try{
    var r=await fetch('/api/social/generate-cards-set',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({})});
    var j=await r.json();
    if(j.ok){toast('Cards set pushed ('+(j.n||'')+')'); setTimeout(function(){location.reload();},900);}
    else{toast(j.error||'Cards build failed'); b.disabled=false; b.textContent=label;}
  }catch(e){toast('Cards build failed (timeout?)'); b.disabled=false; b.textContent=label;}
}
async function genCardsReel(b){
  var label=b.textContent.trim(); b.disabled=true; b.textContent='Building reel...';
  try{
    var r=await fetch('/api/social/generate-cards-reel',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({})});
    var j=await r.json();
    if(j.ok){toast('Cards reel built'); setTimeout(function(){location.reload();},900);}
    else{toast(j.error||'Reel build failed'); b.disabled=false; b.textContent=label;}
  }catch(e){toast('Reel build failed (timeout?)'); b.disabled=false; b.textContent=label;}
}
recount();
document.addEventListener('click',function(e){var w=document.getElementById('genWrap');if(w&&!w.contains(e.target))w.classList.remove('open');});
</script></body></html>"""


@app.route("/social")
@admin_required
def social():
    import json as _json
    try:
        with open(SOCIAL_MANIFEST) as _f:
            entries = _json.load(_f).get("entries", [])
    except Exception:
        entries = []
    posted = _load_posted()
    out, pending = [], []
    for e in entries:
        hdr = e.get("hdr", "")
        title = hdr.split(" -> ")[0].split(" / ", 1)[-1] if hdr else e.get("id", "")
        plats = e.get("scheduled_platforms") or []
        st = _entry_status(e)
        row = {"id": e.get("id"), "title": title,
               "category": e.get("category", "Other"),
               "posted": bool(posted.get(e.get("id"))),
               "scheduled_for": e.get("scheduled_for"),
               "status": st,
               "plat_label": " + ".join({"fb": "Facebook", "ig": "Instagram"}.get(p, p) for p in plats)}
        if st == "pending":
            pending.append(row)
        elif st == "rejected":
            continue  # hidden from the live library
        else:
            out.append(row)
    # newest entries first so freshly generated sets show on top
    out.reverse()
    pending.reverse()
    cats = sorted({o["category"] for o in out})
    # upcoming scheduled posts, soonest first, for the queue at the top
    _now = int(_time.time())
    scheduled = sorted((o for o in out if o.get("scheduled_for") and int(o["scheduled_for"]) > _now), key=lambda o: o["scheduled_for"])
    resp = make_response(render_template_string(SOCIAL_LIBRARY_HTML, entries=out, cats=cats,
                                                scheduled=scheduled, pending=pending, nav_active="social"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/social/posted", methods=["POST"])
@admin_required
def social_mark_posted():
    import time as _time
    data = request.json or {}
    pid = data.get("id", "")
    want = bool(data.get("posted", True))
    if not pid:
        return jsonify({"ok": False, "error": "missing id"}), 400
    posted = _load_posted()
    if want:
        posted[pid] = int(_time.time())
    else:
        posted.pop(pid, None)
    _save_posted(posted)
    return jsonify({"ok": True, "posted": want})


@app.route("/api/social/review", methods=["POST"])
@admin_required
def social_review():
    """Approve or reject a pending AI draft. The actual policy (what reject does,
    whether an approve can be refused) lives in _review_decision() — yours to own.
    An approve also fires the post to FB + IG immediately (no separate button tap),
    reusing the same _publish_fb/_publish_ig the one-tap buttons and scheduler use."""
    d = request.json or {}
    pid = d.get("id", "")
    action = d.get("action", "")
    if action not in ("approve", "reject"):
        return jsonify({"ok": False, "error": "bad action"}), 400
    entry = _social_entry(pid)
    if not entry:
        return jsonify({"ok": False, "error": "post not found"}), 404
    try:
        new_status = _review_decision(action, entry)
    except NotImplementedError as e:
        return jsonify({"ok": False, "error": str(e)}), 501
    if new_status is None:
        _social_delete_entry(pid)
        return jsonify({"ok": True, "deleted": True})
    _social_update_entry(pid, status=new_status)
    result = {"ok": True, "status": new_status}
    if new_status == "approved":
        entry = _social_entry(pid) or entry
        posted, failed = [], []
        if entry.get("source") != "reel" and META_PAGE_ID and META_PAGE_TOKEN:
            fb_ok, fb_msg = _publish_fb(pid, entry)
            (posted if fb_ok else failed).append(("Facebook", fb_msg))
        if META_IG_ID and META_PAGE_TOKEN:
            ig_ok, ig_msg = _publish_ig(pid, entry)
            (posted if ig_ok else failed).append(("Instagram", ig_msg))
        result["posted"] = [p[0] for p in posted]
        result["failed"] = [{"platform": p[0], "error": p[1]} for p in failed]
        if failed:
            _ntfy("Auto-post failed after approve", f"{pid}\n" +
                  "\n".join(f"{p}: {m}" for p, m in failed), tags="warning")
    return jsonify(result)


def _publish_fb(pid, entry):
    """Publish an entry's image + caption to the FB Page. Returns (ok, msg) where
    msg is the post id on success or an error string. Marks posted on success.
    Shared by the one-tap route and the scheduler runner."""
    import time as _time, requests as _req, pathlib
    if not (META_PAGE_ID and META_PAGE_TOKEN):
        return False, "Facebook Page not configured"
    if not (pathlib.Path("/home/ubuntu/harbor-design-system/assets/social") / f"{pid}.png").exists():
        return False, "no local image for this post"
    img = f"{SOCIAL_PUBLIC_BASE}/{pid}.png"
    try:
        r = _req.post(f"https://graph.facebook.com/v21.0/{META_PAGE_ID}/photos",
                      data={"url": img, "caption": entry.get("body", ""), "access_token": META_PAGE_TOKEN},
                      timeout=40)
        j = r.json()
    except Exception as e:
        return False, f"request failed: {e}"
    if r.status_code != 200 or "error" in j:
        return False, (j.get("error", {}) or {}).get("message", f"HTTP {r.status_code}")
    posted = _load_posted()
    posted[pid] = int(_time.time())
    _save_posted(posted)
    # NOTE: FB Page Story auto-share is intentionally NOT called. Meta gates the
    # /photo_stories endpoint behind granular app-review permissions this app does
    # not have (returns "(#3) Application does not have the granular permission").
    # _publish_fb_story() is kept for if the app ever clears review. IG stories,
    # which need no such review, are auto-shared in _publish_ig.
    return True, (j.get("post_id") or j.get("id", ""))


@app.route("/api/social/post-fb", methods=["POST"])
@admin_required
def social_post_fb():
    pid = (request.json or {}).get("id", "")
    entry = _social_entry(pid)
    if not entry:
        return jsonify({"ok": False, "error": "post not found"}), 404
    ok, msg = _publish_fb(pid, entry)
    return (jsonify({"ok": True, "fb_post_id": msg}), 200) if ok else (jsonify({"ok": False, "error": msg}), 502)


def _pinterest_token():
    """Return a usable Pinterest v5 access token. Prefer refreshing (refresh
    tokens last ~1yr; access tokens expire), fall back to the static env token."""
    import base64, requests as _req
    if PINTEREST_APP_ID and PINTEREST_APP_SECRET and PINTEREST_REFRESH_TOKEN:
        basic = base64.b64encode(f"{PINTEREST_APP_ID}:{PINTEREST_APP_SECRET}".encode()).decode()
        try:
            r = _req.post("https://api.pinterest.com/v5/oauth/token",
                          headers={"Authorization": f"Basic {basic}",
                                   "Content-Type": "application/x-www-form-urlencoded"},
                          data={"grant_type": "refresh_token",
                                "refresh_token": PINTEREST_REFRESH_TOKEN},
                          timeout=30)
            j = r.json()
            if r.status_code == 200 and j.get("access_token"):
                return j["access_token"]
        except Exception as e:
            print(f"pinterest: token refresh failed: {e!r}", flush=True)
    return PINTEREST_ACCESS_TOKEN or ""


def _publish_pinterest(pid, entry):
    """Create a Pin from an entry's image + caption. Returns (ok, msg) where msg
    is the pin id on success or an error string. Mirrors _publish_fb's contract,
    but intentionally does NOT touch shared posted-state (Pinterest is additive)."""
    import requests as _req
    if not PINTEREST_BOARD_ID:
        return False, "Pinterest board not configured"
    tok = _pinterest_token()
    if not tok:
        return False, "no Pinterest access token (check refresh creds)"
    # Pinterest fetches the image by URL; reuse the public JPEG renderer (IG path).
    img = _ensure_jpeg(pid, png_url=f"{SOCIAL_PUBLIC_BASE}/{pid}.png")
    if not img:
        return False, "no image for this post"
    hdr = entry.get("hdr", "")
    title = (hdr.split(" -> ")[0].split(" / ", 1)[-1] if hdr else entry.get("id", ""))[:100]
    desc = (entry.get("body", "") or title)[:800]
    body = {"board_id": PINTEREST_BOARD_ID, "title": title, "description": desc,
            "link": entry.get("link") or "https://harborprivacy.com",
            "media_source": {"source_type": "image_url", "url": img}}
    try:
        r = _req.post("https://api.pinterest.com/v5/pins",
                      headers={"Authorization": f"Bearer {tok}",
                               "Content-Type": "application/json"},
                      json=body, timeout=40)
        j = r.json()
    except Exception as e:
        return False, f"request failed: {e}"
    if r.status_code not in (200, 201) or "id" not in j:
        return False, (j.get("message") or f"HTTP {r.status_code}")
    return True, j["id"]


@app.route("/api/social/post-pinterest", methods=["POST"])
@admin_required
def social_post_pinterest():
    pid = (request.json or {}).get("id", "")
    entry = _social_entry(pid)
    if not entry:
        return jsonify({"ok": False, "error": "post not found"}), 404
    ok, msg = _publish_pinterest(pid, entry)
    return (jsonify({"ok": True, "pin_id": msg}), 200) if ok else (jsonify({"ok": False, "error": msg}), 502)


def _oauth1_header(method, url):
    """OAuth 1.0a Authorization header for X. Signs over oauth_* params only; we
    send media as multipart and the tweet as JSON, neither of which contributes
    to the signature base string."""
    import time as _t, secrets as _secrets, hmac, hashlib, base64
    from urllib.parse import quote
    q = lambda s: quote(str(s), safe="")
    oauth = {
        "oauth_consumer_key": X_API_KEY,
        "oauth_nonce": _secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(_t.time())),
        "oauth_token": X_ACCESS_TOKEN,
        "oauth_version": "1.0",
    }
    base_params = "&".join(f"{q(k)}={q(oauth[k])}" for k in sorted(oauth))
    base = "&".join([method.upper(), q(url), q(base_params)])
    key = f"{q(X_API_SECRET)}&{q(X_ACCESS_SECRET)}"
    oauth["oauth_signature"] = base64.b64encode(
        hmac.new(key.encode(), base.encode(), hashlib.sha1).digest()).decode()
    return "OAuth " + ", ".join(f'{q(k)}="{q(v)}"' for k, v in sorted(oauth.items()))


def _publish_x(pid, entry):
    """Upload the post image to X and create a tweet. Returns (ok, msg) with msg =
    tweet id on success. Mirrors _publish_fb's contract; additive (no posted-state)."""
    import requests as _req, pathlib
    if not (X_API_KEY and X_API_SECRET and X_ACCESS_TOKEN and X_ACCESS_SECRET):
        return False, "X not configured"
    _ensure_jpeg(pid, png_url=f"{SOCIAL_PUBLIC_BASE}/{pid}.png")
    base = pathlib.Path("/home/ubuntu/harbor-design-system/assets/social")
    img = base / f"{pid}.jpg"
    if not img.exists():
        img = base / f"{pid}.png"
    if not img.exists():
        return False, "no image for this post"
    # 1) media upload (v1.1, multipart)
    up_url = "https://upload.twitter.com/1.1/media/upload.json"
    try:
        with open(img, "rb") as fh:
            r = _req.post(up_url, headers={"Authorization": _oauth1_header("POST", up_url)},
                          files={"media": fh}, timeout=60)
    except Exception as e:
        return False, f"media upload failed: {e}"
    if r.status_code != 200:
        return False, f"media upload HTTP {r.status_code}: {r.text[:120]}"
    media_id = (r.json() or {}).get("media_id_string")
    if not media_id:
        return False, "no media_id from X"
    # 2) create tweet (v2, JSON)
    tw_url = "https://api.twitter.com/2/tweets"
    text = (entry.get("body", "") or entry.get("hdr", ""))[:280]
    try:
        r = _req.post(tw_url, headers={"Authorization": _oauth1_header("POST", tw_url),
                                       "Content-Type": "application/json"},
                      json={"text": text, "media": {"media_ids": [media_id]}}, timeout=40)
    except Exception as e:
        return False, f"tweet failed: {e}"
    if r.status_code not in (200, 201):
        return False, f"tweet HTTP {r.status_code}: {r.text[:140]}"
    return True, (r.json().get("data", {}) or {}).get("id", "ok")


@app.route("/api/social/post-x", methods=["POST"])
@admin_required
def social_post_x():
    pid = (request.json or {}).get("id", "")
    entry = _social_entry(pid)
    if not entry:
        return jsonify({"ok": False, "error": "post not found"}), 404
    ok, msg = _publish_x(pid, entry)
    return (jsonify({"ok": True, "tweet_id": msg}), 200) if ok else (jsonify({"ok": False, "error": msg}), 502)


@app.route("/social/public/<fname>")
def social_public_img(fname):
    # Public, unauthenticated: Meta fetches post images by URL when publishing.
    # Restricted to png/jpg in the social asset dir; no path traversal.
    import re, pathlib
    from flask import send_file
    if not re.fullmatch(r"[A-Za-z0-9_-]+\.(png|jpg|mp4)", fname or ""):
        return "not found", 404
    p = pathlib.Path("/home/ubuntu/harbor-design-system/assets/social") / fname
    if not p.exists():
        return "not found", 404
    mt = "video/mp4" if fname.endswith(".mp4") else ("image/jpeg" if fname.endswith(".jpg") else "image/png")
    resp = make_response(send_file(str(p), mimetype=mt))
    resp.headers["Cache-Control"] = "public, max-age=86400"
    return resp


def _ensure_jpeg(pid, png_url=""):
    # Instagram's Content Publishing API only accepts JPEG. Render a flattened RGB
    # JPEG next to the PNG so it is public at assets.harborprivacy.com/raw/social.
    import pathlib, io, requests as _req
    from PIL import Image
    base = pathlib.Path("/home/ubuntu/harbor-design-system/assets/social")
    jpg = base / (pid + ".jpg")
    # Regenerate if missing OR a prior render left a zero-byte/partial file.
    if not (jpg.exists() and jpg.stat().st_size > 0):
        png = base / (pid + ".png")
        try:
            if png.exists():
                im = Image.open(png)
            elif png_url.startswith("http"):
                im = Image.open(io.BytesIO(_req.get(png_url, timeout=30).content))
            else:
                return None
            if im.mode in ("RGBA", "P", "LA"):
                bg = Image.new("RGB", im.size, (251, 247, 241))  # cream card bg
                bg.paste(im.convert("RGBA"), mask=im.convert("RGBA").split()[-1])
                im = bg
            else:
                im = im.convert("RGB")
            # Write atomically: Meta fetches this URL the instant the container is
            # created, and a non-atomic save lets it read a half-written JPEG, which
            # IG rejects as "Only photo or video can be accepted as media type".
            tmp = jpg.with_suffix(".jpg.tmp")
            im.save(tmp, "JPEG", quality=90)
            os.replace(tmp, jpg)
        except Exception as e:
            print(f"post-ig: jpeg render failed {pid}: {e!r}", flush=True)
            return None
    return f"{SOCIAL_PUBLIC_BASE}/{pid}.jpg"


def _ensure_story_jpeg(pid):
    """9:16 (1080x1920) Story version: the post image centered on the brand cream
    background, so a square feed image is not cropped when shared to a Story
    (mirrors what Business Suite does when it reposts a feed image as a story)."""
    import pathlib, io, requests as _req
    from PIL import Image
    base = pathlib.Path("/home/ubuntu/harbor-design-system/assets/social")
    out = base / (pid + "-story.jpg")
    if out.exists():
        return f"{SOCIAL_PUBLIC_BASE}/{pid}-story.jpg"
    src = base / (pid + ".jpg")
    if not src.exists():
        src = base / (pid + ".png")
    if not src.exists():
        return None
    CREAM = (251, 247, 241)
    try:
        im = Image.open(src)
        if im.mode in ("RGBA", "P", "LA"):
            bg0 = Image.new("RGB", im.size, CREAM)
            bg0.paste(im.convert("RGBA"), mask=im.convert("RGBA").split()[-1])
            im = bg0
        elif im.mode != "RGB":
            im = im.convert("RGB")
        W, H, margin = 1080, 1920, 70
        canvas = Image.new("RGB", (W, H), CREAM)
        tw = W - 2 * margin
        nw, nh = tw, int(im.height * (tw / im.width))
        if nh > H - 2 * margin:
            nh = H - 2 * margin
            nw = int(im.width * (nh / im.height))
        canvas.paste(im.resize((nw, nh), Image.LANCZOS), ((W - nw) // 2, (H - nh) // 2))
        canvas.save(out, "JPEG", quality=90)
    except Exception as e:
        print(f"story jpeg failed {pid}: {e!r}", flush=True)
        return None
    return f"{SOCIAL_PUBLIC_BASE}/{pid}-story.jpg"


def _publish_ig_story(pid):
    """Post the Story version to Instagram (media_type=STORIES). Returns (ok, msg)."""
    import time as _time, requests as _req
    if not (META_IG_ID and META_PAGE_TOKEN):
        return False, "IG not configured"
    img = _ensure_story_jpeg(pid)
    if not img:
        return False, "no story image"
    base = f"https://graph.facebook.com/v21.0/{META_IG_ID}"
    try:
        c = _req.post(f"{base}/media",
                      data={"image_url": img, "media_type": "STORIES", "access_token": META_PAGE_TOKEN},
                      timeout=60).json()
        cid = c.get("id")
        if not cid:
            return False, (c.get("error", {}) or {}).get("message", "container failed")
        status = ""
        for _ in range(15):
            s = _req.get(f"https://graph.facebook.com/v21.0/{cid}",
                         params={"fields": "status_code", "access_token": META_PAGE_TOKEN}, timeout=30).json()
            status = s.get("status_code", "")
            if status in ("FINISHED", "ERROR", "EXPIRED"):
                break
            _time.sleep(2)
        if status != "FINISHED":
            return False, f"image not ready (status {status or 'unknown'})"
        p = _req.post(f"{base}/media_publish",
                      data={"creation_id": cid, "access_token": META_PAGE_TOKEN}, timeout=60).json()
    except Exception as e:
        return False, f"request failed: {e}"
    if not p.get("id"):
        return False, (p.get("error", {}) or {}).get("message", "publish failed")
    return True, p.get("id")


def _publish_fb_story(pid):
    """Post the Story version to the FB Page (two-step: unpublished photo -> photo_stories)."""
    import requests as _req
    if not (META_PAGE_ID and META_PAGE_TOKEN):
        return False, "FB not configured"
    img = _ensure_story_jpeg(pid)
    if not img:
        return False, "no story image"
    base = f"https://graph.facebook.com/v21.0/{META_PAGE_ID}"
    try:
        up = _req.post(f"{base}/photos",
                       data={"url": img, "published": "false", "access_token": META_PAGE_TOKEN}, timeout=40).json()
        photo_id = up.get("id")
        if not photo_id:
            return False, (up.get("error", {}) or {}).get("message", "photo upload failed")
        r = _req.post(f"{base}/photo_stories",
                      data={"photo_id": photo_id, "access_token": META_PAGE_TOKEN}, timeout=40).json()
    except Exception as e:
        return False, f"request failed: {e}"
    if not (r.get("success") or r.get("post_id") or r.get("id")):
        return False, (r.get("error", {}) or {}).get("message", "story publish failed")
    return True, (r.get("post_id") or r.get("id") or "ok")


# Instagram captions render links as plain text (not clickable), so swap any
# Harbor URL for a "Link in bio" pointer. Hashtags and the rest are untouched.
# Mirrored in JS as igCaption() on the post detail page for the manual copy path.
_IG_URL_RE = re.compile(r"(?:https?://)?[A-Za-z0-9.\-]*harborprivacy\.(?:com|app)\S*")
def _ig_caption(body):
    if not body:
        return body
    return _IG_URL_RE.sub("Link in bio \U0001F517", body).strip()


def _publish_ig(pid, entry):
    """Publish an entry to the linked Instagram Business account. Returns (ok, msg)
    where msg is the IG post id on success or an error string. Marks posted on
    success. Shared by the one-tap route and the scheduler runner."""
    import time as _time, requests as _req
    if not (META_IG_ID and META_PAGE_TOKEN):
        return False, "Instagram not configured"
    base = f"https://graph.facebook.com/v21.0/{META_IG_ID}"
    is_reel = entry.get("source") == "reel"
    caption = _ig_caption(entry.get("body", ""))
    try:
        if is_reel:
            # Post the actual reel video as an IG Reel (media_type=REELS), not the
            # static poster. share_to_feed also drops it in the main feed.
            container = {"media_type": "REELS", "video_url": f"{SOCIAL_PUBLIC_BASE}/{pid}.mp4",
                         "caption": caption, "share_to_feed": "true", "access_token": META_PAGE_TOKEN}
            poll_n = 45  # video transcoding is slower than image ingest
        else:
            jpg = _ensure_jpeg(pid, entry.get("img", ""))
            if not jpg:
                return False, "could not render a JPEG for this post"
            container = {"image_url": jpg, "caption": caption, "access_token": META_PAGE_TOKEN}
            poll_n = 15
        cid = None
        for attempt in range(3):
            c = _req.post(f"{base}/media", data=container, timeout=60).json()
            cid = c.get("id")
            if cid:
                break
            emsg = (c.get("error", {}) or {}).get("message", "container failed")
            # A media-type/format/fetch error here is usually a transient race: Meta
            # tried to pull the URL before it was fully servable. Wait and retry.
            if attempt < 2 and any(k in emsg.lower() for k in ("media type", "format", "fetch", "download")):
                _time.sleep(3)
                continue
            return False, emsg
        # IG ingests/transcodes asynchronously. Publishing before the container is
        # FINISHED fails with "Media ID is not available", so poll status_code.
        status = ""
        for _ in range(poll_n):
            s = _req.get(f"https://graph.facebook.com/v21.0/{cid}",
                         params={"fields": "status_code", "access_token": META_PAGE_TOKEN},
                         timeout=30).json()
            status = s.get("status_code", "")
            if status in ("FINISHED", "ERROR", "EXPIRED"):
                break
            _time.sleep(2)
        if status != "FINISHED":
            return False, f"media not ready (status {status or 'unknown'})"
        p = _req.post(f"{base}/media_publish",
                      data={"creation_id": cid, "access_token": META_PAGE_TOKEN},
                      timeout=60).json()
    except Exception as e:
        return False, f"request failed: {e}"
    if not p.get("id"):
        return False, (p.get("error", {}) or {}).get("message", "publish failed")
    posted = _load_posted()
    posted[pid] = int(_time.time())
    _save_posted(posted)
    # Auto-share to the IG Story too, like Business Suite. Best effort.
    sok, smsg = _publish_ig_story(pid)
    if not sok:
        log.error("IG story failed for %s: %s", pid, smsg)
        _ntfy("IG story did not post", f"{pid}\n{smsg}\n(feed post went out fine)", tags="warning")
    return True, p.get("id")


@app.route("/api/social/post-ig", methods=["POST"])
@admin_required
def social_post_ig():
    pid = (request.json or {}).get("id", "")
    entry = _social_entry(pid)
    if not entry:
        return jsonify({"ok": False, "error": "post not found"}), 404
    ok, msg = _publish_ig(pid, entry)
    return (jsonify({"ok": True, "ig_post_id": msg}), 200) if ok else (jsonify({"ok": False, "error": msg}), 502)


def _social_update_entry(pid, **fields):
    """Patch fields onto one manifest entry, atomic write. A value of None deletes
    that key. Returns the updated entry, or None if the id was not found."""
    import json as _json, tempfile as _tf, os as _os
    try:
        with open(SOCIAL_MANIFEST) as _f:
            man = _json.load(_f)
    except Exception:
        return None
    hit = None
    for e in man.get("entries", []):
        if e.get("id") == pid:
            hit = e
            for k, v in fields.items():
                if v is None:
                    e.pop(k, None)
                else:
                    e[k] = v
            break
    if hit is None:
        return None
    fd, tmp = _tf.mkstemp(dir=_os.path.dirname(SOCIAL_MANIFEST), prefix=".manifest-", suffix=".tmp")
    with _os.fdopen(fd, "w") as _f:
        _json.dump(man, _f, indent=2)
    _os.replace(tmp, SOCIAL_MANIFEST)
    return hit


def _social_delete_entry(pid):
    """Remove one entry from the manifest, atomic write. Returns True if removed.
    Used by the review flow when _review_decision() returns None (hard delete)."""
    import json as _json, tempfile as _tf, os as _os
    try:
        with open(SOCIAL_MANIFEST) as _f:
            man = _json.load(_f)
    except Exception:
        return False
    before = man.get("entries", [])
    after = [e for e in before if e.get("id") != pid]
    if len(after) == len(before):
        return False
    man["entries"] = after
    fd, tmp = _tf.mkstemp(dir=_os.path.dirname(SOCIAL_MANIFEST), prefix=".manifest-", suffix=".tmp")
    with _os.fdopen(fd, "w") as _f:
        _json.dump(man, _f, indent=2)
    _os.replace(tmp, SOCIAL_MANIFEST)
    return True


@app.route("/api/social/schedule", methods=["POST"])
@admin_required
def social_schedule():
    """Set or clear a post's scheduled publish time. Body: {id, when (epoch secs or
    null to cancel), platforms: ['fb','ig']}. The minute cron fires due posts."""
    import time as _time
    d = request.json or {}
    pid = d.get("id", "")
    _se = _social_entry(pid)
    if not _se:
        return jsonify({"ok": False, "error": "post not found"}), 404
    when = d.get("when")
    if when and _entry_status(_se) != "approved":
        return jsonify({"ok": False, "error": "approve this draft before scheduling it"}), 409
    if not when:  # cancel
        _social_update_entry(pid, scheduled_for=None, scheduled_platforms=None)
        return jsonify({"ok": True, "scheduled_for": None})
    try:
        when = int(when)
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "bad time"}), 400
    if when < int(_time.time()) + 60:
        return jsonify({"ok": False, "error": "pick a time at least a minute from now"}), 400
    platforms = [p for p in (d.get("platforms") or []) if p in ("fb", "ig")]
    if not platforms:
        return jsonify({"ok": False, "error": "choose Facebook and/or Instagram"}), 400
    _social_update_entry(pid, scheduled_for=when, scheduled_platforms=platforms)
    return jsonify({"ok": True, "scheduled_for": when, "platforms": platforms})


def _ntfy(title, body, tags="warning", priority="default"):
    """Best-effort push to the harbor-alerts ntfy topic. No-op without NTFY_AUTH."""
    import requests as _req
    auth = os.environ.get("NTFY_AUTH", "")
    try:
        _req.post("https://ntfy.harborprivacy.com/harbor-alerts",
                  data=body.encode(),
                  headers={"Title": title, "Tags": tags, "Priority": priority,
                           **({"Authorization": f"Basic {auth}"} if auth else {})},
                  timeout=5)
    except Exception:
        pass


@app.route("/api/social/run-due", methods=["POST"])
def social_run_due():
    """Cron-fired every minute. Publishes any post whose scheduled_for has passed,
    via the same helpers the one-tap buttons use. Protected by AUTOPOST_SECRET."""
    import json as _json, time as _time
    expected = os.environ.get("AUTOPOST_SECRET", "")
    if not expected:
        return jsonify({"error": "AUTOPOST_SECRET not set"}), 503
    if not secrets.compare_digest(request.headers.get("X-Autopost-Secret", ""), expected):
        return jsonify({"error": "unauthorized"}), 401
    now = int(_time.time())
    try:
        with open(SOCIAL_MANIFEST) as _f:
            entries = _json.load(_f).get("entries", [])
    except Exception:
        entries = []
    due = [e for e in entries if e.get("scheduled_for") and int(e["scheduled_for"]) <= now
           and _entry_status(e) == "approved"]
    fired = []
    for e in due:
        pid = e["id"]
        plats = e.get("scheduled_platforms") or ["fb", "ig"]
        out = {}
        if "fb" in plats:
            ok, msg = _publish_fb(pid, e); out["fb"] = "ok" if ok else msg
        if "ig" in plats:
            ok, msg = _publish_ig(pid, e); out["ig"] = "ok" if ok else msg
        # Clear the schedule after the attempt so a hard failure cannot re-fire
        # every minute. Record the outcome on the entry for the dashboard to show.
        _social_update_entry(pid, scheduled_for=None, scheduled_platforms=None,
                             last_publish={"at": now, "result": out})
        if any(v != "ok" for v in out.values()):
            log.error("scheduled publish had failures for %s: %s", pid, out)
            fails = "; ".join(f"{k.upper()}: {v}" for k, v in out.items() if v != "ok")
            _ntfy("Scheduled post failed", f"{pid}\n{fails}\nReschedule from the dashboard.",
                  tags="warning,calendar", priority="high")
        fired.append({"id": pid, "result": out})
    return jsonify({"ok": True, "count": len(fired), "fired": fired})


@app.route("/api/social/autopost-cards", methods=["POST"])
def social_autopost_cards():
    """Cron-fired (Mon/Wed/Fri). Fully autonomous: posts the next card from the
    card-engine slogan set (source=sticker, the "new social generate") directly to
    FB + IG via the same helpers the one-tap buttons use. No review queue.
    Protected by AUTOPOST_SECRET. Honors the /var/log/harbor-social-paused flag.
    Rotation is a shuffle-bag in ~/.social-autopost-bag.json so a card does not
    repeat until the whole set has been posted."""
    import json as _json, time as _time, random as _random, pathlib as _pl
    expected = os.environ.get("AUTOPOST_SECRET", "")
    if not expected:
        return jsonify({"error": "AUTOPOST_SECRET not set"}), 503
    if not secrets.compare_digest(request.headers.get("X-Autopost-Secret", ""), expected):
        return jsonify({"error": "unauthorized"}), 401
    if os.path.exists("/var/log/harbor-social-paused"):
        return jsonify({"ok": True, "skipped": "paused"})
    try:
        with open(SOCIAL_MANIFEST) as _f:
            entries = _json.load(_f).get("entries", [])
    except Exception as e:
        return jsonify({"error": f"manifest: {e}"}), 500
    card_dir = _pl.Path("/home/ubuntu/harbor-design-system/assets/social")
    cards = [e for e in entries if e.get("source") == "sticker"
             and (card_dir / f"{e['id']}.png").exists()]
    if not cards:
        return jsonify({"error": "no card-engine cards to post"}), 500
    ids = [e["id"] for e in cards]
    idset = set(ids)
    bag_path = _pl.Path("/home/ubuntu/.social-autopost-bag.json")
    try:
        bag = [i for i in _json.loads(bag_path.read_text()).get("bag", []) if i in idset]
    except Exception:
        bag = []
    if not bag:
        bag = list(ids)
        _random.shuffle(bag)
    pid = bag.pop(0)
    bag_path.write_text(_json.dumps({"bag": bag}))
    entry = next(e for e in cards if e["id"] == pid)
    out = {}
    okfb, mfb = _publish_fb(pid, entry); out["fb"] = "ok" if okfb else mfb
    okig, mig = _publish_ig(pid, entry); out["ig"] = "ok" if okig else mig
    try:
        with open("/home/ubuntu/.social-post-history.jsonl", "a") as hf:
            hf.write(_json.dumps({"ts": int(_time.time()), "id": pid,
                "hdr": entry.get("hdr", ""), "result": out, "mode": "autopost-cards"}) + "\n")
    except Exception:
        pass
    if any(v != "ok" for v in out.values()):
        fails = "; ".join(f"{k.upper()}: {v}" for k, v in out.items() if v != "ok")
        _ntfy("Auto-post failed", f"{pid}\n{fails}", tags="warning", priority="high")
    else:
        _ntfy("Auto-posted to FB + IG", entry.get("hdr", pid), tags="bullhorn")
    return jsonify({"ok": True, "id": pid, "result": out})


@app.route("/api/social/generate-set", methods=["POST"])
@admin_required
def social_generate_set():
    import json as _json, time as _time, random as _random, requests as _req
    try:
        count = int((request.json or {}).get("count", 5))
    except Exception:
        count = 5
    count = max(1, min(count, 8))

    pools = {
        "harbor": ["why incognito mode is not actually private",
                   "smart TVs spying on your viewing habits",
                   "what your ISP knows about your family",
                   "blocking ads before they load on every device",
                   "why public WiFi is dangerous and how to stay safe",
                   "trackers following you across every device"],
        "career": ["ATS resume filtering",
                   "cover letter that actually matches the job posting",
                   "why generic cover letters get ignored",
                   "the 6-second resume rule and how to beat it"],
        "fax":    ["send a fax anonymously without an account",
                   "why doctors and lawyers still require fax",
                   "send a fax from your phone in two minutes"],
        "booking":["let clients book appointments online 24/7",
                   "reduce no-shows with automatic reminders",
                   "free booking software for small businesses"],
        "money":  ["budgeting without your bank login",
                   "private budgeting that does not sell your spending",
                   "forward receipts and alerts to track spending privately"],
        "burn":   ["send a password as a link that self-destructs after one open",
                   "stop pasting passwords into email and chat where they live forever",
                   "share a WiFi or door code with a guest using a one-time burn link",
                   "end-to-end encrypted notes where even we cannot read the contents"],
        "tips":   ["turn off your Windows advertising ID so apps stop profiling you",
                   "disable Windows activity history and timeline tracking",
                   "stop Windows from sending diagnostic and typing data to Microsoft",
                   "turn off the Windows 11 lock screen and Start menu ads",
                   "delete your Android advertising ID in one settings toggle",
                   "stop Android apps from grabbing your location in the background",
                   "turn off Android personalized ads",
                   "check which Android apps can use your microphone and camera",
                   "turn off iPhone app tracking with one toggle",
                   "stop your iPhone from sharing your precise location with apps",
                   "turn off iPhone personalized ads in settings",
                   "limit which photos an iPhone app can actually see",
                   "turn off iPhone Significant Locations history",
                   "disable your smart TV's automatic content recognition tracking",
                   "stop Amazon Echo and Alexa from saving your voice recordings",
                   "turn off ad tracking on a Roku or Fire TV stick",
                   "turn off location history and web activity in your Google account"],
    }
    # Tips draw from the live, web-harvested tip bank (refresh-tips.py via Gemini
    # search grounding) so the "Tips set" button stops repeating the static list.
    try:
        _tb = _json.load(open("/home/ubuntu/tip-bank.json")).get("tips", [])
        _fresh = [t["idea"] for t in _tb if isinstance(t, dict) and t.get("idea")]
        if _fresh:
            pools["tips"] = _fresh
    except Exception:
        pass
    only = (request.json or {}).get("only")
    if only in pools:
        brands = [only]
    else:
        brands = list(pools.keys())

    # Load the manifest up front so picks can dedup against topics already
    # generated in earlier runs. Mirrors the used_seeds rotation the cron
    # (social-refresh.py) uses so the on-demand button stops repeating.
    added, ids = 0, []
    try:
        with open(SOCIAL_MANIFEST) as _f:
            man = _json.load(_f)
    except Exception:
        man = {"version": 1, "entries": []}
    man.setdefault("entries", [])
    used_set = set(man.setdefault("used_topics", []))

    def _avail(b):
        """Topics for brand b not used recently; restart the brand's rotation
        (forget its history) once every one of its topics has been used."""
        fresh = [t for t in pools[b] if t not in used_set]
        if not fresh:
            for t in pools[b]:
                used_set.discard(t)
            fresh = pools[b][:]
        return fresh

    _random.shuffle(brands)
    picks = []
    if len(brands) == 1:
        # single-brand set (e.g. tips): distinct topics, no in-batch repeats
        topics = _avail(brands[0])
        _random.shuffle(topics)
        picks = [(brands[0], t) for t in topics[:count]]
    else:
        # round-robin across brands, sampling WITHOUT replacement per brand
        bags = {}
        for b in brands:
            bag = _avail(b)
            _random.shuffle(bag)
            bags[b] = bag
        i = 0
        while len(picks) < count and any(bags.values()):
            b = brands[i % len(brands)]
            if bags[b]:
                picks.append((b, bags[b].pop()))
            i += 1
    # Remember everything picked so the next run avoids it.
    for _b, _t in picks:
        used_set.add(_t)
    man["used_topics"] = sorted(used_set)

    ts = int(_time.time())
    for idx, (brand, topic) in enumerate(picks):
        prompt, platform_keys = _build_post_prompt(brand, topic, {"facebook": True, "instagram": True, "linkedin": True})
        body = ""
        card = {"headline": "", "path": "", "action": ""}
        try:
            r = _req.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                         "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-sonnet-4-6", "max_tokens": 600,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=40)
            rj = r.json()
            raw = rj["content"][0]["text"]
            # Decode the first JSON object only. The model sometimes wraps it in
            # code fences or appends prose after it, which broke a bare json.loads
            # with "Extra data". Skip to the first brace, raw_decode, ignore the rest.
            start = raw.find("{")
            if start < 0:
                raise ValueError("no JSON object in model output")
            posts, _ = _json.JSONDecoder().raw_decode(raw[start:])
            body = posts.get("facebook") or posts.get("linkedin") or posts.get("instagram") or ""
            card = {"headline": posts.get("headline") or "", "path": posts.get("path") or "", "action": posts.get("action") or ""}
        except Exception as e:
            print(f"generate-set: copy gen failed brand={brand} err={e!r}", flush=True)
            body = ""
        if not body:
            body = f"{topic[0].upper()+topic[1:]}.\n\nHarbor Privacy can help.\n\nhttps://harborprivacy.com"
        # Guarantee a hashtag line on every generated post when the model omits it.
        if "#" not in body:
            if brand == "tips":
                tl = topic.lower()
                dev = next((tag for needles, tag in [
                    (("windows",), "#Windows"), (("android",), "#Android"),
                    (("iphone", "ios"), "#iPhone"),
                    (("smart tv", "content recognition"), "#SmartTV"),
                    (("echo", "alexa"), "#Alexa"),
                    (("roku", "fire tv"), "#StreamingTV"),
                    (("google",), "#Google"),
                ] if any(n in tl for n in needles)), "#Privacy")
                tags = f"#PrivacyTips {dev} #StopTracking #DataPrivacy"
            else:
                tags = {
                    "fax":      "#SecureFax #HIPAA #Privacy #DataPrivacy",
                    "booking":  "#SmallBusiness #Scheduling #Privacy #BookingApp",
                    "money":    "#Budgeting #PersonalFinance #Privacy #MoneyTips",
                    "scan":     "#DataPrivacy #DataBrokers #OptOut #PrivacyMatters",
                    "neighbor": "#HomeNetwork #WiFi #Privacy #SmartHome",
                    "career":   "#JobSearch #Resume #Privacy #CareerTips",
                    "stickers": "#Privacy #Homelab #Stickers #DataPrivacy",
                }.get(brand, "#Privacy #DataPrivacy #DigitalPrivacy #HarborPrivacy")
            body = body.rstrip() + f"\n\n{tags}"

        pid = f"gen-{brand}-{ts}-{idx}"
        cat = SOCIAL_BRAND_CAT.get(brand, "Harbor")
        head = topic[0].upper() + topic[1:]
        # Render the card and copy it into the asset library so /social/img
        # serves it locally (the dashboard social-images URL is not public).
        import shutil as _sh, pathlib as _pl
        def _stash(gurl, suffix):
            # copy a freshly rendered card from social-images into the asset
            # library as <pid><suffix>.png and return its public URL
            if not gurl:
                return ""
            stem = gurl.rsplit("/", 1)[-1]
            src = _pl.Path("/var/www/network/social-images") / stem
            dst = _pl.Path("/home/ubuntu/harbor-design-system/assets/social") / (pid + suffix + ".png")
            try:
                if src.exists():
                    _sh.copyfile(src, dst)
                    return f"https://assets.harborprivacy.com/raw/social/{pid}{suffix}.png"
            except Exception as e:
                print(f"generate-set: image copy failed {pid}{suffix}: {e!r}", flush=True)
            return ""
        # All brands now render through the shared card engine (4:5 portrait).
        img = _stash(_generate_engine_card(brand, topic), "")
        img_square = ""
        entry = {
            "id": pid, "category": cat,
            "hdr": f"{cat} / {head} -> https://harborprivacy.com",
            "img": img or "",
            "link": "https://harborprivacy.com",
            "tags": "lightbulb,shield",
            "body": body,
            "status": "pending",  # AI drafts land in the review queue, not the live pool
        }
        entry["topic"] = topic  # dedup key for future generate-set runs
        if img_square:
            entry["img_square"] = img_square
        if brand == "tips":
            entry["tip"] = card  # keep structured fields for re-rendering
        man["entries"].append(entry)
        ids.append(pid); added += 1

    # Atomic write: temp file in the same dir, then os.replace. This only needs
    # write permission on the directory (owned by ubuntu), so the save survives
    # the manifest being left root-owned by the daily social-refresh cron.
    import os as _os, tempfile as _tf
    tmp = None
    try:
        fd, tmp = _tf.mkstemp(dir=_os.path.dirname(SOCIAL_MANIFEST), prefix=".manifest-", suffix=".tmp")
        with _os.fdopen(fd, "w") as _f:
            _json.dump(man, _f, indent=2, ensure_ascii=False)
        _os.replace(tmp, SOCIAL_MANIFEST)
    except Exception as e:
        if tmp:
            try:
                _os.unlink(tmp)
            except Exception:
                pass
        return jsonify({"ok": False, "error": f"save failed: {e}"}), 500
    return jsonify({"ok": True, "added": added, "ids": ids})


@app.route("/api/social/generate-reel", methods=["POST"])
@admin_required
def social_generate_reel():
    """On-demand reel build. mode=='pets' runs the deep-teal pet pack; anything
    else runs the normal brand rotation. Synchronous: reel-refresh.py renders the
    scenes + ffmpeg mp4 + poster and appends the manifest itself (~20-40s). Runs as
    the service user (ubuntu) so the manifest stays ubuntu-owned, no chown needed."""
    import subprocess as _sp
    body = request.get_json(silent=True) or {}
    mode = (body.get("mode") or "").strip().lower()
    extra = []
    if mode == "pets":
        extra.append("pets")
        niche = (body.get("niche") or "").strip().lower()
        if niche in ("walkers", "groomers", "sitters", "mobile"):
            extra.append(niche)
    cmd = ["/usr/bin/python3", "/home/ubuntu/harbor-backend/reel-refresh.py", *extra]
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=240,
                    cwd="/home/ubuntu/harbor-backend", env=os.environ.copy())
    except _sp.TimeoutExpired:
        return jsonify({"ok": False, "error": "reel build timed out"}), 504
    added = next((l for l in (r.stdout or "").splitlines() if l.startswith("added ")), "")
    if r.returncode != 0 or not added:
        # surface the script's own last line (e.g. quality-gate reason)
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        return jsonify({"ok": False, "error": tail[-1] if tail else "reel generation failed"}), 500
    parts = added.split()
    return jsonify({"ok": True, "id": parts[1] if len(parts) > 1 else "", "pet": mode == "pets"})


@app.route("/api/social/generate-sticker-reel", methods=["POST"])
@admin_required
def social_generate_sticker_reel():
    """On-demand randomized Etsy sticker product reel. make-sticker-reel.py in
    'random' mode assembles a fresh reel (design subset+order, hook/CTA copy,
    accent, montage style, timing all varied), renders the mp4 + poster, appends
    the manifest, and prunes the sticker-reel pool. Synchronous (~10-25s). Needs no
    API key; runs as the service user so the manifest stays ubuntu-owned."""
    import subprocess as _sp
    body = request.get_json(silent=True) or {}
    arg = "tiktok" if (body.get("mode") or "").strip().lower() == "tiktok" else "random"
    cmd = ["/usr/bin/python3", "/home/ubuntu/make-sticker-reel.py", arg]
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=240,
                    cwd="/home/ubuntu", env=os.environ.copy())
    except _sp.TimeoutExpired:
        return jsonify({"ok": False, "error": "reel build timed out"}), 504
    added = next((l for l in (r.stdout or "").splitlines() if l.startswith("added ")), "")
    if r.returncode != 0 or not added:
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        return jsonify({"ok": False, "error": tail[-1] if tail else "reel generation failed"}), 500
    parts = added.split()
    return jsonify({"ok": True, "id": parts[1] if len(parts) > 1 else ""})


@app.route("/api/social/generate-cards-set", methods=["POST"])
@admin_required
def social_generate_cards_set():
    """Regenerate the curated card-engine slogan set (10 cards, varied layouts) and
    push them LIVE into /social. push-cards-to-social.py renders each through the
    card engine and replaces stable card-<slug> manifest entries (idempotent).
    Synchronous (~10-15s); no API key; runs as the service user (ubuntu-owned manifest)."""
    import subprocess as _sp
    cmd = ["/usr/bin/python3", "/home/ubuntu/push-cards-to-social.py"]
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=120,
                    cwd="/home/ubuntu", env=os.environ.copy())
    except _sp.TimeoutExpired:
        return jsonify({"ok": False, "error": "cards build timed out"}), 504
    pushed = next((l for l in (r.stdout or "").splitlines() if l.startswith("pushed ")), "")
    if r.returncode != 0 or not pushed:
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        return jsonify({"ok": False, "error": tail[-1] if tail else "cards generation failed"}), 500
    parts = pushed.split()
    return jsonify({"ok": True, "n": parts[1] if len(parts) > 1 else ""})


@app.route("/api/social/generate-cards-reel", methods=["POST"])
@admin_required
def social_generate_cards_reel():
    """On-demand reel that animates the card_engine promo layouts (dark quote,
    receipt, stat, outline, compare...) into a 9:16 mp4 with Ken Burns motion.
    make-cards-reel.py renders the cards, frames them, builds the mp4 + poster,
    appends the manifest and prunes. Synchronous (~15-25s); no API key."""
    import subprocess as _sp
    cmd = ["/usr/bin/python3", "/home/ubuntu/make-cards-reel.py"]
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=240,
                    cwd="/home/ubuntu", env=os.environ.copy())
    except _sp.TimeoutExpired:
        return jsonify({"ok": False, "error": "reel build timed out"}), 504
    added = next((l for l in (r.stdout or "").splitlines() if l.startswith("added ")), "")
    if r.returncode != 0 or not added:
        tail = ((r.stdout or "") + (r.stderr or "")).strip().splitlines()
        return jsonify({"ok": False, "error": tail[-1] if tail else "reel generation failed"}), 500
    parts = added.split()
    return jsonify({"ok": True, "id": parts[1] if len(parts) > 1 else ""})


# ════════════════════════════════════════════════════════════
# LinkedIn personal-post generator
# Drafts a post (hook -> take -> tie-back -> question) for a chosen persona.
# Link goes in first_comment, not the body (LinkedIn demotes in-body links).
# Personas can be overridden by /home/ubuntu/harbor-backend/linkedin-personas.json
# ════════════════════════════════════════════════════════════
def _linkedin_personas():
    base = {
        "harbor_founder": {
            "label": "Harbor founder / builder",
            "voice": ("First person, a founder building in public. Plain, direct, specific. "
                      "Real numbers, real tradeoffs, what broke and what you learned. No hype, no buzzwords."),
            "positioning": ("Tim Brazer, founder of Harbor Privacy, a privacy-first suite of small tools "
                            "(booking, anonymous fax, data-broker removal/Scan, money, neighbor network management, "
                            "encrypted DNS). Ships fast and mostly solo on a home lab plus cloud VMs."),
            "tie_back": ("Connect the topic to privacy and, only when it fits naturally, to a relevant Harbor "
                         "product. Never force a pitch. The story is the point, the product is the proof."),
            "hashtags": ["privacy", "buildinpublic", "datasecurity"],
            "seeds": [
                "a small thing that broke in production this week and the unglamorous lesson in it",
                "why you reach for boring, proven tech instead of the trendy thing",
                "the real cost of building a feature nobody actually asked for",
                "what shipping mostly solo teaches you that a big team hides",
                "a privacy default most companies get wrong, and the simple fix",
                "why you put the customer's data out of your own reach on purpose",
                "the difference between a tool people try once and a tool people keep",
                "a moment you almost over-engineered something and stopped yourself",
                "what running your own home lab teaches you about real reliability",
                "why 'no account required' is a feature, not a missing one",
            ],
        },
        "healthcare_ops_leader": {
            "label": "Healthcare ops leader (job hunt)",
            "voice": ("First person, a credible operations leader. Calm, results-oriented, people-first. "
                      "Shows judgment and outcomes, not jargon. Confident, never desperate."),
            "positioning": ("Tim Brazer, a healthcare operations leader pursuing an MBA and open to a leadership "
                            "role in healthcare operations. Strengths: process improvement, team building, "
                            "patient and customer experience, cross-functional execution, and data privacy / HIPAA "
                            "awareness (builds privacy and HIPAA-friendly tools on the side)."),
            "tie_back": ("Tie the topic to operations leadership lessons: efficiency, patient experience, staffing, "
                         "process, compliance, change management. Position Tim as a thoughtful leader and give a "
                         "subtle, dignified signal that he is open to the right role. Never sound like a plea."),
            "hashtags": ["healthcare", "operations", "leadership"],
            "seeds": [
                "a staffing lesson from a hard shift and how you would handle it now",
                "why steady process beats daily heroics in operations",
                "what patient experience actually comes down to, beyond the survey score",
                "a change-management mistake you learned from and the fix",
                "how you would cut appointment no-shows without adding headcount",
                "the operations metric leaders watch that frontline staff feel first",
                "why cross-functional trust moves faster than any new software",
                "a small workflow change that saved real time, and how you found it",
                "what privacy and HIPAA awareness looks like in day-to-day operations",
                "how you onboard a new team member so they are useful in week one",
            ],
        },
    }
    try:
        import json as _j
        p = "/home/ubuntu/harbor-backend/linkedin-personas.json"
        if os.path.exists(p):
            with open(p) as _f:
                base.update(_j.load(_f) or {})
    except Exception as e:
        print(f"linkedin personas override failed: {e!r}", flush=True)
    return base


def _pick_linkedin_seed(pkey, per):
    """Pick a fresh theme seed for auto-generation, rotating to avoid recent repeats."""
    import json as _j, random as _r
    seeds = per.get("seeds") or ["a specific lesson from your week and why it matters"]
    statef = "/home/ubuntu/harbor-backend/linkedin-seed-state.json"
    used = {}
    try:
        if os.path.exists(statef):
            used = _j.load(open(statef)) or {}
    except Exception:
        used = {}
    recent = used.get(pkey, [])
    pool = [s for s in seeds if s not in recent] or seeds
    choice = _r.choice(pool)
    used[pkey] = (recent + [choice])[-max(1, len(seeds) // 2):]
    try:
        with open(statef, "w") as _f:
            _j.dump(used, _f)
    except Exception:
        pass
    return choice


LINKEDIN_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>LinkedIn post generator</title>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;--surface:#ffffff;--surface-2:#f6f1e7;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:680px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:24px;line-height:1.2;margin:6px 0 6px;color:var(--ink);}
.sub{color:var(--mute);font-size:14px;margin:0 0 18px;}
.card{background:var(--surface);border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px;}
label{display:block;font-size:13px;font-weight:600;margin:0 0 6px;color:var(--ink);}
.hint{font-size:12px;color:var(--mute);font-weight:400;}
textarea,input,select{width:100%;border:1px solid var(--line);border-radius:12px;padding:12px;font:15px/1.5 -apple-system,system-ui,sans-serif;color:var(--ink);background:var(--surface-2);resize:vertical;}
textarea,input,select{outline:none;}
textarea:focus,input:focus,select:focus{border-color:var(--teal);}
::placeholder{color:var(--mute);opacity:.8;}
textarea{min-height:90px;}
textarea#post{min-height:240px;}
select{appearance:none;background:var(--surface-2);}
select option{background:var(--surface);color:var(--ink);}
.field{margin-bottom:14px;}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;border:none;border-radius:12px;padding:14px;font-size:16px;font-weight:700;cursor:pointer;margin-top:6px;background:var(--teal);color:#fff;text-decoration:none;}
.btn.alt{background:transparent;color:var(--teal);border:1.5px solid var(--teal);font-weight:600;}
.btn:active{opacity:.8;}.btn:disabled{opacity:.5;}
.btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;}
.row{display:flex;gap:10px;}.row .btn{margin-top:0;}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:#2d2d2d;color:#fff;padding:12px 20px;border-radius:999px;font-size:14px;font-weight:600;opacity:0;transition:.25s;pointer-events:none;z-index:9;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.back{display:inline-flex;align-items:center;gap:6px;color:var(--teal);text-decoration:none;font-size:14px;font-weight:600;margin-bottom:16px;}
.back svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;}
</style></head><body>
""" + NAV_LIGHT + """
<div class="eyebrow">Personal posts</div>
<h1>LinkedIn post generator</h1>
<p class="sub">Pick who you are posting as and hit Write. Leave the topic blank and it picks a fresh angle for you, or paste a headline to react to. The link goes in the first comment so LinkedIn does not bury the post.</p>

<div class="card">
  <div class="field">
    <label for="persona">Post as</label>
    <select id="persona" onchange="syncLink()">
      {% for p in personas %}<option value="{{ p.key }}" data-link="{{ p.link }}">{{ p.label }}</option>{% endfor %}
    </select>
  </div>
  <div class="field">
    <label for="topic">Topic or headline <span class="hint">(optional, leave blank and it writes one for you)</span></label>
    <textarea id="topic" placeholder="e.g. Another health system breach exposed 2M patient records this week..."></textarea>
  </div>
  <div class="field">
    <label for="angle">Your own angle / experience to include <span class="hint">(optional, but makes it yours)</span></label>
    <textarea id="angle" placeholder="e.g. When I ran intake we cut no-shows 30% by... / I built Harbor Fax because..."></textarea>
  </div>
  <div class="field">
    <label for="link">Link for the first comment <span class="hint">(optional)</span></label>
    <input id="link" type="text" placeholder="https://...">
  </div>
  <button class="btn" id="genbtn" onclick="gen(this)">
    <svg viewBox="0 0 24 24"><path d="M12 3v18M3 12h18"/></svg>
    Write a post
  </button>
  <button class="btn alt" onclick="surprise()" style="margin-top:8px;">
    <svg viewBox="0 0 24 24"><polyline points="16 3 21 3 21 8"/><line x1="4" y1="20" x2="21" y2="3"/><polyline points="21 16 21 21 16 21"/><line x1="15" y1="15" x2="21" y2="21"/><line x1="4" y1="4" x2="9" y2="9"/></svg>
    Surprise me
  </button>
</div>

<div class="card" id="result" style="display:none;">
  <div class="eyebrow" style="margin-bottom:8px;">Draft</div>
  <textarea id="post" readonly></textarea>
  <div class="row" style="margin-top:10px;">
    <button class="btn" onclick="cp('post','Post copied')">
      <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy post
    </button>
    <button class="btn alt" onclick="gen(document.getElementById('genbtn'))">
      <svg viewBox="0 0 24 24"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>
      Regenerate
    </button>
  </div>
  <div class="eyebrow" style="margin:16px 0 8px;">First comment (drop your link here)</div>
  <textarea id="fc" readonly style="min-height:90px;"></textarea>
  <button class="btn alt" onclick="cp('fc','First comment copied')" style="margin-top:10px;">
    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    Copy first comment
  </button>
  <a class="btn" href="https://www.linkedin.com/feed/?shareActive=true" target="_blank" rel="noopener" style="margin-top:10px;">
    <svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg>
    Open LinkedIn composer
  </a>
</div>

<div class="toast" id="toast"></div>
<script>
var CSRF="{{ csrf_token }}";
async function gen(btn){
  var t=document.getElementById('topic').value.trim();
  var lbl=btn.innerHTML; btn.disabled=true; btn.textContent='Writing...';
  try{
    var r=await fetch('/api/linkedin/generate',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},
      body:JSON.stringify({persona:document.getElementById('persona').value,topic:t,
        angle:document.getElementById('angle').value,link:document.getElementById('link').value})});
    var j=await r.json();
    if(!j.ok){toast(j.error||'Failed');return;}
    document.getElementById('post').value=j.full;
    document.getElementById('fc').value=j.first_comment||'';
    document.getElementById('result').style.display='block';
    document.getElementById('result').scrollIntoView({behavior:'smooth'});
    toast('Draft ready');
  }catch(e){toast('Network error');}
  finally{btn.disabled=false; btn.innerHTML=lbl;}
}
function surprise(){
  var sel=document.getElementById('persona');
  if(sel&&sel.options.length){sel.selectedIndex=Math.floor(Math.random()*sel.options.length);}
  document.getElementById('topic').value='';
  document.getElementById('angle').value='';
  gen(document.getElementById('genbtn'));
}
function cp(id,msg){var el=document.getElementById(id);el.select();el.setSelectionRange(0,99999);
  navigator.clipboard.writeText(el.value).then(function(){toast(msg);},function(){document.execCommand('copy');toast(msg);});}
function toast(m){var x=document.getElementById('toast');x.textContent=m;x.classList.add('show');setTimeout(function(){x.classList.remove('show');},1600);}
var lastDefault="";
function syncLink(){
  var sel=document.getElementById('persona');
  var nd=sel.options[sel.selectedIndex].getAttribute('data-link')||"";
  var lf=document.getElementById('link');
  // only auto-fill if the field is empty or still holds a previous persona default
  if(lf.value.trim()===""||lf.value.trim()===lastDefault){lf.value=nd;}
  lastDefault=nd;
}
syncLink();
</script>
</body></html>"""


@app.route("/linkedin")
@admin_required
def linkedin_page():
    P = _linkedin_personas()
    personas = [{"key": k, "label": v.get("label", k), "link": v.get("default_link", "")} for k, v in P.items()]
    resp = make_response(render_template_string(LINKEDIN_HTML, personas=personas, nav_active="linkedin"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/linkedin/generate", methods=["POST"])
@admin_required
def linkedin_generate():
    import requests as _rq, json as _j
    d = request.get_json(silent=True) or {}
    topic = (d.get("topic") or "").strip()
    angle = (d.get("angle") or "").strip()
    link  = (d.get("link") or "").strip()
    P = _linkedin_personas()
    pkey = d.get("persona") or next(iter(P.keys()))
    per = P.get(pkey) or next(iter(P.values()))
    if topic:
        topic_block = f"TOPIC or headline to react to:\n{topic}\n"
    else:
        seed = _pick_linkedin_seed(pkey, per)
        topic_block = (
            "No topic was given, so this is your own post. Develop THIS theme, inventing "
            "concrete, realistic specifics from your own experience. Do NOT fabricate exact "
            "statistics, employer names, dates, or specific events; keep any specifics "
            "plausible and general rather than invented facts:\n" + seed + "\n")
    angle_txt = (f"\nYour own angle or experience to weave in (use it, do not ignore it):\n{angle}\n"
                 if angle else "")
    link_txt = (f"The first_comment MUST naturally include this link: {link}"
                if link else "If no specific link fits, make first_comment a short call to action with NO url.")
    prompt = (
        f"You write a LinkedIn post for {per['positioning']}\n"
        f"Voice: {per['voice']}\n\n"
        f"{topic_block}{angle_txt}\n"
        "Write ONE LinkedIn post with this exact structure:\n"
        "- A single scroll-stopping hook as the first line, on its own (max about 12 words). "
        "It is all readers see before 'see more'.\n"
        "- Then 3 to 6 short lines or tiny paragraphs: set up the topic, give YOUR specific take "
        "(what most people miss), then connect it to your own work or experience. "
        f"{per['tie_back']}\n"
        "- End with one short question that invites comments.\n\n"
        "Rules: first person. Plain language. No em dashes anywhere. No emoji. Short lines with blank "
        "lines between thoughts. Do NOT put any url in the post body (LinkedIn demotes in-body links). "
        "Keep the whole post under 1300 characters. " + link_txt + "\n\n"
        "Return ONLY a JSON object:\n"
        '  "hook": the first line\n'
        '  "body": everything after the hook (no hashtags, no url)\n'
        '  "hashtags": array of exactly 3 lowercase tags, no # sign\n'
        '  "first_comment": a short first comment (this is where any link goes)'
    )
    try:
        r = _rq.post("https://api.anthropic.com/v1/messages",
            headers={"x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                     "anthropic-version": "2023-06-01", "content-type": "application/json"},
            json={"model": "claude-sonnet-4-6", "max_tokens": 900,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=45)
        raw = r.json()["content"][0]["text"]
        obj, _ = _j.JSONDecoder().raw_decode(raw[raw.find("{"):])
    except Exception as e:
        print(f"linkedin generate failed: {e!r}", flush=True)
        return jsonify({"ok": False, "error": "Generation failed, try again."}), 502
    hook = (obj.get("hook") or "").strip()
    body = (obj.get("body") or "").strip()
    tags = obj.get("hashtags") or per.get("hashtags", [])
    tags = ["#" + str(t).lstrip("#") for t in tags][:3]
    fc = (obj.get("first_comment") or "").strip()
    full = hook + "\n\n" + body + (("\n\n" + " ".join(tags)) if tags else "")
    return jsonify({"ok": True, "hook": hook, "body": body, "hashtags": tags,
                    "first_comment": fc, "full": full})


SOCIAL_POST_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>{{ e.hdr }}</title>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:680px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:24px;line-height:1.2;margin:6px 0 18px;}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px;}
textarea{width:100%;border:1px solid var(--line);border-radius:12px;padding:14px;font:15px/1.5 -apple-system,system-ui,sans-serif;color:var(--ink);background:#fcfaf6;resize:vertical;min-height:200px;}
img.preview{width:100%;border-radius:12px;border:1px solid var(--line);display:block;}
  video.preview{display:block;width:auto;max-width:100%;max-height:78vh;margin:0 auto;border-radius:12px;border:1px solid var(--line);background:#000;}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;border:none;border-radius:12px;padding:14px;font-size:16px;font-weight:600;cursor:pointer;margin-top:10px;background:var(--teal);color:#fff;text-decoration:none;}
.btn.alt{background:#fff;color:var(--teal);border:1.5px solid var(--teal);}
.btn:active{opacity:.8;}
.btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;}
.row{display:flex;gap:10px;}.row .btn{margin-top:10px;}
.share{display:flex;gap:10px;flex-wrap:wrap;margin-top:10px;}
.share .btn{flex:1 1 calc(50% - 5px);min-width:140px;margin-top:0;font-size:14px;padding:12px;}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:#2d2d2d;color:#fff;padding:12px 20px;border-radius:999px;font-size:14px;opacity:0;transition:.25s;pointer-events:none;z-index:9;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
.back{display:inline-flex;align-items:center;gap:6px;color:var(--teal);text-decoration:none;font-size:14px;font-weight:600;margin-bottom:16px;}
.back svg{width:16px;height:16px;stroke:currentColor;fill:none;stroke-width:2;}
</style></head><body>
<a href="/social" class="back"><svg viewBox="0 0 24 24"><path d="M15 18l-6-6 6-6"/></svg>Sent posts</a>
<div class="eyebrow">{{ e.category }} post</div>
<h1>{{ e.hdr }}</h1>

<div class="card">
  <div class="eyebrow" style="margin-bottom:8px;">Caption</div>
  <textarea id="body" readonly>{{ e.body }}</textarea>
  <div class="share">
    <button class="btn" onclick="copyText()">
      <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
      Copy caption
    </button>
    <button class="btn alt" onclick="copyIG()">
      <svg viewBox="0 0 24 24"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>
      Copy for Instagram
    </button>
    <a class="btn alt" href="https://www.facebook.com/sharer/sharer.php?u={{ e.link|urlencode }}" target="_blank" rel="noopener" onclick="copyForShare()">
      <svg viewBox="0 0 24 24"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>
      Facebook
    </a>
    <a class="btn alt" href="https://www.instagram.com/" target="_blank" rel="noopener" onclick="copyIG()">
      <svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
      Instagram
    </a>
    <a class="btn alt" href="https://www.linkedin.com/feed/?shareActive=true&text={{ e.body|urlencode }}" target="_blank" rel="noopener" onclick="copyForShare()">
      <svg viewBox="0 0 24 24"><path d="M16 8a6 6 0 0 1 6 6v7h-4v-7a2 2 0 0 0-4 0v7h-4v-7a6 6 0 0 1 6-6z"/><rect x="2" y="9" width="4" height="12"/><circle cx="4" cy="4" r="2"/></svg>
      LinkedIn
    </a>
    <a class="btn alt" href="https://twitter.com/intent/tweet?text={{ x_caption|urlencode }}" target="_blank" rel="noopener">
      <svg viewBox="0 0 24 24"><path d="M18.244 2.25h3.308l-7.227 8.26 8.502 11.24H16.17l-5.214-6.817L4.99 21.75H1.68l7.73-8.835L1.254 2.25H8.08l4.713 6.231zm-1.161 17.52h1.833L7.084 4.126H5.117z"/></svg>
      X
    </a>
    <a class="btn alt" href="https://business.facebook.com/latest/composer" target="_blank" rel="noopener" onclick="copyForShare()">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
      Business Suite
    </a>
  </div>
</div>

<div class="card">
  <div class="eyebrow" style="margin-bottom:8px;">Image</div>
  <img class="preview" id="img" src="/social/img/{{ e.id }}" alt="" data-name="{{ e.id }}.png">
  <div class="row">
    <button class="btn alt" onclick="copyImg()">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
      Copy image
    </button>
    <button class="btn" onclick="dlImg()">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
      Save image
    </button>
  </div>
</div>

{% if e.source == 'reel' %}
<div class="card">
  <div class="eyebrow" style="margin-bottom:8px;">Reel video</div>
  <video class="preview" id="vid" src="/social/public/{{ e.id }}.mp4" poster="/social/img/{{ e.id }}" controls playsinline preload="metadata" style="background:#000;"></video>
  <div class="row">
    <button class="btn" onclick="dlVid()">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
      Save reel
    </button>
  </div>
  <div class="eyebrow" style="margin-top:8px;">Silent by design. Add Facebook or Instagram music when you upload.</div>
</div>
{% endif %}

{% if e.img_square %}
<div class="card">
  <div class="eyebrow" style="margin-bottom:8px;">Square image (feed)</div>
  <img class="preview" id="imgsq" src="/social/img/{{ e.id }}?sq=1" alt="" data-name="{{ e.id }}-sq.png">
  <div class="row">
    <button class="btn alt" onclick="copyImgEl('imgsq')">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
      Copy image
    </button>
    <button class="btn" onclick="dlImgEl('imgsq')">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
      Save image
    </button>
  </div>
</div>
{% endif %}

{% if fb_ready %}
<button class="btn" id="fbPostBtn" onclick="postFB()" style="margin-top:10px;">
  <svg viewBox="0 0 24 24"><path d="M18 2h-3a5 5 0 0 0-5 5v3H7v4h3v8h4v-8h3l1-4h-4V7a1 1 0 0 1 1-1h3z"/></svg>
  <span id="fbTxt">Post to Facebook Page now</span>
</button>
{% endif %}
{% if ig_ready %}
<button class="btn" id="igPostBtn" onclick="postIG()" style="margin-top:10px;">
  <svg viewBox="0 0 24 24"><rect x="2" y="2" width="20" height="20" rx="5" ry="5"/><path d="M16 11.37A4 4 0 1 1 12.63 8 4 4 0 0 1 16 11.37z"/><line x1="17.5" y1="6.5" x2="17.51" y2="6.5"/></svg>
  <span id="igTxt">Post to Instagram now</span>
</button>
{% endif %}
{% if pin_ready %}
<button class="btn" id="pinPostBtn" onclick="postPin()" style="margin-top:10px;">
  <svg viewBox="0 0 24 24"><path d="M12 2a10 10 0 0 0-3.6 19.33c-.09-.78-.17-1.98.03-2.83.18-.78 1.18-4.97 1.18-4.97s-.3-.6-.3-1.49c0-1.4.81-2.44 1.82-2.44.86 0 1.27.64 1.27 1.42 0 .86-.55 2.15-.83 3.35-.24 1 .5 1.82 1.49 1.82 1.79 0 3.16-1.89 3.16-4.61 0-2.41-1.73-4.1-4.21-4.1-2.87 0-4.55 2.15-4.55 4.37 0 .87.33 1.8.75 2.31a.3.3 0 0 1 .07.29c-.08.32-.25 1-.28 1.14-.04.18-.15.22-.34.13-1.25-.58-2.03-2.4-2.03-3.87 0-3.15 2.29-6.04 6.6-6.04 3.47 0 6.16 2.47 6.16 5.77 0 3.45-2.17 6.22-5.19 6.22-1.01 0-1.97-.53-2.29-1.15l-.62 2.38c-.23.86-.83 1.94-1.24 2.6A10 10 0 1 0 12 2z"/></svg>
  <span id="pinTxt">Pin to Pinterest now</span>
</button>
{% endif %}

{% if fb_ready or ig_ready %}
<div style="border-top:1px solid var(--line);margin-top:14px;padding-top:14px;">
  <div class="eyebrow" style="margin-bottom:8px;">Schedule for later</div>
  <div id="schedNow" style="display:none;font-size:14px;">
    Scheduled for <b id="schedWhenTxt"></b> <span id="schedPlatsTxt" style="color:var(--mute);"></span>
    <button class="btn alt" onclick="cancelSchedule()" style="margin-top:10px;">
      <svg viewBox="0 0 24 24"><path d="M18 6L6 18M6 6l12 12"/></svg>
      Cancel schedule
    </button>
  </div>
  <div id="schedForm">
    <input type="datetime-local" id="schedWhen" style="width:100%;border:1px solid var(--line);border-radius:12px;padding:12px;font:15px -apple-system,system-ui,sans-serif;color:var(--ink);background:#fcfaf6;">
    <div style="display:flex;gap:18px;margin:12px 2px;font-size:14px;">
      {% if fb_ready %}<label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="schedFB" checked> Facebook</label>{% endif %}
      {% if ig_ready %}<label style="display:flex;align-items:center;gap:6px;"><input type="checkbox" id="schedIG" checked> Instagram</label>{% endif %}
    </div>
    <button class="btn" onclick="saveSchedule()" style="margin-top:0;">
      <svg viewBox="0 0 24 24"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg>
      Schedule post
    </button>
  </div>
</div>
{% endif %}

<a class="btn alt" href="{{ e.link }}" target="_blank" rel="noopener">
  <svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></svg>
  Open {{ e.link.split('//')[-1] }}
</a>

<button class="btn{{ '' if posted else ' alt' }}" id="markBtn" onclick="markPosted()" style="margin-top:10px;">
  <svg viewBox="0 0 24 24"><path d="M20 6L9 17l-5-5"/></svg>
  <span id="markTxt">{{ 'Posted' if posted else 'Mark as posted' }}</span>
</button>

<div class="toast" id="toast"></div>
<script>
var CSRF="{{ csrf_token }}", PID="{{ e.id }}", POSTED={{ 'true' if posted else 'false' }};
var SCHED={% if e.scheduled_for %}{{ e.scheduled_for|int }}{% else %}null{% endif %};
var SCHED_PLATS={% if e.scheduled_platforms %}{{ e.scheduled_platforms|tojson }}{% else %}[]{% endif %};
function fmtLocal(epoch){return new Date(epoch*1000).toLocaleString([],{weekday:'short',month:'short',day:'numeric',hour:'numeric',minute:'2-digit'});}
function renderSched(){
  var nowEl=document.getElementById('schedNow'),formEl=document.getElementById('schedForm');
  if(!nowEl||!formEl)return;
  if(SCHED){nowEl.style.display='block';formEl.style.display='none';
    document.getElementById('schedWhenTxt').textContent=fmtLocal(SCHED);
    document.getElementById('schedPlatsTxt').textContent=SCHED_PLATS.length?'('+SCHED_PLATS.map(function(p){return p=='fb'?'Facebook':'Instagram';}).join(' + ')+')':'';
  }else{nowEl.style.display='none';formEl.style.display='block';}
}
async function saveSchedule(){
  var v=document.getElementById('schedWhen').value;
  if(!v){toast('Pick a date and time');return;}
  var epoch=Math.floor(new Date(v).getTime()/1000), plats=[];
  var fb=document.getElementById('schedFB'); if(fb&&fb.checked)plats.push('fb');
  var ig=document.getElementById('schedIG'); if(ig&&ig.checked)plats.push('ig');
  if(!plats.length){toast('Choose Facebook and/or Instagram');return;}
  try{var r=await fetch('/api/social/schedule',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID,when:epoch,platforms:plats})});
    var j=await r.json();
    if(j.ok){SCHED=j.scheduled_for;SCHED_PLATS=plats;renderSched();toast('Scheduled for '+fmtLocal(epoch));}
    else toast(j.error||'Could not schedule');
  }catch(e){toast('Could not schedule');}
}
async function cancelSchedule(){
  try{var r=await fetch('/api/social/schedule',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID,when:null})});
    var j=await r.json();
    if(j.ok){SCHED=null;SCHED_PLATS=[];renderSched();toast('Schedule cancelled');}
    else toast(j.error||'Could not cancel');
  }catch(e){toast('Could not cancel');}
}
renderSched();
async function markPosted(){
  try{
    var r=await fetch('/api/social/posted',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID,posted:!POSTED})});
    var j=await r.json(); if(!j.ok) throw 0;
    POSTED=j.posted; var b=document.getElementById('markBtn');
    document.getElementById('markTxt').textContent=POSTED?'Posted':'Mark as posted';
    b.classList.toggle('alt',!POSTED);
    toast(POSTED?'Marked as posted':'Marked unposted');
  }catch(e){toast('Could not update');}
}
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show');},1600);}
function copyText(){var b=document.getElementById('body');b.select();navigator.clipboard.writeText(b.value).then(function(){toast('Caption copied');},function(){document.execCommand('copy');toast('Caption copied');});}
function copyForShare(){var v=document.getElementById('body').value;try{navigator.clipboard.writeText(v);}catch(e){var b=document.getElementById('body');b.select();document.execCommand('copy');}toast('Caption copied. Paste it into the post');}
function igCaption(t){return t.replace(/(?:https?:\/\/)?[A-Za-z0-9.\-]*harborprivacy\.(?:com|app)\S*/g,'Link in bio 🔗').trim();}
function copyIG(){var v=igCaption(document.getElementById('body').value);try{navigator.clipboard.writeText(v);}catch(e){}toast('Instagram caption copied. Link swapped for Link in bio');}
async function postFB(){var b=document.getElementById('fbPostBtn'),t=document.getElementById('fbTxt');b.disabled=true;t.textContent='Posting...';
  try{var r=await fetch('/api/social/post-fb',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID})});var j=await r.json();
    if(j.ok){t.textContent='Posted to Page';toast('Posted to Facebook Page');}
    else{t.textContent='Post to Facebook Page now';b.disabled=false;toast(j.error||'Post failed');}
  }catch(e){t.textContent='Post to Facebook Page now';b.disabled=false;toast('Post failed');}}
async function postIG(){var b=document.getElementById('igPostBtn'),t=document.getElementById('igTxt');b.disabled=true;t.textContent='Posting...';
  try{var r=await fetch('/api/social/post-ig',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID})});var j=await r.json();
    if(j.ok){t.textContent='Posted to Instagram';toast('Posted to Instagram');}
    else{t.textContent='Post to Instagram now';b.disabled=false;toast(j.error||'Post failed');}
  }catch(e){t.textContent='Post to Instagram now';b.disabled=false;toast('Post failed');}}
async function postPin(){var b=document.getElementById('pinPostBtn'),t=document.getElementById('pinTxt');b.disabled=true;t.textContent='Pinning...';
  try{var r=await fetch('/api/social/post-pinterest',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:PID})});var j=await r.json();
    if(j.ok){t.textContent='Pinned to Pinterest';toast('Pinned to Pinterest');}
    else{t.textContent='Pin to Pinterest now';b.disabled=false;toast(j.error||'Pin failed');}
  }catch(e){t.textContent='Pin to Pinterest now';b.disabled=false;toast('Pin failed');}}
var IMGBLOB=null, IMGFILE=null;
(function(){
  // Preload every preview image into a per-element blob/File so Save can use
  // navigator.share within the click gesture (clean "Save Image" on iOS).
  document.querySelectorAll('img.preview').forEach(function(el){
    fetch(el.src).then(function(r){return r.blob();}).then(function(b){
      el._blob=b; el._file=new File([b], el.dataset.name||'harbor-post.png', {type:b.type||'image/png'});
      if(el.id==='img'){IMGBLOB=b;IMGFILE=el._file;}
    }).catch(function(){});
  });
})();
async function copyImg(){try{var bl=IMGBLOB||await (await fetch(document.getElementById('img').src,{mode:'cors'})).blob();await navigator.clipboard.write([new ClipboardItem({[bl.type]:bl})]);toast('Image copied');}catch(e){toast('Long-press the image to copy');}}
async function dlImg(){var el=document.getElementById('img');var name=el.dataset.name||'harbor-post.png';
  try{
    if(IMGFILE && navigator.canShare && navigator.canShare({files:[IMGFILE]})){await navigator.share({files:[IMGFILE]});return;}
    var bl=IMGBLOB||await (await fetch(el.src)).blob();
    var u=URL.createObjectURL(bl);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);toast('Saved');
  }catch(e){if(e&&e.name==='AbortError')return;window.open(el.src,'_blank');}}
async function dlVid(){var el=document.getElementById('vid');if(!el)return;var name='{{ e.id }}.mp4';
  try{
    var bl=await (await fetch(el.src)).blob();
    var f=new File([bl],name,{type:bl.type||'video/mp4'});
    if(navigator.canShare && navigator.canShare({files:[f]})){await navigator.share({files:[f]});return;}
    var u=URL.createObjectURL(bl);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);toast('Saved');
  }catch(e){if(e&&e.name==='AbortError')return;window.open(el.src,'_blank');}}
async function copyImgEl(id){try{var el=document.getElementById(id);var bl=el._blob||await (await fetch(el.src,{mode:'cors'})).blob();await navigator.clipboard.write([new ClipboardItem({[bl.type]:bl})]);toast('Image copied');}catch(e){toast('Long-press the image to copy');}}
async function dlImgEl(id){var el=document.getElementById(id);var name=el.dataset.name||'harbor-post.png';
  try{
    if(el._file && navigator.canShare && navigator.canShare({files:[el._file]})){await navigator.share({files:[el._file]});return;}
    var bl=el._blob||await (await fetch(el.src)).blob();
    var u=URL.createObjectURL(bl);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);toast('Saved');
  }catch(e){if(e&&e.name==='AbortError')return;window.open(el.src,'_blank');}}
</script></body></html>"""


def _social_entry(post_id):
    import json as _json
    try:
        with open(SOCIAL_MANIFEST) as _f:
            entries = _json.load(_f).get("entries", [])
    except Exception:
        entries = []
    return next((e for e in entries if e.get("id") == post_id), None)


def _x_caption(entry):
    """X caps at 280 chars but our bodies are long FB/IG captions. Build a tight
    X version: headline + hashtags (if they fit) + link, always <=280."""
    import re
    head = (entry.get("head") or entry.get("title") or "").strip()
    link = (entry.get("link") or "").strip()
    tags = " ".join(re.findall(r"#\w+", entry.get("body", "")))
    cap = f"{head}\n{tags}\n{link}" if tags else f"{head}\n{link}"
    if len(cap) > 280:                      # drop hashtags first
        cap = f"{head}\n{link}"
    if len(cap) > 280:                      # then trim the headline
        keep = max(0, 280 - len(link) - 1)
        cap = f"{head[:keep].rstrip()}\n{link}"
    return cap


@app.route("/social/post/<post_id>")
@admin_required
def social_post_page(post_id):
    entry = _social_entry(post_id)
    if not entry:
        return "Post not found", 404
    posted = bool(_load_posted().get(post_id))
    fb_ready = bool(META_PAGE_ID and META_PAGE_TOKEN)
    ig_ready = bool(META_IG_ID and META_PAGE_TOKEN)
    pin_ready = bool(PINTEREST_BOARD_ID and (PINTEREST_ACCESS_TOKEN or
                     (PINTEREST_APP_ID and PINTEREST_APP_SECRET and PINTEREST_REFRESH_TOKEN)))
    x_ready = bool(X_API_KEY and X_API_SECRET and X_ACCESS_TOKEN and X_ACCESS_SECRET)
    x_caption = _x_caption(entry)
    resp = make_response(render_template_string(SOCIAL_POST_HTML, e=entry, posted=posted,
                                                fb_ready=fb_ready, ig_ready=ig_ready, pin_ready=pin_ready,
                                                x_ready=x_ready, x_caption=x_caption))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/social/img/<post_id>")
@admin_required
def social_post_img(post_id):
    # Same-origin image proxy so the staging page can copy/download cleanly.
    from flask import Response, send_file
    import pathlib, requests as _req
    entry = _social_entry(post_id)
    if not entry:
        return "not found", 404
    sq = bool(request.args.get("sq"))
    suffix = "-sq" if sq else ""
    remote = (entry.get("img_square") if sq else entry.get("img")) or ""
    local = pathlib.Path("/home/ubuntu/harbor-design-system/assets/social") / (post_id + suffix + ".png")
    if local.exists():
        return send_file(str(local), mimetype="image/png")
    if not remote:
        return "not found", 404
    try:
        r = _req.get(remote, timeout=20)
        ctype = r.headers.get("Content-Type", "image/png")
        # Persist into the asset library so the image is reusable and future
        # requests serve the local copy instead of re-proxying the remote URL.
        if r.status_code == 200 and ctype.startswith("image/"):
            try:
                local.parent.mkdir(parents=True, exist_ok=True)
                local.write_bytes(r.content)
            except Exception as e:
                print(f"social_post_img: cache write failed for {post_id}{suffix}: {e!r}", flush=True)
        return Response(r.content, mimetype=ctype)
    except Exception:
        return redirect(remote)


# ===== Live apex marketing-page inventory (reel planning surface) =====
NETWORK_DIR = "/var/www/network"
# Utility/funnel/legal pages that are not reel material.
PAGES_EXCLUDE = {
    "404", "adblock-test", "already-member", "checkout", "confirm-your-email",
    "docs", "fax-status", "fax-success", "index", "privacy", "scan-results",
    "setup-guide", "slow-down", "terms", "welcome", "welcome-paid",
}
PAGES_ORDER = ["Booking niches", "Booking comparisons", "Scan & data removal",
               "Products & landers", "South Shore towns"]


def _page_bucket(slug):
    if slug.startswith("booking-for-"):
        return "Booking niches"
    if slug.startswith("booking-vs-") or slug == "booking-compare":
        return "Booking comparisons"
    if slug.startswith("scan"):
        return "Scan & data removal"
    if slug.endswith("MA"):
        return "South Shore towns"
    return "Products & landers"


def _page_title(path):
    import re as _re, html as _html
    try:
        head = open(path, encoding="utf-8", errors="ignore").read(2000)
    except Exception:
        return ""
    m = _re.search(r"<title>(.*?)</title>", head, _re.S | _re.I)
    if not m:
        return ""
    t = _html.unescape(m.group(1)).strip()
    # Trim the site-name suffix for a cleaner label.
    for sep in (" — ", " | ", ": "):
        if sep in t:
            t = t.split(sep, 1)[1] if t.lower().startswith("harbor") else t.split(sep, 1)[0]
            break
    return t.strip()


SOCIAL_PAGES_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>Apex pages</title>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;--surface:#fff;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:760px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:26px;margin:6px 0 4px;}
.sub{color:var(--mute);font-size:14px;margin:0 0 20px;}
h2{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:19px;margin:26px 0 10px;display:flex;align-items:baseline;gap:8px;}
h2 .n{font-family:ui-monospace,monospace;font-size:12px;color:var(--mute);letter-spacing:1px;}
a.row{display:flex;align-items:center;gap:12px;background:var(--surface);border:1px solid var(--line);border-radius:12px;padding:11px 14px;margin-bottom:8px;text-decoration:none;color:inherit;}
a.row:hover{border-color:var(--teal);}
.row .path{font-family:ui-monospace,Menlo,monospace;font-size:13px;color:var(--teal);font-weight:600;white-space:nowrap;}
.row .title{font-size:13px;color:var(--mute);min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}
.row .ext{margin-left:auto;flex:0 0 auto;width:15px;height:15px;stroke:var(--mute);fill:none;stroke-width:2;}
.foot{color:var(--mute);font-size:12px;margin-top:24px;font-family:ui-monospace,monospace;}
</style></head><body>
""" + NAV_LIGHT + """
<div class="eyebrow">Harbor social</div>
<h1>Live apex pages</h1>
<p class="sub">{{ total }} marketing pages live on harborprivacy.com. Tap one to open it, then make a reel from it.</p>
{% for cat, items in groups %}
<h2>{{ cat }} <span class="n">{{ items|length }}</span></h2>
{% for p in items %}
<a class="row" href="{{ p.url }}" target="_blank" rel="noopener">
  <span class="path">/{{ p.slug }}</span>
  <span class="title">{{ p.title }}</span>
  <svg class="ext" viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></svg>
</a>
{% endfor %}
{% endfor %}
<p class="foot">Served live from /var/www/network. New booking-for / scan / town pages appear here automatically.</p>
</body></html>"""


@app.route("/social/pages")
@admin_required
def social_pages():
    import glob as _glob, os as _os
    groups = {c: [] for c in PAGES_ORDER}
    total = 0
    for fp in _glob.glob(_os.path.join(NETWORK_DIR, "*.html")):
        slug = _os.path.basename(fp)[:-5]
        if slug in PAGES_EXCLUDE:
            continue
        groups[_page_bucket(slug)].append({
            "slug": slug,
            "url": f"https://harborprivacy.com/{slug}",
            "title": _page_title(fp),
        })
        total += 1
    ordered = [(c, sorted(groups[c], key=lambda p: p["slug"])) for c in PAGES_ORDER if groups[c]]
    resp = make_response(render_template_string(SOCIAL_PAGES_HTML, groups=ordered, total=total, nav_active="social"))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/api/csrf")
def api_csrf():
    tok = session.get("csrf")
    if not tok:
        tok = secrets.token_urlsafe(32)
        session["csrf"] = tok
    return jsonify({"csrf": tok})

# ===== Leads (AI lead generator + vetting) =====
LEADS_FILE = "/home/ubuntu/harbor-leads.json"

def _leads_load():
    import json as _j
    try:
        with open(LEADS_FILE) as f:
            return _j.load(f)
    except Exception:
        return {"version": 1, "vertical": "leads", "leads": []}

def _leads_save(data):
    import json as _j, os as _os, tempfile as _tf
    tmp = None
    try:
        fd, tmp = _tf.mkstemp(dir=_os.path.dirname(LEADS_FILE), prefix=".leads-", suffix=".tmp")
        with _os.fdopen(fd, "w") as f:
            _j.dump(data, f, indent=2, ensure_ascii=False)
        _os.replace(tmp, LEADS_FILE)
        return True
    except Exception as e:
        if tmp:
            try: _os.unlink(tmp)
            except Exception: pass
        print(f"leads save failed: {e!r}", flush=True)
        return False

def _lead_message(name, profession, town):
    n = name.split(",")[0].strip()
    where = f" in {town}" if town else ""
    return (f"Hi {n}, I'm Tim Brazer, local on the South Shore. I came across your {profession} "
            f"practice{where}. I built a scheduling tool made for private practice: the intake "
            "answers a client fills in at booking are never written to our database, they go "
            "straight to your inbox, so the booking layer stays completely outside your client "
            "confidentiality. It also handles online scheduling and reminders, and it's free to "
            "start. Could I set up a page for your practice so you can see it? No cost, no "
            "commitment.\n\nBest,\nTim - harborprivacy.com/booking-for-therapists")

LEADS_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>Leads - {{ vertical }}</title>
<link rel="apple-touch-icon" sizes="180x180" href="/leads-icon-180.png">
<link rel="manifest" href="/leads-app.webmanifest">
<meta name="mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-capable" content="yes">
<meta name="apple-mobile-web-app-status-bar-style" content="default">
<meta name="apple-mobile-web-app-title" content="Harbor Leads">
<meta name="theme-color" content="#1f5d6b">
<script>if('serviceWorker' in navigator){navigator.serviceWorker.getRegistrations().then(function(rs){rs.forEach(function(r){r.unregister();});}).catch(function(){});}</script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--terra:#c98a52;--line:#e5dfd3;--surface:#fff;--danger:#b3563f;--ok:#1f7a5b;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:18px;padding-top:max(18px,env(safe-area-inset-top));max-width:780px;margin:0 auto;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:26px;margin:4px 0 2px;}
.sub{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mute);letter-spacing:1px;text-transform:uppercase;margin-bottom:18px;}
.addbox{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:22px;}
.addbox h2{font-size:13px;margin:0 0 10px;font-family:ui-monospace,monospace;color:var(--teal);letter-spacing:1px;text-transform:uppercase;}
.addbox input{width:100%;border:1px solid var(--line);border-radius:9px;padding:10px 12px;margin-bottom:8px;font:14px/1.4 system-ui;background:#fcfaf6;color:var(--ink);}
.addbox button{width:100%;border:none;border-radius:10px;padding:12px;font-size:15px;font-weight:600;background:var(--teal);color:#fff;cursor:pointer;}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:16px;margin-bottom:14px;}
.card.skip,.card.won{opacity:.55;}
.row1{display:flex;justify-content:space-between;align-items:flex-start;gap:10px;}
.nm{font-weight:600;font-size:16px;}
.meta{font-size:13px;color:var(--mute);margin:2px 0 8px;}
.badge{font-family:ui-monospace,monospace;font-size:10px;letter-spacing:1px;text-transform:uppercase;padding:3px 8px;border-radius:999px;white-space:nowrap;}
.fit-yes{background:#e3f1ec;color:var(--ok);}
.fit-maybe{background:#f6ecdd;color:var(--terra);}
.fit-no{background:#f6e3de;color:var(--danger);}
.fit-unvetted{background:#eee9df;color:var(--mute);}
.book{font-size:12px;color:var(--mute);margin-bottom:8px;}
textarea{width:100%;border:1px solid var(--line);border-radius:10px;padding:11px;font:13px/1.5 system-ui;color:var(--ink);background:#fcfaf6;resize:vertical;min-height:120px;}
.btns{display:flex;flex-wrap:wrap;gap:6px;margin-top:8px;}
.btns button{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:8px;padding:7px 11px;font-size:12px;cursor:pointer;}
.btns a.gbtn{border:1px solid var(--line);background:#fff;color:var(--ink);border-radius:8px;padding:7px 11px;font-size:12px;text-decoration:none;display:inline-flex;align-items:center;}
.btns button.copy{background:var(--teal);color:#fff;border-color:var(--teal);}
.btns button.on{background:var(--ink);color:#fff;border-color:var(--ink);}
.btns button.rm{color:var(--danger);}
.filters{display:flex;gap:8px;flex-wrap:wrap;margin:0 0 18px;}
.filters button{border:1px solid var(--line);background:#fff;color:var(--mute);border-radius:999px;padding:6px 14px;font-size:13px;cursor:pointer;font-family:ui-monospace,Menlo,monospace;}
.filters button.on{background:var(--ink);color:#fff;border-color:var(--ink);}
.tools{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin:0 0 12px;}
.tools input{flex:1;min-width:180px;border:1px solid var(--line);border-radius:999px;padding:8px 14px;font:14px/1.4 system-ui;background:#fcfaf6;color:var(--ink);}
.tools button{border:1px solid var(--line);background:#fff;color:var(--mute);border-radius:999px;padding:8px 14px;font-size:13px;cursor:pointer;font-family:ui-monospace,Menlo,monospace;white-space:nowrap;}
.tools button.on{background:var(--terra);color:#fff;border-color:var(--terra);}
.badge.pri{background:#fbe9d6;color:var(--terra);margin-left:6px;}
.badge.due{background:#f6e3de;color:var(--danger);margin-left:6px;}
.fu{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:10px;padding-top:9px;border-top:1px dashed var(--line);}
.fu label{font-size:11px;color:var(--mute);font-family:ui-monospace,Menlo,monospace;display:flex;align-items:center;gap:5px;text-transform:uppercase;letter-spacing:.5px;}
.fu input[type=date]{border:1px solid var(--line);border-radius:8px;padding:6px 9px;font:13px system-ui;background:#fcfaf6;color:var(--ink);}
.fu input.fu-reply{flex:1;min-width:140px;border:1px solid var(--line);border-radius:8px;padding:6px 10px;font:13px system-ui;background:#fcfaf6;color:var(--ink);}
.fu button.fu-save{border:1px solid var(--teal);background:var(--teal);color:#fff;border-radius:8px;padding:6px 12px;font-size:12px;cursor:pointer;}
.fu[data-due="1"]{border-top-color:var(--danger);}
.toast{position:fixed;left:50%;bottom:24px;transform:translateX(-50%) translateY(20px);background:#2d2d2d;color:#fff;padding:11px 18px;border-radius:999px;font-size:14px;opacity:0;transition:.25s;pointer-events:none;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style></head><body>
""" + NAV_LIGHT + """
<h1>Leads</h1>
<div class="sub">{{ vertical }} - {{ leads|length }} active</div>
<div class="addbox">
  <h2>Vet &amp; add a lead</h2>
  <input id="v_name" placeholder="Name (e.g. Jane Smith, LICSW)">
  <input id="v_prof" placeholder="Profession" value="therapist">
  <input id="v_town" placeholder="Town">
  <input id="v_url" placeholder="Website URL (optional - AI checks their booking system)">
  <input id="v_contact" placeholder="Phone or email (optional)">
  <button onclick="vet()">Vet &amp; add</button>
</div>
<div class="tools">
  <input id="search" type="search" placeholder="Search name, town, profession..." oninput="applyFilters()">
  <button id="sortbtn" onclick="toggleSort(this)">Sort: priority</button>
</div>
<div class="filters" id="filters">
  <button class="on" data-f="all" onclick="filt('all',this)">All</button>
  <button data-f="new" onclick="filt('new',this)">New</button>
  <button data-f="contacted" onclick="filt('contacted',this)">Contacted</button>
  <button data-f="due" onclick="filt('due',this)">Due</button>
  <button data-f="replied" onclick="filt('replied',this)">Replied</button>
  <button data-f="won" onclick="filt('won',this)">Won</button>
  <button data-f="skip" onclick="filt('skip',this)">Skip</button>
</div>
{% for l in leads %}
<div class="card {{ l.status }}" id="c-{{ l.id }}" data-idx="{{ loop.index0 }}" data-priority="{{ l.priority|default('normal') }}" data-due="{{ '1' if (l.next_followup and l.next_followup <= today) else '0' }}" data-search="{{ (l.name ~ ' ' ~ l.profession ~ ' ' ~ l.town ~ ' ' ~ l.contact ~ ' ' ~ l.booking)|lower }}">
  <div class="row1">
    <div><div class="nm">{{ l.name }}{% if l.priority=='high' %}<span class="badge pri">priority</span>{% endif %}{% if l.next_followup and l.next_followup <= today %}<span class="badge due">follow up due</span>{% endif %}</div><div class="meta">{{ l.profession }} - {{ l.town }}{% if l.contact %} - {{ l.contact }}{% endif %}</div></div>
    <span class="badge fit-{{ l.fit }}">{{ l.fit }}</span>
  </div>
  <div class="book">Booking: {{ l.booking }}{% if l.reason %} - {{ l.reason }}{% endif %}</div>
  <textarea readonly>{{ l.message }}</textarea>
  <div class="btns">
    <button class="copy" onclick="copyMsg(this)">Copy message</button>
    <a class="gbtn" href="https://www.google.com/search?q={{ (l.name.split('(')[0].strip() ~ ' ' ~ l.town.split('(')[0].strip()) | urlencode }}" target="_blank" rel="noopener">Google &#8599;</a>
    <button class="{{ 'on' if l.status=='contacted' else '' }}" onclick="setStatus('{{ l.id }}','contacted')">Contacted</button>
    <button class="{{ 'on' if l.status=='replied' else '' }}" onclick="setStatus('{{ l.id }}','replied')">Replied</button>
    <button class="{{ 'on' if l.status=='won' else '' }}" onclick="setStatus('{{ l.id }}','won')">Won</button>
    <button class="{{ 'on' if l.status=='skip' else '' }}" onclick="setStatus('{{ l.id }}','skip')">Skip</button>
    <button class="rm" onclick="setStatus('{{ l.id }}','remove')">Remove</button>
  </div>
  <div class="fu" data-due="{{ '1' if (l.next_followup and l.next_followup <= today) else '0' }}">
    <label>Next<input type="date" class="fu-date" value="{{ l.next_followup }}"></label>
    <input type="text" class="fu-reply" value="{{ l.replied }}" placeholder="Reply notes...">
    <button class="fu-save" onclick="saveFollowup(this)">Save</button>
  </div>
</div>
{% endfor %}
<div class="toast" id="toast"></div>
<script>
const CSRF="{{ csrf_token }}";
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show');},1600);}
function copyMsg(b){var t=b.closest('.card').querySelector('textarea');try{navigator.clipboard.writeText(t.value);}catch(e){t.select();document.execCommand('copy');}toast('Message copied');}
async function setStatus(id,status){try{var r=await fetch('/api/leads/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:id,status:status})});if(!r.ok){toast('Failed ('+r.status+')');return;}if(status==='remove'){var c=document.getElementById('c-'+id);if(c)c.remove();toast('Removed');}else{location.reload();}}catch(e){toast('Failed');}}
async function vet(){var name=document.getElementById('v_name').value.trim();if(!name){toast('Name required');return;}toast('Vetting...');try{var r=await fetch('/api/leads/vet',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({name:name,profession:document.getElementById('v_prof').value,town:document.getElementById('v_town').value,url:document.getElementById('v_url').value,contact:document.getElementById('v_contact').value})});var d=await r.json();if(d.ok){toast('Added ('+d.lead.fit+')');location.reload();}else{toast(d.error||'Failed');}}catch(e){toast('Failed');}}
async function saveFollowup(b){
  var card=b.closest('.card'); var id=card.id.slice(2);
  var date=card.querySelector('.fu-date').value;
  var reply=card.querySelector('.fu-reply').value;
  try{var r=await fetch('/api/leads/update',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF':CSRF},body:JSON.stringify({id:id,next_followup:date,replied:reply})});if(!r.ok){toast('Failed ('+r.status+')');return;}toast('Saved');card.dataset.due=(date && date<='{{ today }}')?'1':'0';}catch(e){toast('Failed');}
}
var curStatus='all', sortOn=false;
function filt(s,btn){
  curStatus=s;
  document.querySelectorAll('#filters button').forEach(function(b){b.classList.toggle('on', b===btn);});
  applyFilters();
}
function applyFilters(){
  var q=(document.getElementById('search').value||'').trim().toLowerCase();
  document.querySelectorAll('.card').forEach(function(c){
    var okStatus = (curStatus==='all' || (curStatus==='due' ? c.dataset.due==='1' : c.classList.contains(curStatus)));
    var okSearch = (!q || (c.dataset.search||'').indexOf(q)>=0);
    c.style.display = (okStatus && okSearch) ? '' : 'none';
  });
}
function toggleSort(btn){
  sortOn=!sortOn;
  btn.classList.toggle('on', sortOn);
  var cards=Array.prototype.slice.call(document.querySelectorAll('.card'));
  cards.sort(function(a,b){
    if(sortOn){
      var pa=a.dataset.priority==='high'?0:1, pb=b.dataset.priority==='high'?0:1;
      if(pa!==pb) return pa-pb;
    }
    return (+a.dataset.idx)-(+b.dataset.idx);
  });
  var anchor=document.getElementById('toast');
  cards.forEach(function(c){anchor.parentNode.insertBefore(c, anchor);});
}
(function(){
  document.querySelectorAll('#filters button').forEach(function(b){
    var f=b.dataset.f;
    var n = f==='all' ? document.querySelectorAll('.card').length
          : f==='due' ? document.querySelectorAll('.card[data-due="1"]').length
                      : document.querySelectorAll('.card.'+f).length;
    b.textContent = b.textContent + ' ' + n;
  });
})();
</script>
</body></html>"""

@app.route("/leads")
@admin_required
def leads_page():
    data = _leads_load()
    leads = [l for l in data.get("leads", []) if l.get("status") != "removed"]
    order = {"new": 0, "replied": 1, "contacted": 2, "won": 3, "skip": 4}
    leads.sort(key=lambda l: (order.get(l.get("status"), 9), -l.get("added", 0)))
    import datetime as _dt
    today = _dt.date.today().isoformat()
    return render_template_string(LEADS_HTML, leads=leads, vertical=data.get("vertical", "leads"), today=today, nav_active="leads")

@app.route("/api/leads/update", methods=["POST"])
@admin_required
def leads_update():
    d = request.json or {}
    lid = d.get("id"); status = d.get("status")
    data = _leads_load(); found = False
    for l in data.get("leads", []):
        if l.get("id") == lid:
            if status == "remove":
                l["status"] = "removed"
            elif status in ("new", "contacted", "replied", "won", "skip"):
                l["status"] = status
            if "replied" in d:
                l["replied"] = (d.get("replied") or "").strip()
            if "next_followup" in d:
                l["next_followup"] = (d.get("next_followup") or "").strip()
            found = True; break
    if not found:
        return jsonify({"ok": False, "error": "not found"}), 404
    _leads_save(data)
    return jsonify({"ok": True})

@app.route("/api/leads/vet", methods=["POST"])
@admin_required
def leads_vet():
    import time as _t, json as _j, requests as _rq
    d = request.json or {}
    name = (d.get("name") or "").strip()
    profession = (d.get("profession") or "therapist").strip() or "therapist"
    town = (d.get("town") or "").strip()
    url = (d.get("url") or "").strip()
    contact = (d.get("contact") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    booking = "unvetted"; fit = "unvetted"; reason = ""
    if url:
        try:
            if not url.startswith("http"):
                url = "https://" + url
            r = _rq.get(url, timeout=20, headers={"User-Agent": "Mozilla/5.0"})
            text = r.text[:6000]
            prompt = ("You are vetting a therapist as a sales lead for a free booking tool aimed at "
                "SOLO, PRIVATE-PAY therapists who do NOT use a full practice-management EHR. From this "
                "website HTML decide and return JSON only with keys booking_system, fit, reason.\n"
                "- booking_system: the scheduling platform if any (TherapyPortal, SimplePractice, Calendly, "
                "Acuity, IntakeQ, Jane, Kareo/Tebra), or 'phone/email only' if none is present.\n"
                "- fit: 'yes' if a solo/private-pay practice with no full EHR or online scheduler we would "
                "replace; 'no' if on a full EHR or clearly an insurance-billing group; 'maybe' if unclear.\n"
                "- reason: one short sentence.\n\nHTML:\n" + text)
            rr = _rq.post("https://api.anthropic.com/v1/messages",
                headers={"x-api-key": os.environ.get("ANTHROPIC_API_KEY", ""),
                         "anthropic-version": "2023-06-01", "content-type": "application/json"},
                json={"model": "claude-haiku-4-5-20251001", "max_tokens": 300,
                      "messages": [{"role": "user", "content": prompt}]},
                timeout=30)
            raw = rr.json()["content"][0]["text"]
            obj, _ = _j.JSONDecoder().raw_decode(raw[raw.find("{"):])
            booking = obj.get("booking_system") or "unvetted"
            fit = obj.get("fit") or "maybe"
            reason = obj.get("reason") or ""
        except Exception as e:
            print(f"leads vet failed: {e!r}", flush=True)
            booking = "vet error"; fit = "maybe"; reason = "auto-vet failed, check manually"
    data = _leads_load()
    lead = {"id": f"ld-{int(_t.time())}", "name": name, "profession": profession, "town": town,
            "contact": contact, "source": url or "manual", "fit": fit, "booking": booking,
            "reason": reason, "channel": "email / phone" if contact else "email / contact form",
            "message": _lead_message(name, profession, town), "status": "new", "added": int(_t.time())}
    data.setdefault("leads", []).insert(0, lead)
    _leads_save(data)
    return jsonify({"ok": True, "lead": lead})

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
    elif brand == "tips":
        context = """This is a quick privacy how-to from Harbor Privacy. The post teaches one specific setting an everyday person can change on a Windows PC, Android phone, iPhone, smart TV, or smart speaker to stop being tracked. It must name the exact step-by-step path so a non-technical person can follow it (for example: Settings > Privacy & Security > Tracking > turn off Allow Apps to Request to Track). Keep it to that one tip. Harbor Privacy makes whole-home privacy automatic for the stuff you can't toggle, at harborprivacy.com."""
        problem_angles = [
            "Most of your gadgets ship with tracking turned ON by default. Here's a 30-second fix.",
            "Your phone has a privacy switch most people never find. Here's where it is.",
            "You don't need new software to stop most tracking. You need one setting changed.",
            "The companies that make your devices bury the off switch on purpose. Here it is.",
            "One toggle. That's all it takes to stop this device from profiling you.",
        ]
        import random
        problem = random.choice(problem_angles)
        cta_fb = "More privacy tips at harborprivacy.com/learn"
        cta_ig = "More tips in bio"
        cta_li = "harborprivacy.com/learn"
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
    extra_keys = []
    if brand == "tips":
        platform_rules.append("- Hashtags: Every caption (facebook, instagram, linkedin) must end with 3 to 5 relevant hashtags on their own new line, for example: #PrivacyTips #iPhone #StopTracking #DataPrivacy")
        platform_rules.append('- headline: a short sentence-case action phrase for the card image, 3 to 6 words, no ending period. Example: "Turn off iPhone app tracking"')
        platform_rules.append('- path: the exact settings menu path the person taps, with " > " between each step. Example: "Settings > Privacy & Security > Tracking"')
        platform_rules.append('- action: the specific switch or option to turn off, short, no leading verb. Example: "Allow Apps to Request to Track"')
        extra_keys = ["headline", "path", "action"]
    else:
        platform_rules.append(f"- headline: A short punchy 4-8 word image overlay headline for this post. All caps. No punctuation. Examples: STOP LOSING CLIENTS TO VOICEMAIL / YOUR DATA STAYS YOURS / FREE SCHEDULING THAT ACTUALLY WORKS")

    if not platform_keys:
        platform_keys = ["facebook", "instagram"]

    prompt = f"""Write social media posts about: {topic}

Context: {context}

Rules:
- The first line has to stop a scrolling stranger: a surprising fact, a pointed question, or a real stake they feel instantly. Never open with the product name or a slogan.
- Lead with a real problem people face, not a product feature
- Sound like a real person, not a company
- No corporate speak, no buzzwords, no em dashes
- Short and punchy -- people scroll fast
{chr(10).join(platform_rules)}

Return JSON only with keys: {", ".join(platform_keys + extra_keys)}"""
    return prompt, platform_keys

SOCIAL_IMAGES_ENABLED = True  # local SVG brand-card renderer (no API quota)

def _generate_engine_card(brand, topic):
    """Render a card via the shared card_engine (native.no-style 4:5) into the
    social-images dir and return its dashboard URL (basename used by _stash).
    Replaces _generate_image_claude/_generate_tip_card as the card renderer."""
    import card_engine, pathlib as _pl, time as _t
    tbl = {
        "harbor":  ("HARBOR / PRIVACY", "harborprivacy.com",        "Network-level privacy for every device."),
        "career":  ("HARBOR / CAREER",  "harborprivacy.com/career", "Beat the filter. Keep your data."),
        "fax":     ("HARBOR / FAX",     "harborprivacy.com/fax",    "Send private documents. No account."),
        "booking": ("HARBOR / BOOKING", "harborprivacy.com/booking","Scheduling that never sells client data."),
        "money":   ("HARBOR / MONEY",   "harborprivacy.com/money",  "Budget without your bank login."),
        "scan":    ("HARBOR / SCAN",    "scan.harborprivacy.com",   "Find and delete your data for sale."),
        "tips":    ("HARBOR / PRIVACY", "harborprivacy.com/learn",  "A 30-second privacy fix."),
    }
    mark, url, sub = tbl.get(brand, tbl["harbor"])
    try:
        out_dir = _pl.Path("/var/www/network/social-images"); out_dir.mkdir(exist_ok=True)
        _generate_engine_card._n = getattr(_generate_engine_card, "_n", 0) + 1
        stem = f"social-{brand}-{int(_t.time())}-{_generate_engine_card._n}"
        head = topic[0].upper() + topic[1:]
        card_engine.render(stem, brand=brand, headline=head, subhead=sub,
                           eyebrow=mark, url=url, topic=topic, out_dir=str(out_dir))
        return f"https://dashboard.harborprivacy.com/social-images/{stem}.png"
    except Exception as e:
        print(f"_generate_engine_card EXC {e!r}", flush=True)
        return None


def _generate_image_claude(brand, topic):
    if not SOCIAL_IMAGES_ENABLED:
        return None
    # Brand-card renderer: on-brand Harbor SVG tile -> PNG via rsvg-convert.
    # Replaces AI image generation; name kept for back-compat with callers.
    import subprocess as _sp, time as _t, pathlib, textwrap as _tw, html as _html
    BG = "#fbf7f1"; GRID = "#e5dfd3"; INK = "#1a2420"; MUTE = "#6b7a72"; TEAL = "#1f5d6b"; TERRA = "#c98a52"
    brands = {
        "harbor":  ("HARBOR / PRIVACY", "PRIVACY TIP",   "harborprivacy.com",
                    ["Network-level privacy for your whole home.", "No tech skills needed. Every device covered."]),
        "career":  ("HARBOR / CAREER",  "CAREER TIP",    "harborprivacy.com/career",
                    ["Privacy-first AI that tailors your resume.", "Beat the filter without giving up your data."]),
        "fax":     ("HARBOR / FAX",     "PRIVACY TIP",   "harborprivacy.com/fax",
                    ["Send sensitive documents privately.", "No account, no stored copy left behind."]),
        "booking": ("HARBOR / BOOKING", "BUSINESS TIP",  "harborprivacy.com/booking",
                    ["Free scheduling that keeps client data yours.", "Nothing tracked, nothing sold."]),
        "money":   ("HARBOR / MONEY",   "MONEY TIP",     "harborprivacy.com/money",
                    ["Budgeting without your bank login.", "Forward receipts and alerts. Private by design."]),
        "tim":     ("HARBOR / PRIVACY", "PRIVACY TIP",   "harborprivacy.com",
                    ["Network-level privacy for your whole home.", "No tech skills needed. Every device covered."]),
        "tips":    ("HARBOR / PRIVACY", "PRIVACY TIP",   "harborprivacy.com/learn",
                    ["A 30-second privacy fix.", "One setting. Less tracking."]),
    }
    mark, eyebrow, url, subs = brands.get(brand, brands["harbor"])
    # Tips render as a recognizable device-tip series: terra accent + the
    # gadget the tip is for shown as the eyebrow (WINDOWS / ANDROID / iPHONE...).
    accent = TEAL
    if brand == "tips":
        accent = TERRA
        tl = (topic or "").lower()
        device = next((lbl for needles, lbl in [
            (("windows", "windows 11"), "WINDOWS TIP"),
            (("android",), "ANDROID TIP"),
            (("iphone", "ios"), "iPHONE TIP"),
            (("smart tv", "content recognition", "acr"), "SMART TV TIP"),
            (("echo", "alexa"), "ALEXA TIP"),
            (("roku", "fire tv"), "STREAMING TIP"),
            (("google account", "google"), "GOOGLE TIP"),
        ] if any(n in tl for n in needles)), "PRIVACY TIP")
        eyebrow = device
    t = (topic or "").strip()
    t = (t[0].upper() + t[1:]) if t else "Privacy by default."
    lines = _tw.wrap(t, width=20)[:4] or ["Privacy by default."]
    longest = max(len(l) for l in lines)
    fs = 92 if longest <= 14 else (76 if longest <= 18 else 62)
    lh = int(fs * 1.12)
    y0 = 330 if len(lines) >= 3 else 410
    headsvg = "".join(
        f'<text x="90" y="{y0 + i*lh}" font-family="DM Serif Display, Georgia, serif" '
        f'font-size="{fs}" fill="{INK}">{_html.escape(l)}</text>' for i, l in enumerate(lines))
    sub_y = max(y0 + len(lines) * lh + 40, 600)
    subsvg = "".join(
        f'<text x="90" y="{sub_y + i*52}" font-family="DM Sans, system-ui, sans-serif" '
        f'font-size="33" fill="{INK if i == 0 else MUTE}" font-weight="400">{_html.escape(s)}</text>'
        for i, s in enumerate(subs))
    ew = 22 + len(eyebrow) * 12
    # corner glyph: lightbulb for tips, alert circle for everything else
    if brand == "tips":
        glyph = (f'<g transform="translate(886,106) scale(3.67)" stroke="{TERRA}" '
                 f'stroke-width="1.6" fill="none" stroke-linecap="round" stroke-linejoin="round">'
                 f'<path d="M9 18h6"/><path d="M10 22h4"/>'
                 f'<path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V18h6v-1.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></g>')
    else:
        glyph = (f'<circle cx="930" cy="150" r="44" fill="none" stroke="{TERRA}" stroke-width="6" opacity="0.9"/>'
                 f'<line x1="930" y1="128" x2="930" y2="158" stroke="{TERRA}" stroke-width="8" stroke-linecap="round"/>'
                 f'<circle cx="930" cy="176" r="5" fill="{TERRA}"/>')
    svg = f'''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1080 1080" role="img" aria-label="{_html.escape(t)}">
  <defs>
    <pattern id="grid" width="60" height="60" patternUnits="userSpaceOnUse">
      <path d="M 60 0 L 0 0 0 60" fill="none" stroke="{GRID}" stroke-width="1"/>
    </pattern>
    <radialGradient id="glow" cx="50%" cy="-5%" r="65%">
      <stop offset="0%" stop-color="rgba(31,93,107,0.10)"/>
      <stop offset="100%" stop-color="rgba(31,93,107,0)"/>
    </radialGradient>
  </defs>
  <rect width="1080" height="1080" fill="{BG}"/>
  <rect width="1080" height="1080" fill="url(#grid)" opacity="0.55"/>
  <rect width="1080" height="1080" fill="url(#glow)"/>
  <rect x="36" y="36" width="1008" height="1008" rx="24" ry="24" fill="none" stroke="{GRID}" stroke-width="2"/>
  <text x="90" y="148" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="26" fill="{TEAL}" letter-spacing="7" font-weight="500">{mark}</text>
  <g transform="translate(90, 198)">
    <rect x="0" y="0" width="{ew}" height="38" rx="19" ry="19" fill="none" stroke="{accent}" stroke-width="1.5"/>
    <text x="{ew/2}" y="25" text-anchor="middle" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="13" fill="{accent}" letter-spacing="3" font-weight="500">{eyebrow}</text>
  </g>
  {headsvg}
  {subsvg}
  <line x1="90" y1="900" x2="990" y2="900" stroke="{GRID}" stroke-width="1.5"/>
  {glyph}
  <text x="990" y="970" text-anchor="end" font-family="DM Mono, ui-monospace, Menlo, monospace" font-size="22" fill="{TEAL}" letter-spacing="3" font-weight="500">{url}</text>
</svg>'''
    try:
        out_dir = pathlib.Path("/var/www/network/social-images")
        out_dir.mkdir(exist_ok=True)
        _generate_image_claude._n = getattr(_generate_image_claude, "_n", 0) + 1
        stem = f"social-{brand}-{int(_t.time())}-{_generate_image_claude._n}"
        svgp = out_dir / (stem + ".svg")
        pngp = out_dir / (stem + ".png")
        svgp.write_text(svg)
        _sp.run(["rsvg-convert", "-w", "1080", "-h", "1080", str(svgp), "-o", str(pngp)],
                check=True, timeout=30)
        return f"https://dashboard.harborprivacy.com/social-images/{stem}.png"
    except Exception as e:
        print(f"_generate_image: brand-card EXC {e!r}", flush=True)
    return None

def _generate_tip_card(topic, card, fmt="story"):
    # Canva-style privacy-tip card: cream, rounded border, terra device pill,
    # centered lightbulb, big serif headline, the exact settings path, divider,
    # teal action line, "A 30-second privacy fix" footer.
    # fmt = "story" (1080x1920 vertical) or "square" (1080x1080).
    if not SOCIAL_IMAGES_ENABLED:
        return None
    import subprocess as _sp, time as _t, pathlib, textwrap as _tw, html as _html
    BG = "#fbf7f1"; GRID = "#e5dfd3"; INK = "#1a2420"; MUTE = "#6b7a72"; TEAL = "#1f5d6b"; TERRA = "#c98a52"
    if fmt == "square":
        W = H = 1080; bx, by, bw, bh, brx = 32, 32, 1016, 1016, 40
        pill_y = 72; bulb_cy = 250; bscale = 3.0; head_y0 = 430; footer_y = 1012
        wrapw = 14; f_big, f_mid, f_sm = 78, 66, 54; foot_fs = 24
        head_gap = 90; step_gap = 20; div_gap = 55
    else:
        W, H = 1080, 1920; bx, by, bw, bh, brx = 44, 44, 992, 1832, 48
        pill_y = 120; bulb_cy = 430; bscale = 4.6; head_y0 = 650; footer_y = 1800
        wrapw = 11; f_big, f_mid, f_sm = 96, 80, 66; foot_fs = 26
        head_gap = 120; step_gap = 30; div_gap = 70
    card = card or {}
    tl = (topic or "").lower()
    label = next((lbl for needles, lbl in [
        (("windows",), "WINDOWS TIP"), (("android",), "ANDROID TIP"),
        (("iphone", "ios"), "iPHONE TIP"),
        (("smart tv", "content recognition", "acr"), "SMART TV TIP"),
        (("echo", "alexa"), "ALEXA TIP"), (("roku", "fire tv"), "STREAMING TIP"),
        (("google account", "google"), "GOOGLE TIP"),
    ] if any(n in tl for n in needles)), "PRIVACY TIP")
    head = (card.get("headline") or (topic or "A 30-second privacy fix")).strip()
    head = head[0].upper() + head[1:] if head else head
    path = (card.get("path") or "").strip()
    action = (card.get("action") or "").strip()

    def esc(s): return _html.escape(s or "")
    lines = _tw.wrap(head, width=wrapw)[:4] or [head]
    longest = max(len(l) for l in lines)
    fs = f_big if longest <= wrapw else (f_mid if longest <= wrapw + 4 else f_sm)
    lh = int(fs * 1.12)
    cursor = head_y0 + (len(lines) - 1) * lh + head_gap

    pw = 64 + len(label) * 14
    pill = (f'<rect x="80" y="{pill_y}" width="{pw}" height="58" rx="29" fill="{TERRA}"/>'
            f'<text x="{80 + pw/2}" y="{pill_y+38}" text-anchor="middle" font-family="DM Mono, monospace" '
            f'font-size="22" fill="#fff" letter-spacing="3" font-weight="500">{esc(label)}</text>')
    s = bscale
    bulb = (f'<g transform="translate({540-12*s},{bulb_cy-12*s}) scale({s})" stroke="{TERRA}" '
            f'stroke-width="1.5" fill="none" stroke-linecap="round" stroke-linejoin="round">'
            f'<path d="M9 18h6"/><path d="M10 22h4"/>'
            f'<path d="M12 2a7 7 0 0 0-4 12.7c.6.5 1 1.3 1 2.1V18h6v-1.2c0-.8.4-1.6 1-2.1A7 7 0 0 0 12 2z"/></g>')
    headsvg = "".join(
        f'<text x="540" y="{head_y0 + i*lh}" text-anchor="middle" '
        f'font-family="DM Serif Display, Georgia, serif" font-size="{fs}" fill="{INK}">{esc(l)}</text>'
        for i, l in enumerate(lines))
    stepsvg = ""
    if path:
        sfs = 32 if len(path) <= 42 else 26
        wrapped = _tw.wrap(path, width=max(10, int(900 / (sfs * 0.55))))[:2]
        for i, sl in enumerate(wrapped):
            stepsvg += (f'<text x="540" y="{cursor + i*int(sfs*1.4)}" text-anchor="middle" '
                        f'font-family="DM Sans, sans-serif" font-size="{sfs}" fill="{INK}" font-weight="500">{esc(sl)}</text>')
        cursor += int(sfs * 1.4) * max(1, len(wrapped)) + step_gap
    cursor += 18
    divider = f'<line x1="380" y1="{cursor}" x2="700" y2="{cursor}" stroke="{GRID}" stroke-width="2"/>'
    cursor += div_gap
    actsvg = ""
    if action:
        atxt = f"Turn off: {action}"
        afs = 30 if len(atxt) <= 46 else 25
        for i, al in enumerate(_tw.wrap(atxt, width=max(10, int(900 / (afs * 0.55))))[:2]):
            actsvg += (f'<text x="540" y="{cursor + i*int(afs*1.4)}" text-anchor="middle" '
                       f'font-family="DM Sans, sans-serif" font-size="{afs}" fill="{TEAL}" font-weight="500">{esc(al)}</text>')
    footer = (f'<text x="540" y="{footer_y}" text-anchor="middle" font-family="DM Mono, monospace" '
              f'font-size="{foot_fs}" fill="{MUTE}" letter-spacing="2">A 30-second privacy fix</text>')
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {W} {H}">'
           f'<rect width="{W}" height="{H}" fill="{BG}"/>'
           f'<rect x="{bx}" y="{by}" width="{bw}" height="{bh}" rx="{brx}" fill="none" stroke="{GRID}" stroke-width="2"/>'
           f'{pill}{bulb}{headsvg}{stepsvg}{divider}{actsvg}{footer}</svg>')
    try:
        out_dir = pathlib.Path("/var/www/network/social-images")
        out_dir.mkdir(exist_ok=True)
        _generate_tip_card._n = getattr(_generate_tip_card, "_n", 0) + 1
        stem = f"tip-{fmt}-{int(_t.time())}-{_generate_tip_card._n}"
        svgp = out_dir / (stem + ".svg")
        pngp = out_dir / (stem + ".png")
        svgp.write_text(svg)
        _sp.run(["rsvg-convert", "-w", str(W), "-h", str(H), str(svgp), "-o", str(pngp)],
                check=True, timeout=30)
        return f"https://dashboard.harborprivacy.com/social-images/{stem}.png"
    except Exception as e:
        print(f"_generate_tip_card: EXC {e!r}", flush=True)
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

        ip = request.headers.get("X-Real-IP", request.remote_addr or "")

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

    profile_url = f"https://adblock.harborprivacy.com/profiles/{client_id}.mobileconfig"
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
    ip = request.headers.get("X-Real-IP", request.remote_addr or "")

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
_SYS_CACHE = {"ts": 0, "data": None}

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
                    "harbor-career","brazer-dashboard","nginx",
                    "fail2ban","AdGuardHome"]
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


_HS_PROFILE_TMPL = """<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin / Harbor Scan</p>
    <h1>Profile #{{ pid }}</h1>
  </div>
  {% if data.error %}
    <div class="card" style="border-color:#ff4e4e;color:#ff4e4e;"><strong>error:</strong> {{ data.error }}</div>
  {% elif not data.profile %}
    <div class="card">Profile not found.</div>
  {% else %}
  {% set p = data.profile %}
  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Identity</div>
    <div style="display:grid;grid-template-columns:140px 1fr;gap:8px 16px;font-size:13px;">
      <div style="color:var(--muted);">Full name</div><div>{{ p.full_name }}</div>
      <div style="color:var(--muted);">Customer ID</div><div style="font-family:DM Mono,monospace;">{{ p.customer_id }}</div>
      <div style="color:var(--muted);">DOB</div><div>{{ p.dob or '-' }}</div>
      <div style="color:var(--muted);">Authorization</div>
      <div>{% if p.authorization_signed_at %}<span class="badge badge-on">signed</span> <span style="color:var(--muted);font-family:DM Mono,monospace;font-size:11px;">{{ p.authorization_signed_at }}</span>{% else %}<span class="badge badge-off">unsigned</span> <span style="color:var(--muted);font-size:11px;">(opt-out engine will skip this profile)</span>{% endif %}</div>
      <div style="color:var(--muted);">Aliases</div><div>{% for a in p.aliases or [] %}<span class="badge">{{ a }}</span> {% else %}<span style="color:var(--muted);">none</span>{% endfor %}</div>
      <div style="color:var(--muted);">Emails</div><div>{% for e in p.emails or [] %}<div style="font-family:DM Mono,monospace;font-size:12px;">{{ e }}</div>{% else %}<span style="color:var(--muted);">none</span>{% endfor %}</div>
      <div style="color:var(--muted);">Phones</div><div>{% for ph in p.phones or [] %}<div style="font-family:DM Mono,monospace;font-size:12px;">{{ ph }}</div>{% else %}<span style="color:var(--muted);">none</span>{% endfor %}</div>
      <div style="color:var(--muted);">Addresses</div><div>{% for a in p.addresses or [] %}<div style="font-size:12px;">{{ a.street1 }}{% if a.street2 %}, {{ a.street2 }}{% endif %}, {{ a.city }}, {{ a.state }} {{ a.zip }}</div>{% else %}<span style="color:var(--muted);">none</span>{% endfor %}</div>
      <div style="color:var(--muted);">Relatives</div><div>{% for r in p.relatives or [] %}<span class="badge">{{ r }}</span> {% else %}<span style="color:var(--muted);">none</span>{% endfor %}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Findings ({{ data.findings|length }})</div>
    {% if data.findings %}
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">broker</th><th>listing</th><th style="text-align:right;">confidence</th>
        <th>status</th><th style="text-align:right;">opt-outs</th><th>last seen</th>
      </tr>
      {% for f in data.findings %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;color:var(--accent);">{{ f.broker_id }}</td>
        <td style="font-size:11px;font-family:DM Mono,monospace;word-break:break-all;"><a href="{{ f.listing_url }}" target="_blank" rel="noopener" style="color:var(--text);">{{ f.listing_url[:80] }}{% if f.listing_url|length > 80 %}…{% endif %}</a></td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ '%.2f'|format(f.confidence|float) }}</td>
        <td>{% if f.status == 'removed' %}<span class="badge badge-on">removed</span>{% else %}<span class="badge badge-off">{{ f.status }}</span>{% endif %}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ f.optout_attempts }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ f.last_seen_at }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div style="color:var(--muted);padding:10px 0;">No findings yet.</div>{% endif %}
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Opt-Out Requests ({{ data.optouts|length }})</div>
    {% if data.optouts %}
      {% for r in data.optouts %}
        <div style="border-top:1px solid var(--border);padding:12px 0;">
          <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
            <span><span style="color:var(--muted);font-family:DM Mono,monospace;">#{{ r.request_id }}</span> <span style="color:var(--accent);">{{ r.broker_id }}</span> <span class="badge">{{ r.method }}</span></span>
            <span>{% if r.status == 'verified_removed' %}<span class="badge badge-on">{{ r.status }}</span>{% elif r.status in ['failed','blocked_unauthorized','relisted'] %}<span class="badge badge-off">{{ r.status }}</span>{% else %}<span class="badge">{{ r.status }}</span>{% endif %} <span style="color:var(--muted);font-family:DM Mono,monospace;font-size:11px;">attempt {{ r.attempts }}</span></span>
          </div>
          <div style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);word-break:break-all;">{{ r.listing_url }}</div>
          <div style="display:grid;grid-template-columns:140px 1fr;gap:2px 16px;margin-top:6px;font-size:11px;font-family:DM Mono,monospace;color:var(--muted);">
            {% if r.submitted_at %}<div>submitted</div><div>{{ r.submitted_at }}</div>{% endif %}
            {% if r.confirmation_at %}<div>confirmed</div><div>{{ r.confirmation_at }}</div>{% endif %}
            {% if r.verified_removed_at %}<div>verified removed</div><div>{{ r.verified_removed_at }}</div>{% endif %}
            {% if r.last_error %}<div style="color:#ff4e4e;">last error</div><div style="color:#ff4e4e;">{{ r.last_error }}</div>{% endif %}
          </div>
        </div>
      {% endfor %}
    {% else %}<div style="color:var(--muted);padding:10px 0;">No opt-out requests yet.</div>{% endif %}
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Scan Schedule</div>
    {% if data.schedule %}
    <table style="width:100%;border-collapse:collapse;font-size:12px;font-family:DM Mono,monospace;">
      <tr style="text-align:left;color:var(--muted);font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:6px 0;">broker</th><th>next search</th><th>next verify</th><th>next relist check</th>
      </tr>
      {% for s in data.schedule %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:8px 0;color:var(--accent);">{{ s.broker_id }}</td>
        <td>{{ s.next_search_at }}</td>
        <td>{{ s.next_verify_at or '-' }}</td>
        <td>{{ s.next_relist_check_at or '-' }}</td>
      </tr>
      {% endfor %}
    </table>
    {% else %}<div style="color:var(--muted);padding:10px 0;">No schedule rows.</div>{% endif %}
  </div>
  {% endif %}
  <a href="/admin/scan" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;">← Back to Harbor Scan</a>
</div>
"""

# ---- Harbor Scan admin summary (restored from refactor) ----
import subprocess as _hs_subprocess

_HS_DIR = "/home/ubuntu/harbor-scan"
_HS_PY = f"{_HS_DIR}/.venv/bin/python"

def _hs_env():
    if hasattr(_hs_env, "_cache"):
        return _hs_env._cache
    env = dict(os.environ)
    try:
        with open(f"{_HS_DIR}/.env") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k] = v
    except Exception:
        pass
    _hs_env._cache = env
    return env

def _hs_summary(profile_id=None):
    cmd = [_HS_PY, "worker.py", "scan-summary"]
    if profile_id is not None:
        cmd += ["--profile-id", str(profile_id)]
    try:
        out = _hs_subprocess.run(
            cmd, cwd=_HS_DIR, capture_output=True, text=True,
            timeout=20, env=_hs_env(),
        )
    except Exception as e:
        return {"error": f"subprocess: {e}"}
    if out.returncode != 0:
        return {"error": (out.stderr or "non-zero exit").strip()[:400]}
    try:
        return json.loads(out.stdout)
    except Exception as e:
        return {"error": f"json: {e}", "raw": out.stdout[:400]}

_HS_OVERVIEW_TMPL = """<div class="wrap">
  <div style="margin-bottom:32px;">
    <p style="font-family:'DM Mono',monospace;font-size:10px;color:var(--accent);letter-spacing:0.2em;text-transform:uppercase;margin-bottom:8px;">Admin</p>
    <h1>Harbor Scan</h1>
  </div>
  {% if data.error %}
    <div class="card" style="border-color:#ff4e4e;color:#ff4e4e;"><strong>error:</strong> {{ data.error }}</div>
  {% else %}
  <div class="stat-grid" style="margin-bottom:20px;">
    <div class="stat"><div class="stat-num">{{ data.totals.profiles_total }}</div><div class="stat-label">Profiles</div></div>
    <div class="stat"><div class="stat-num" style="color:var(--accent);">{{ data.totals.profiles_authorized }}</div><div class="stat-label">Authorized</div></div>
    <div class="stat"><div class="stat-num" style="color:#ff4e4e;">{{ data.totals.findings_found }}</div><div class="stat-label">Open Findings</div></div>
    <div class="stat"><div class="stat-num" style="color:#22c55e;">{{ data.totals.findings_removed }}</div><div class="stat-label">Removed</div></div>
    <div class="stat"><div class="stat-num">{{ data.totals.brokers_enabled }}</div><div class="stat-label">Brokers Enabled</div></div>
    <div class="stat"><div class="stat-num">{{ data.totals.clicks_queued }}</div><div class="stat-label">Clicks Queued</div></div>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Worker Status</div>
    {% set ws = data.worker_status %}
    <div style="display:flex;justify-content:space-between;align-items:center;padding:10px 0;border-bottom:1px solid var(--border);font-size:13px;">
      <span><span style="font-family:DM Mono,monospace;color:var(--muted);">Pi SOCKS tunnel</span></span>
      <span>{% if ws.socks.ok %}<span class="badge badge-on">up</span>{% elif ws.socks.proxy %}<span class="badge badge-off">down</span> <span style="font-family:DM Mono,monospace;font-size:11px;color:#ff4e4e;">{{ ws.socks.error or 'no SOCKS5 reply' }}</span>{% else %}<span class="badge">no proxy</span>{% endif %}</span>
    </div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;margin-top:6px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">worker</th><th>state</th><th>last run</th><th>next run</th><th>last invocation</th><th style="text-align:right;">errors</th>
      </tr>
      {% for w in ws.workers %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;">{{ w.name }}</td>
        <td>{% if w.active == 'active' %}<span class="badge badge-on">{{ w.active }}</span>{% else %}<span class="badge badge-off">{{ w.active }}</span>{% endif %}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ w.last_run or '-' }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ w.next_run or '-' }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{% if w.last_invocation_at %}{% if w.last_succeeded %}<span style="color:#22c55e;">●</span>{% else %}<span style="color:#ff4e4e;">●</span>{% endif %} {{ w.last_invocation_at }}{% else %}never{% endif %}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;{% if w.recent_errors %}color:#ff4e4e;{% else %}color:#22c55e;{% endif %}">{{ w.recent_errors|length }}</td>
      </tr>
      {% if w.recent_errors %}
        {% for e in w.recent_errors %}
        <tr><td colspan="6" style="padding:6px 0 6px 18px;font-family:DM Mono,monospace;font-size:11px;color:#ff4e4e;border-top:none;word-break:break-word;">
          <span style="color:var(--muted);">{{ e.broker_id or e.url or '' }}</span> {{ (e.error or '')[:200] }}
        </td></tr>
        {% endfor %}
      {% endif %}
      {% endfor %}
    </table>
    <p style="font-size:11px;color:var(--muted);margin-top:8px;font-family:DM Mono,monospace;">● green = last invocation succeeded · ● red = last invocation had errors · errors clear when next run is clean</p>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Opt-Out Pipeline</div>
    {% if data.optouts_by_status %}
      {% for r in data.optouts_by_status %}
        <div style="display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--border);">
          <span>{{ r.status }}</span>
          <span style="font-family:DM Mono,monospace;font-size:12px;color:var(--muted);">{{ r.n }}</span>
        </div>
      {% endfor %}
    {% else %}
      <div style="color:var(--muted);padding:10px 0;">No opt-out requests yet.</div>
    {% endif %}
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Brokers</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">id</th><th>name</th><th>tier</th><th>enabled</th>
        <th style="text-align:right;padding-right:20px;">open</th><th style="text-align:right;padding-right:20px;">removed</th><th style="padding-left:24px;">last verified</th>
      </tr>
      {% for b in data.brokers %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;">{{ b.id }}</td>
        <td>{{ b.name }}</td>
        <td><span class="badge">{{ b.optout_tier }}</span></td>
        <td>{% if b.enabled %}<span class="badge badge-on">on</span>{% else %}<span class="badge badge-off">off</span>{% endif %}</td>
        <td style="text-align:right;padding-right:20px;font-family:DM Mono,monospace;">{{ b.findings_open }}</td>
        <td style="text-align:right;padding-right:20px;font-family:DM Mono,monospace;color:#22c55e;">{{ b.findings_removed }}</td>
        <td style="padding-left:24px;font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ b.last_verified or '-' }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Profiles</div>
    <table style="width:100%;border-collapse:collapse;font-size:13px;">
      <tr style="text-align:left;color:var(--muted);font-family:DM Mono,monospace;font-size:10px;letter-spacing:0.15em;text-transform:uppercase;">
        <th style="padding:8px 0;">id</th><th>name</th><th>customer</th><th>auth</th>
        <th style="text-align:right;">emails</th><th style="text-align:right;">phones</th>
        <th style="text-align:right;">addrs</th><th style="text-align:right;">aliases</th>
        <th style="text-align:right;">open</th><th style="text-align:right;">removed</th>
      </tr>
      {% for p in data.profiles %}
      <tr style="border-top:1px solid var(--border);">
        <td style="padding:10px 0;font-family:DM Mono,monospace;"><a href="/admin/scan/profile/{{ p.id }}" style="color:var(--accent);text-decoration:none;">#{{ p.id }}</a></td>
        <td>{{ p.full_name }}</td>
        <td style="font-family:DM Mono,monospace;font-size:11px;color:var(--muted);">{{ p.customer_id }}</td>
        <td>{% if p.authorization_signed_at %}<span class="badge badge-on">signed</span>{% else %}<span class="badge badge-off">unsigned</span>{% endif %}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.emails_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.phones_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.addresses_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;">{{ p.aliases_count }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;color:#ff4e4e;">{{ p.findings_open }}</td>
        <td style="text-align:right;font-family:DM Mono,monospace;color:#22c55e;">{{ p.findings_removed }}</td>
      </tr>
      {% endfor %}
    </table>
  </div>

  <div class="card" style="margin-bottom:20px;">
    <div class="card-label">Recent Opt-Out Activity</div>
    {% if data.recent_optouts %}
      {% for r in data.recent_optouts %}
        <div style="display:flex;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border);font-size:12px;">
          <span><span style="color:var(--muted);font-family:DM Mono,monospace;">#{{ r.request_id }}</span> <a href="/admin/scan/profile/{{ r.profile_id }}" style="color:var(--text);text-decoration:none;">profile {{ r.profile_id }}</a> via <span style="color:var(--accent);">{{ r.broker_id }}</span></span>
          <span style="font-family:DM Mono,monospace;color:var(--muted);">{{ r.status }} ({{ r.attempts }})</span>
        </div>
      {% endfor %}
    {% else %}
      <div style="color:var(--muted);padding:10px 0;">No opt-out activity yet.</div>
    {% endif %}
  </div>
  {% endif %}
  <a href="/admin" style="font-family:'DM Mono',monospace;font-size:11px;color:var(--muted);text-decoration:none;">← Back to Admin</a>
</div>
"""


@app.route("/admin/scan")
@admin_required
def admin_scan_overview():
    data = _hs_summary()
    return render_template_string(STYLE + NAV_ADMIN + _HS_OVERVIEW_TMPL, data=data, active="scan")

@app.route("/admin/scan/profile/<int:profile_id>")
@admin_required
def admin_scan_profile(profile_id):
    data = _hs_summary(profile_id=profile_id)
    return render_template_string(STYLE + NAV_ADMIN + _HS_PROFILE_TMPL,
                                  data=data, pid=profile_id, active="scan")

# ════════════════════════════════════════════════════════════
# /etsy — listing staging page (mockup image + title/tags/description
# with copy and save buttons, same mechanics as /social).
# Copy source of truth: harbor-design-system/assets/stickers/etsy-listings.md
# ════════════════════════════════════════════════════════════

ETSY_LISTINGS_MD = "/home/ubuntu/harbor-design-system/assets/stickers/etsy-listings.md"
ETSY_MOCKUP_DIR  = "/home/ubuntu/harbor-design-system/assets/stickers/mockups"
ETSY_STICKER_DIR = "/home/ubuntu/harbor-design-system/assets/stickers"

def _etsy_listings():
    # Parses etsy-listings.md: blockquote = shared description footer;
    # each "### N. Name" section needs Slug/SKU/Title/Description (top)/Tags lines.
    import re as _re, os as _os
    try:
        with open(ETSY_LISTINGS_MD) as _f:
            md = _f.read()
    except Exception:
        return [], "", {}
    footer = " ".join(l.lstrip(">").strip() for l in md.splitlines() if l.startswith(">"))
    out = []
    for sec in _re.split(r"\n### ", md)[1:]:
        name = sec.split("\n", 1)[0].strip()
        name = _re.sub(r"^\d+\.\s*", "", name)
        def grab(field):
            m = _re.search(r"\*\*" + field + r":\*\*\s*(.+)", sec)
            return m.group(1).strip() if m else ""
        slug = grab("Slug")
        if not slug:
            continue
        # gallery: every variant that exists on disk, hero first
        imgs = []
        def add(label, fname, suffix):
            if _os.path.exists(_os.path.join(ETSY_MOCKUP_DIR, fname)):
                imgs.append({"label": label, "name": fname,
                             "src": "/etsy/img/" + slug + suffix})
        add("Mockup", slug + "-mockup.jpg", "")
        add("Scale", slug + "-scale.jpg", "?variant=scale")
        add("On a laptop", slug + "-laptop.jpg", "?variant=laptop")
        if slug == "the-whole-harbor-pack" and _os.path.exists(
                _os.path.join(ETSY_MOCKUP_DIR, "the-whole-harbor-grid.jpg")):
            imgs.append({"label": "All nine", "name": "the-whole-harbor-grid.jpg",
                         "src": "/etsy/img/the-whole-harbor-grid"})
        out.append({
            "name": name, "slug": slug, "sku": grab("SKU"), "title": grab("Title"),
            "desc": grab(r"Description \(top\)"), "tags": grab("Tags"), "imgs": imgs,
            "has_print": _os.path.exists(_os.path.join(ETSY_STICKER_DIR, slug + "@300dpi.png")),
        })
    shared = {"has_specs": _os.path.exists(_os.path.join(ETSY_MOCKUP_DIR, "etsy-specs.jpg"))}
    return out, footer, shared


ETSY_PAGE_HTML = """<!doctype html><html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no, viewport-fit=cover">
<title>Etsy listings</title>
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f1;--ink:#1a2420;--mute:#6b7a72;--teal:#1f5d6b;--line:#e5dfd3;}
*{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;background:var(--bg);color:var(--ink);font-family:-apple-system,system-ui,"DM Sans",sans-serif;padding:20px;padding-top:max(20px,calc(env(safe-area-inset-top) + 14px));max-width:680px;margin:0 auto;}
.eyebrow{font-family:ui-monospace,Menlo,monospace;font-size:12px;letter-spacing:3px;color:var(--teal);text-transform:uppercase;}
h1{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:26px;margin:6px 0 18px;}
.card{background:#fff;border:1px solid var(--line);border-radius:16px;padding:16px;margin-bottom:16px;}
.card h2{font-family:"DM Serif Display",Georgia,serif;font-weight:400;font-size:20px;margin:0 0 10px;}
.shared{font-size:14px;line-height:1.6;color:var(--ink);}
.shared b{color:var(--teal);}
textarea,input.field{width:100%;border:1px solid var(--line);border-radius:12px;padding:12px;font:14px/1.5 -apple-system,system-ui,sans-serif;color:var(--ink);background:#fcfaf6;resize:vertical;}
textarea.desc{min-height:120px;}
img.preview{width:100%;border-radius:12px;border:1px solid var(--line);display:block;background:#f3eee6;}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;border:none;border-radius:12px;padding:13px;font-size:15px;font-weight:600;cursor:pointer;margin-top:10px;background:var(--teal);color:#fff;text-decoration:none;}
.btn.alt{background:#fff;color:var(--teal);border:1.5px solid var(--teal);}
.btn:active{opacity:.8;}
.btn svg{width:18px;height:18px;stroke:currentColor;fill:none;stroke-width:2;}
.row{display:flex;gap:10px;}.row .btn{margin-top:10px;}
.fldlbl{font-family:ui-monospace,Menlo,monospace;font-size:11px;letter-spacing:2px;color:var(--mute);text-transform:uppercase;margin:14px 0 6px;}
.skuline{display:flex;align-items:center;gap:8px;font-family:ui-monospace,Menlo,monospace;font-size:12px;color:var(--mute);margin:0 0 12px;}
.skuline code{background:#f3eee6;border:1px solid var(--line);border-radius:6px;padding:3px 8px;color:var(--ink);font-size:13px;letter-spacing:1px;}
.sku-copy{border:1px solid var(--teal);background:#fff;color:var(--teal);border-radius:6px;padding:3px 10px;font-size:11px;font-weight:600;cursor:pointer;font-family:inherit;}
.gallery{display:flex;gap:10px;flex-wrap:wrap;}
.gitem{flex:1 1 calc(50% - 5px);min-width:150px;}
.gitem img.preview{margin:0;}
.glabel{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--mute);text-align:center;margin:6px 0 4px;}
.grow{display:flex;gap:6px;}
.btn.mini{margin-top:0;padding:9px;font-size:13px;}
.toast{position:fixed;left:50%;bottom:28px;transform:translateX(-50%) translateY(20px);background:#2d2d2d;color:#fff;padding:12px 20px;border-radius:999px;font-size:14px;opacity:0;transition:.25s;pointer-events:none;z-index:9;}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0);}
</style></head><body>
""" + NAV_LIGHT + """
<div class="eyebrow">Harbor stickers</div>
<h1>Etsy listings</h1>

<div class="card shared">
  <h2>Every listing, same settings</h2>
  <b>Price:</b> $4.50 single, $18 pack &middot; <b>Qty:</b> your batch count<br>
  <b>Who made it:</b> I did &middot; <b>What:</b> A finished product &middot; <b>When:</b> 2020-2026, made to order<br>
  <b>Category:</b> Stickers &amp; Labels &gt; Stickers &middot; <b>Type:</b> Physical &middot; <b>Renewal:</b> Automatic<br>
  <b>Materials:</b> Vinyl, Laminate &middot; <b>Personalization:</b> off &middot; <b>SKU:</b> HARBOR-&lt;slug&gt;<br>
  <b>Production partner:</b> add Sticker Mule once in Settings &gt; Production partners, tick it on each listing<br>
  <b>Photos:</b> image 1 = that design's mockup, image 2 = the pack mockup, image 3 later = real phone photo<br>
  <b>Tags:</b> add one at a time (13 max, 20 chars, letters/numbers/spaces only) &middot; the comma list below is just the separator, do not paste commas into a tag<br>
  <b>Weight:</b> enter 1 oz (sticker is ~3 g; round up) &middot; <b>Pkg singles:</b> 6&times;4&times;0.1 in flat envelope, one stamp<br>
  <b>Pkg pack:</b> 7&times;5&times;0.25 in &middot; never a thick rigid mailer on singles (nonmachinable surcharge)<br>
  <b>Shipping:</b> two flat-rate profiles, free shipping &middot; <b>Processing:</b> 3-5 business days &middot; <b>Origin:</b> 02359<br>
  <b>Returns:</b> no returns/exchanges (made to order) &middot; cancellations ok within 2h &middot; replace damaged/lost by message
</div>

{% if shared.has_specs %}
<div class="card">
  <div class="fldlbl">Specs tile &mdash; add to any listing's photos</div>
  <img class="preview" id="img-specs" src="/etsy/img/etsy-specs" data-name="etsy-specs.jpg" alt="">
  <div class="row">
    <button class="btn alt" onclick="copyImgEl('img-specs')">
      <svg viewBox="0 0 24 24"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><path d="M21 15l-5-5L5 21"/></svg>
      Copy image
    </button>
    <button class="btn" onclick="dlImgEl('img-specs')">
      <svg viewBox="0 0 24 24"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
      Save image
    </button>
  </div>
</div>
{% endif %}

{% for l in listings %}
<div class="card">
  <h2>{{ l.name }}</h2>
  {% if l.sku %}
  <div class="skuline">SKU <code>{{ l.sku }}</code>
    <button class="sku-copy" onclick="copySku('{{ l.sku }}')">copy</button>
  </div>
  {% endif %}
  {% if l.imgs %}
  <div class="gallery">
    {% for im in l.imgs %}
    <div class="gitem">
      <img class="preview" id="img-{{ l.slug }}-{{ loop.index }}" src="{{ im.src }}" data-name="{{ im.name }}" loading="lazy" alt="{{ im.label }}">
      <div class="glabel">{{ im.label }}</div>
      <div class="grow">
        <button class="btn alt mini" onclick="copyImgEl('img-{{ l.slug }}-{{ loop.index }}')">Copy</button>
        <button class="btn mini" onclick="dlImgEl('img-{{ l.slug }}-{{ loop.index }}')">Save</button>
      </div>
    </div>
    {% endfor %}
  </div>
  {% endif %}
  {% if l.has_print %}
  <button class="btn alt" onclick="dlPrint('{{ l.slug }}')">
    <svg viewBox="0 0 24 24"><path d="M6 9V2h12v7"/><path d="M6 18H4a2 2 0 0 1-2-2v-5a2 2 0 0 1 2-2h16a2 2 0 0 1 2 2v5a2 2 0 0 1-2 2h-2"/><rect x="6" y="14" width="12" height="8"/></svg>
    Save print file (Sticker Mule upload)
  </button>
  {% endif %}

  <div class="fldlbl">Title</div>
  <textarea id="t-{{ l.slug }}" rows="3" readonly>{{ l.title }}</textarea>
  <button class="btn alt" onclick="copyVal('t-{{ l.slug }}','Title copied')">
    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    Copy title
  </button>

  <div class="fldlbl">Tags</div>
  <textarea id="g-{{ l.slug }}" rows="3" readonly>{{ l.tags }}</textarea>
  <button class="btn alt" onclick="copyVal('g-{{ l.slug }}','Tags copied')">
    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    Copy tags
  </button>

  <div class="fldlbl">Description</div>
  <textarea class="desc" id="d-{{ l.slug }}" readonly>{{ l.desc }}

{{ footer }}</textarea>
  <button class="btn" onclick="copyVal('d-{{ l.slug }}','Description copied')">
    <svg viewBox="0 0 24 24"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
    Copy description
  </button>
</div>
{% endfor %}

<a class="btn alt" href="https://www.etsy.com/your/shops/me/tools/listings" target="_blank" rel="noopener">
  <svg viewBox="0 0 24 24"><path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6"/><path d="M15 3h6v6"/><path d="M10 14L21 3"/></svg>
  Open Etsy listing manager
</a>

<div class="toast" id="toast"></div>
<script>
function toast(m){var t=document.getElementById('toast');t.textContent=m;t.classList.add('show');setTimeout(function(){t.classList.remove('show');},1600);}
function copyVal(id,msg){var b=document.getElementById(id);b.select();navigator.clipboard.writeText(b.value).then(function(){toast(msg);},function(){document.execCommand('copy');toast(msg);});}
function copySku(s){navigator.clipboard.writeText(s).then(function(){toast('SKU copied');},function(){toast('SKU copied');});}
(function(){
  // Preload previews into per-element blob/File so Save can use
  // navigator.share within the click gesture (clean "Save Image" on iOS).
  document.querySelectorAll('img.preview').forEach(function(el){
    fetch(el.src).then(function(r){return r.blob();}).then(function(b){
      el._blob=b; el._file=new File([b], el.dataset.name||'harbor-sticker.jpg', {type:b.type||'image/jpeg'});
    }).catch(function(){});
  });
})();
async function copyImgEl(id){try{var el=document.getElementById(id);var bl=el._blob||await (await fetch(el.src)).blob();await navigator.clipboard.write([new ClipboardItem({[bl.type]:bl})]);toast('Image copied');}catch(e){toast('Long-press the image to copy');}}
async function dlImgEl(id){var el=document.getElementById(id);var name=el.dataset.name||'harbor-sticker.jpg';
  try{
    if(el._file && navigator.canShare && navigator.canShare({files:[el._file]})){await navigator.share({files:[el._file]});return;}
    var bl=el._blob||await (await fetch(el.src)).blob();
    var u=URL.createObjectURL(bl);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);toast('Saved');
  }catch(e){if(e&&e.name==='AbortError')return;window.open(el.src,'_blank');}}
async function dlPrint(slug){var name=slug+'-300dpi.png';
  try{
    var bl=await (await fetch('/etsy/img/'+slug+'?print=1')).blob();
    var f=new File([bl],name,{type:bl.type||'image/png'});
    if(navigator.canShare && navigator.canShare({files:[f]})){await navigator.share({files:[f]});return;}
    var u=URL.createObjectURL(bl);var a=document.createElement('a');a.href=u;a.download=name;document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(u);toast('Saved');
  }catch(e){if(e&&e.name==='AbortError')return;toast('Could not fetch print file');}}
</script></body></html>"""


@app.route("/etsy")
@admin_required
def etsy_page():
    listings, footer, shared = _etsy_listings()
    resp = make_response(render_template_string(ETSY_PAGE_HTML, listings=listings,
                                                footer=footer, shared=shared))
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/etsy/img/<slug>")
@admin_required
def etsy_img(slug):
    import re as _re, os as _os
    from flask import send_file
    if not _re.fullmatch(r"[a-z0-9-]+", slug):
        return "not found", 404
    variant = request.args.get("variant", "")
    if request.args.get("print"):
        path, mt = _os.path.join(ETSY_STICKER_DIR, slug + "@300dpi.png"), "image/png"
    elif variant in ("scale", "laptop"):
        path, mt = _os.path.join(ETSY_MOCKUP_DIR, slug + "-" + variant + ".jpg"), "image/jpeg"
    elif slug in ("etsy-specs", "the-whole-harbor-grid"):
        path, mt = _os.path.join(ETSY_MOCKUP_DIR, slug + ".jpg"), "image/jpeg"
    else:
        path, mt = _os.path.join(ETSY_MOCKUP_DIR, slug + "-mockup.jpg"), "image/jpeg"
    if not _os.path.exists(path):
        return "not found", 404
    return send_file(path, mimetype=mt)


# harbor-help SSO + alias routes (loaded from snippet file so dashboard.py
# stays slim; routes register at import time via decorators inside the snippet).
__HARBOR_HELP_SNIPPET = "/home/ubuntu/harbor-backend/snippets/account_emails_routes.py"
with open(__HARBOR_HELP_SNIPPET) as __f:
    exec(compile(__f.read(), __HARBOR_HELP_SNIPPET, "exec"))

# Public linktree page for link.harborprivacy.com (nginx proxies to /__link)
_LINK_PAGE_TMPL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Harbor Privacy — All Links</title>
<meta name="description" content="All Harbor Privacy products and tools in one place.">
<meta name="theme-color" content="#1f5d6b">
<link href="https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@400;500;600&display=swap" rel="stylesheet">
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>
:root{--bg:#fbf7f0;--surface:#ffffff;--border:#e6dfd2;--text:#1a2420;--muted:#6b7a72;--soft:#a6b1a8;--accent:#1f5d6b;--accent-soft:rgba(31,93,107,0.10);}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:"DM Sans",sans-serif;min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased;padding:48px 20px}
body::before{content:"";position:fixed;inset:0;background-image:linear-gradient(var(--border) 1px,transparent 1px),linear-gradient(90deg,var(--border) 1px,transparent 1px);background-size:60px 60px;opacity:0.18;pointer-events:none;z-index:0}
.wrap{position:relative;z-index:1;max-width:520px;margin:0 auto}
.head{text-align:center;margin-bottom:36px}
.logo{display:block;width:112px;height:112px;margin:0 auto 18px;border-radius:24px;box-shadow:0 8px 32px rgba(31,93,107,0.12)}
.brand{font-family:"DM Mono",monospace;font-size:13px;color:var(--accent);letter-spacing:0.18em;text-transform:uppercase;margin-bottom:14px}
h1{font-size:28px;font-weight:600;color:var(--text);margin-bottom:10px;letter-spacing:-0.01em}
.sub{font-size:15px;color:var(--muted)}
.links{display:flex;flex-direction:column;gap:10px}
.link{display:flex;align-items:center;gap:14px;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:16px 18px;text-decoration:none;color:var(--text);transition:border-color .15s,transform .15s,box-shadow .15s}
.link:hover{border-color:var(--accent);transform:translateY(-1px);box-shadow:0 6px 24px rgba(31,93,107,0.08)}
.link.feat{border-color:var(--accent);background:var(--accent-soft)}
.icon{width:44px;height:44px;flex-shrink:0;border-radius:10px;overflow:hidden;background:#fbf7f1;border:1px solid var(--border)}
.icon img{display:block;width:100%;height:100%}
.body{flex:1;min-width:0}
.name{display:block;font-weight:600;font-size:15px;color:var(--text);margin-bottom:3px}
.desc{display:block;font-size:13px;color:var(--muted);line-height:1.4}
.arrow{color:var(--soft);font-size:18px;flex-shrink:0}
.foot{text-align:center;margin-top:36px;font-family:"DM Mono",monospace;font-size:11px;color:var(--soft);letter-spacing:0.18em;text-transform:uppercase}
.foot a{color:var(--muted);text-decoration:none}
.foot a:hover{color:var(--accent)}
.empty{text-align:center;padding:40px;color:var(--muted);font-family:"DM Mono",monospace;font-size:13px}
</style>
</head>
<body>
<div class="wrap">
  <div class="head">
    <img class="logo" src="/icons/logo.svg" alt="Harbor Privacy">
    <div class="brand">Harbor Privacy</div>
    <h1>All Links</h1>
    <div class="sub">Privacy-first tools for home, business, and career.</div>
  </div>
  <div class="links">
    {% for l in links %}
      <a class="link {% if l.featured %}feat{% endif %}" href="{{ l.url }}" data-pill="{{ l.label }}">
        <span class="icon">{% if l.icon %}<img src="/icons/{{ l.icon }}.svg" alt="" loading="lazy">{% endif %}</span>
        <span class="body"><span class="name">{{ l.label }}</span>{% if l.desc %}<span class="desc">{{ l.desc }}</span>{% endif %}</span>
        <span class="arrow">→</span>
      </a>
    {% else %}
      <div class="empty">No links configured yet.</div>
    {% endfor %}
  </div>
  <div class="foot"><a href="https://harborprivacy.com">harborprivacy.com</a></div>
</div>
</body>
</html>"""

@app.route("/__link", strict_slashes=False)
@app.route("/__link/")
def public_link_page():
    import json as _json
    try:
        links = _json.loads(open("/var/www/link/links.json").read())
    except Exception:
        links = []
    resp = make_response(render_template_string(_LINK_PAGE_TMPL, links=links))
    resp.headers["Cache-Control"] = "public, max-age=60"
    return resp

if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("DASHBOARD_PORT", 7000)), debug=False)
