"""
Shared admin auth for the single-file Flask apps (fax, career).

Usage:
    from admin_common import init_admin_auth, admin_required, csrf_token, audit_log

    secret_key, decorator = init_admin_auth(app, audit_path="/var/log/fax-admin-audit.log")

Auth model:
    Env vars:
        ADMIN_PASSWORD_HASH   werkzeug hash of the admin password
        ADMIN_SESSION_SECRET  Flask secret key (random)
        TURNSTILE_SITE_KEY    optional, shown on login if set
        TURNSTILE_SECRET_KEY  optional, verified server-side if set
        ADMIN_RATE_MAX        default 5
        ADMIN_RATE_WINDOW_S   default 900
"""
import json
import os
import secrets as _secrets
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlencode

import requests
from flask import (current_app, jsonify, redirect, render_template, request,
                   session, url_for)
from werkzeug.security import check_password_hash

_RATE = {}


def _ip():
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def _audit_file_default(app_name):
    return f"/var/log/{app_name}-admin-audit.log"


def audit_log(path, actor, action, target_type=None, target_id=None, payload=None):
    rec = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "actor": actor or "?",
        "ip": _ip(),
        "action": action,
        "target_type": target_type,
        "target_id": str(target_id) if target_id is not None else None,
        "payload": payload,
    }
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(rec) + "\n")
    except Exception:
        pass


def read_audit(path, limit=200):
    p = Path(path)
    if not p.exists():
        return []
    try:
        lines = p.read_text().splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
        out.reverse()
        return out
    except Exception:
        return []


def _verify_turnstile(token):
    secret = os.environ.get("TURNSTILE_SECRET_KEY")
    if not secret:
        return True
    if not token:
        return False
    try:
        r = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify",
            data={"secret": secret, "response": token, "remoteip": _ip()},
            timeout=5,
        )
        return r.ok and r.json().get("success") is True
    except Exception:
        return False


def _rate_ok(key, cap, window):
    now = time.time()
    bucket = _RATE.setdefault(key, [])
    bucket[:] = [t for t in bucket if now - t < window]
    return len(bucket) < cap


def _rate_hit(key):
    _RATE.setdefault(key, []).append(time.time())


def csrf_token():
    tok = session.get("_csrf")
    if not tok:
        tok = _secrets.token_urlsafe(32)
        session["_csrf"] = tok
    return tok


def _csrf_check():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return True
    sent = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token") or ""
    return bool(sent) and secrets_compare(sent, session.get("_csrf") or "")


def secrets_compare(a, b):
    return _secrets.compare_digest(str(a), str(b))


def init_admin_auth(app, app_name, login_route="/admin/login",
                    after_login_route="/admin"):
    """Attach admin auth to `app`. Returns the audit log path used."""
    secret = os.environ.get("ADMIN_SESSION_SECRET")
    if not secret:
        # Fallback to ephemeral key — sessions will reset on restart.
        secret = _secrets.token_urlsafe(48)
    app.secret_key = secret
    app.config["ADMIN_AUDIT_PATH"] = _audit_file_default(app_name)
    app.config["ADMIN_APP_NAME"] = app_name

    @app.before_request
    def _csrf_protect():
        # Only enforce CSRF on /admin/* mutating requests.
        if request.path.startswith("/admin") and request.method not in ("GET", "HEAD", "OPTIONS"):
            # Login endpoint is allowed without prior CSRF; we still re-check via session token if present.
            if request.path == login_route:
                return None
            if not _csrf_check():
                return jsonify({"error": "csrf"}), 400

    @app.context_processor
    def _admin_ctx():
        return {
            "csrf_token": csrf_token,
            "turnstile_site_key": os.environ.get("TURNSTILE_SITE_KEY", ""),
            "is_admin": bool(session.get("admin_authed")),
        }

    @app.route(login_route, methods=["GET", "POST"])
    def _admin_login():
        cap = int(os.environ.get("ADMIN_RATE_MAX", "5"))
        win = int(os.environ.get("ADMIN_RATE_WINDOW_S", "900"))
        rk = f"login:{_ip()}"
        err = None
        if request.method == "POST":
            if not _rate_ok(rk, cap, win):
                err = "Too many attempts. Wait 15 minutes."
            else:
                pw = (request.form.get("password") or "").strip()
                ts_token = request.form.get("cf-turnstile-response", "")
                pw_hash = os.environ.get("ADMIN_PASSWORD_HASH", "")
                if not pw_hash:
                    err = "Admin password not configured."
                elif not _verify_turnstile(ts_token):
                    err = "Turnstile check failed."
                elif not check_password_hash(pw_hash, pw):
                    _rate_hit(rk)
                    err = "Invalid password."
                else:
                    session.clear()
                    session["admin_authed"] = True
                    session["admin_email"] = os.environ.get("ADMIN_EMAIL", "admin@harborprivacy.com")
                    session.permanent = True
                    csrf_token()
                    audit_log(app.config["ADMIN_AUDIT_PATH"],
                              session["admin_email"], "login", "admin", None,
                              {"ok": True})
                    return redirect(after_login_route)
            if err and request.method == "POST":
                _rate_hit(rk)
        return render_template("admin_login.html",
                               err=err, app_name=app_name)

    @app.route("/admin/logout", methods=["POST"])
    def _admin_logout():
        if session.get("admin_authed"):
            audit_log(app.config["ADMIN_AUDIT_PATH"],
                      session.get("admin_email"), "logout", "admin")
        session.clear()
        return redirect(login_route)

    return app.config["ADMIN_AUDIT_PATH"]


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("admin_authed"):
            return redirect("/admin/login")
        return f(*a, **kw)
    return w
