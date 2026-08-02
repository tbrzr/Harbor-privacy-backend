"""
harbor_lib.auth — JWT token make/verify helpers.

Note: @login_required / @admin_required decorators stay in dashboard.py
because they import Flask's `request` and use redirects.
"""
from datetime import datetime, timedelta
import secrets
import jwt
from .config import SECRET_KEY


def make_sso_token(email, is_admin=False):
    # Short-lived, single-purpose bootstrap token for the cross-service SSO
    # handoff (/sso, /vpn-sso) -- deliberately NOT a real session token.
    # This value travels in a URL query string, which nginx logs verbatim
    # ($request in the "harbor" log_format) on every request, so it stays
    # valid for minutes, not the 8h/30d a real hp_token session lives for.
    # jti + purpose let the receiving side reject reuse and reject a leaked
    # ordinary hp_token being replayed here.
    return jwt.encode(
        {
            "email": email,
            "admin": is_admin,
            "purpose": "sso",
            "jti": secrets.token_hex(16),
            "exp": datetime.utcnow() + timedelta(minutes=2),
        },
        SECRET_KEY,
        algorithm="HS256",
    )


def verify_sso_token(token):
    payload = verify_token(token)
    if not payload or payload.get("purpose") != "sso" or not payload.get("jti"):
        return None
    return payload


def make_token(email, is_admin=False):
    # Admin tokens live 30 days so the Social/Leads PWAs are not asking for
    # a login every workday; customer tokens stay short-lived.
    ttl = timedelta(days=30) if is_admin else timedelta(hours=8)
    return jwt.encode(
        {
            "email": email,
            "admin": is_admin,
            "exp": datetime.utcnow() + ttl,
        },
        SECRET_KEY,
        algorithm="HS256",
    )


def verify_token(token):
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except Exception:
        return None
