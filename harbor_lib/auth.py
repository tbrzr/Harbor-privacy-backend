"""
harbor_lib.auth — JWT token make/verify helpers.

Note: @login_required / @admin_required decorators stay in dashboard.py
because they import Flask's `request` and use redirects.
"""
from datetime import datetime, timedelta
import jwt
from .config import SECRET_KEY


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
