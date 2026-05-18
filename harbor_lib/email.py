"""
harbor_lib.email — Resend API wrapper + failure log.
Used by dashboard.py. webhook.py has its own copy with EMAIL_FOOTER.
"""
import json, logging, requests, sys
from datetime import datetime
from .config import RESEND_API_KEY, FROM_EMAIL, EMAIL_FAILURES_FILE

sys.path.insert(0, "/home/ubuntu/harbor-shared")
from email_brand import wrap, BRAND_PRIVACY  # noqa: E402

log = logging.getLogger(__name__)


def record_email_failure(to, subject, error):
    try:
        try:
            with open(EMAIL_FAILURES_FILE) as f:
                fails = json.load(f)
        except Exception:
            fails = []
        fails.append({
            "ts": datetime.utcnow().isoformat() + "Z",
            "to": to, "subject": subject, "error": str(error)[:500],
        })
        fails = fails[-200:]
        with open(EMAIL_FAILURES_FILE, "w") as f:
            json.dump(fails, f)
    except Exception as e:
        log.error(f"email failure log write error: {e}")


def send_email(to, subject, html):
    if not RESEND_API_KEY:
        log.error(f"send_email skipped (no RESEND_API_KEY): to={to} subject={subject!r}")
        record_email_failure(to, subject, "RESEND_API_KEY not set")
        return False
    try:
        full_html = wrap(html, brand=BRAND_PRIVACY) if "<!DOCTYPE" not in (html or "")[:50] else html
        r = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
            json={"from": f"Harbor Privacy <{FROM_EMAIL}>", "to": [to], "subject": subject,
                  "html": full_html, "reply_to": "support@harborprivacy.com"},
            timeout=10,
        )
        if r.status_code >= 400:
            log.error(f"send_email Resend {r.status_code}: to={to} subject={subject!r} body={r.text[:300]}")
            record_email_failure(to, subject, f"Resend {r.status_code}: {r.text[:300]}")
            return False
        return True
    except Exception as e:
        log.error(f"send_email exception: to={to} subject={subject!r} err={e}")
        record_email_failure(to, subject, e)
        return False
