"""
harbor_lib.config — centralized env vars + file paths.
Imported by dashboard.py and other harbor_lib modules.
Do not put logic here, only constants.
"""
import os

# ── Secrets ────────────────────────────────────────────────
FLASK_SECRET       = os.environ["FLASK_SECRET"]
SECRET_KEY         = os.environ["DASHBOARD_SECRET"]
TURNSTILE_SECRET   = os.environ.get("TURNSTILE_SECRET_KEY", "")
AUTOPOST_SECRET    = os.environ.get("AUTOPOST_SECRET", "")
HOME_STATUS_TOKEN  = os.environ.get("HOME_STATUS_TOKEN", "")

# ── AdGuard ────────────────────────────────────────────────
ADGUARD_URL        = os.environ.get("ADGUARD_URL", "http://127.0.0.1:8080")
ADGUARD_USER       = os.environ.get("ADGUARD_USER", "admin")
ADGUARD_PASS       = os.environ.get("ADGUARD_PASS", "")
AGH_TIMEOUT        = float(os.environ.get("AGH_TIMEOUT", "4"))

# ── Email (Resend) ─────────────────────────────────────────
RESEND_API_KEY     = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL         = os.environ.get("FROM_EMAIL", "info@harborprivacy.app")
ADMIN_EMAIL        = "admin@harborprivacy.com"

# ── File paths ─────────────────────────────────────────────
CUSTOMERS_LOG       = os.environ.get("CUSTOMERS_LOG", "/var/log/harbor-customers.json")
USERS_DB            = os.environ.get("USERS_DB", "/var/log/harbor-dashboard-users.json")
HOME_STATUS_FILE    = "/home/ubuntu/harbor-home-status.json"
SIGNUP_STATS_FILE   = "/home/ubuntu/harbor-backend/signup-stats.json"
AGH_SNAPSHOT_FILE   = "/home/ubuntu/harbor-backend/agh-snapshot.json"
EMAIL_FAILURES_FILE = "/home/ubuntu/harbor-backend/email-failures.json"
DISPOSABLE_DOMAINS_FILE = "/home/ubuntu/harbor-backend/disposable-domains.txt"
