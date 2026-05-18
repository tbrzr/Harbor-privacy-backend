"""
harbor_lib.data — users + customers JSON store helpers.
"""
import json, logging
from .config import USERS_DB, CUSTOMERS_LOG

log = logging.getLogger(__name__)


def load_users():
    try:
        with open(USERS_DB) as f:
            return json.load(f)
    except Exception:
        return {}


def save_users(users):
    with open(USERS_DB, "w") as f:
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
        log.error("save_customers error: " + str(e))
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
                except Exception:
                    pass
    except Exception:
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
                except Exception:
                    lines.append(line)
        if updated:
            with open(CUSTOMERS_LOG, "w") as f:
                f.write("\n".join(lines) + "\n")
        return updated
    except Exception:
        return False


def find_customer(email):
    for c in load_customers():
        if c.get("email", "").lower() == email.lower():
            return c
    return None


def has_family_addon(client_id):
    """Returns True if customer has Family Safe addon, based on customer log."""
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                try:
                    r = json.loads(line.strip())
                    if r.get("client_id") == client_id and r.get("family_safe") is True:
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    return False
