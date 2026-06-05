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


# -----------------------------------------------------------------------------
# Email aliases: per-customer verified alternate addresses for ticket linking.
# Stored on each customer record as `aliases: [{email, verified, added_at,
# verified_at, verify_token_hash}, ...]`. Lookups in find_customer_by_any_email
# check primary email plus every verified alias.
# -----------------------------------------------------------------------------
from datetime import datetime as _dt


def _iter_all_lines():
    try:
        with open(CUSTOMERS_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    yield line
    except Exception:
        return


def _rewrite_customer(client_id, mutator):
    """Rewrite CUSTOMERS_LOG, applying mutator(record_dict) to the matching
    customer in place. mutator returns True to indicate the change happened."""
    lines = []
    hit = False
    for raw in _iter_all_lines():
        try:
            c = json.loads(raw)
        except Exception:
            lines.append(raw)
            continue
        if c.get("client_id") == client_id and not hit:
            if mutator(c):
                hit = True
        lines.append(json.dumps(c))
    if hit:
        try:
            with open(CUSTOMERS_LOG, "w") as f:
                f.write("\n".join(lines) + "\n")
        except Exception as e:
            log.error("alias rewrite error: " + str(e))
            return False
    return hit


def find_customer_by_client_id(client_id):
    for raw in _iter_all_lines():
        try:
            c = json.loads(raw)
        except Exception:
            continue
        if c.get("client_id") == client_id and c.get("status") == "active":
            return c
    return None


def find_customer_by_any_email(email):
    """Match primary email OR any verified alias."""
    needle = (email or "").lower()
    if not needle:
        return None
    for raw in _iter_all_lines():
        try:
            c = json.loads(raw)
        except Exception:
            continue
        if c.get("status") != "active":
            continue
        if c.get("email", "").lower() == needle:
            return c
        for a in c.get("aliases", []) or []:
            if a.get("verified") and a.get("email", "").lower() == needle:
                return c
    return None


def list_aliases(client_id):
    c = find_customer_by_client_id(client_id)
    return list(c.get("aliases", []) or []) if c else []


def add_pending_alias(client_id, email, token_hash):
    email = (email or "").lower()

    def mut(c):
        c.setdefault("aliases", [])
        for a in c["aliases"]:
            if a.get("email", "").lower() == email:
                a["verify_token_hash"] = token_hash
                a["verified"] = False
                a["added_at"] = _dt.utcnow().isoformat() + "Z"
                return True
        c["aliases"].append({
            "email": email,
            "verified": False,
            "added_at": _dt.utcnow().isoformat() + "Z",
            "verified_at": None,
            "verify_token_hash": token_hash,
        })
        return True

    return _rewrite_customer(client_id, mut)


def verify_alias(client_id, email, token_hash):
    email = (email or "").lower()

    def mut(c):
        for a in c.get("aliases", []) or []:
            if (a.get("email", "").lower() == email
                    and a.get("verify_token_hash") == token_hash):
                a["verified"] = True
                a["verified_at"] = _dt.utcnow().isoformat() + "Z"
                a["verify_token_hash"] = None
                return True
        return False

    return _rewrite_customer(client_id, mut)


def remove_alias(client_id, email):
    email = (email or "").lower()

    def mut(c):
        before = c.get("aliases", []) or []
        after = [a for a in before
                 if a.get("email", "").lower() != email]
        if len(after) != len(before):
            c["aliases"] = after
            return True
        return False

    return _rewrite_customer(client_id, mut)


def email_in_use_elsewhere(email, by_client_id):
    """True if `email` is the primary or verified alias of any active customer
    other than `by_client_id`."""
    needle = (email or "").lower()
    for raw in _iter_all_lines():
        try:
            c = json.loads(raw)
        except Exception:
            continue
        if c.get("status") != "active":
            continue
        if c.get("client_id") == by_client_id:
            continue
        if c.get("email", "").lower() == needle:
            return True
        for a in c.get("aliases", []) or []:
            if a.get("verified") and a.get("email", "").lower() == needle:
                return True
    return False
