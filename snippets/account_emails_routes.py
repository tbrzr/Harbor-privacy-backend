# =============================================================================
# APPEND-ONLY: paste at the END of dashboard.py
# Do NOT touch the harbor_kids / plan_type blocks near lines 920 / 1747.
# Adds:
#   GET  /api/whoami            (for harbor-help SSO; JSON, no redirect on auth fail)
#   POST /api/customer_lookup   (internal, gated by X-Internal-Key)
#   GET  /account/emails        (alias UI)
#   POST /account/emails/add
#   GET  /account/emails/verify/<token>
#   POST /account/emails/remove
#
# Depends on existing dashboard.py items: app, request, redirect, jsonify,
# render_template_string, login_required, verify_token, send_email, ADMIN_EMAIL.
# Depends on harbor_lib.data: find_customer, find_customer_by_any_email,
# find_customer_by_client_id, list_aliases, add_pending_alias, verify_alias,
# remove_alias, email_in_use_elsewhere.
# =============================================================================
from itsdangerous import URLSafeTimedSerializer as _URLSafeSer
from itsdangerous import BadSignature as _BadSig, SignatureExpired as _SigExp
from hashlib import sha256 as _sha256
import os as _os
import secrets as _secrets
from harbor_lib.data import (
    find_customer as _find_customer,
    find_customer_by_any_email as _find_by_any,
    find_customer_by_client_id as _find_by_cid,
    list_aliases as _list_aliases,
    add_pending_alias as _add_pending,
    verify_alias as _verify_alias,
    remove_alias as _remove_alias,
    email_in_use_elsewhere as _email_in_use,
)

# No hardcoded fallback: the literal was committed to the repo, so anyone with
# repo access could call /api/customer_lookup. Require the env var; fail closed
# (reject all) if it's unset rather than fall back to a guessable key.
_HELP_INTERNAL_KEY = _os.environ.get("HELP_INTERNAL_API_KEY", "")
_EMAIL_VERIFY_SECRET = _os.environ.get(
    "EMAIL_VERIFY_SECRET", app.config.get("SECRET_KEY") or "harbor-email-verify-fallback"
)
_EMAIL_SIGNER = _URLSafeSer(_EMAIL_VERIFY_SECRET, salt="customer-email-verify")


def _whoami_payload():
    raw = request.headers.get("Cookie", "")
    tokens = []
    for part in raw.split(";"):
        part = part.strip()
        if part.startswith("hp_token="):
            tokens.append(part[len("hp_token="):])
    for t in tokens:
        p = verify_token(t)
        if p:
            return p
    return None


@app.get("/api/whoami")
def api_whoami():
    p = _whoami_payload()
    if not p:
        return jsonify({}), 401
    email = (p.get("email") or "").lower()
    cust = _find_customer(email) or {}
    return jsonify({
        "email": email,
        "customer_id": cust.get("client_id"),
        "client_id": cust.get("client_id"),
        "plan": cust.get("plan_type"),
        "is_admin": bool(p.get("admin")) or email == ADMIN_EMAIL,
    })


@app.post("/api/customer_lookup")
def api_customer_lookup():
    sent = request.headers.get("X-Internal-Key", "")
    if not _HELP_INTERNAL_KEY or not _secrets.compare_digest(sent, _HELP_INTERNAL_KEY):
        return jsonify({}), 403
    body = request.get_json(silent=True) or {}
    email = (body.get("email") or "").strip().lower()
    if not email:
        return jsonify({})
    c = _find_by_any(email)
    if not c:
        return jsonify({})
    return jsonify({
        "customer_id": c.get("client_id"),
        "client_id": c.get("client_id"),
        "plan": c.get("plan_type"),
    })


_ACCOUNT_EMAILS_HTML = """<!doctype html>
<html><head><meta charset="utf-8">
<title>Email aliases — Harbor Privacy</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<script defer src="https://cloud.umami.is/script.js" data-website-id="2d16b46c-899b-444b-9767-0e2d21feedf9"></script>
<style>body{font-family:system-ui,sans-serif;max-width:760px;margin:1.5rem auto;padding:0 1rem}
table{border-collapse:collapse;width:100%}th,td{border:1px solid #ddd;padding:.4rem .6rem;text-align:left}
.flash{background:#f5f5dc;padding:.5rem .8rem;border-left:3px solid #c90;margin:.5rem 0}
.muted{color:#666;font-size:.9rem}</style>
</head><body>
<p><a href="/dashboard">&larr; Dashboard</a></p>
<h1>Email aliases</h1>
<p>Tickets you submit on <a href="https://help.harborprivacy.com">help.harborprivacy.com</a>
from any verified email below are auto-linked to your Harbor account, even when you are
signed out or in a private window. Useful for Apple Hide My Email, SimpleLogin, addy.io,
or a separate work email.</p>
{% if flash %}<div class="flash">{{ flash }}</div>{% endif %}
<h2>Primary email</h2>
<p><strong>{{ primary_email }}</strong> <span class="muted">(cannot be changed here)</span></p>
<h2>Alternate emails</h2>
<table>
<tr><th>Email</th><th>Status</th><th>Added</th><th></th></tr>
{% for a in aliases %}
<tr>
<td>{{ a.email }}</td>
<td>{{ "verified" if a.verified else "pending verification" }}</td>
<td>{{ (a.added_at or "")[:10] }}</td>
<td>
  <form method="post" action="/account/emails/remove" style="display:inline">
    <input type="hidden" name="email" value="{{ a.email }}">
    <button type="submit" onclick="return confirm('Remove this alias?')">Remove</button>
  </form>
</td>
</tr>
{% else %}
<tr><td colspan="4" class="muted">No alternate emails added yet.</td></tr>
{% endfor %}
</table>
<h2>Add an alternate email</h2>
<form method="post" action="/account/emails/add">
  <input type="email" name="email" required placeholder="alias@example.com" size="40">
  <button type="submit">Send verification</button>
</form>
<p class="muted">We will email a confirmation link to that address. The alias is
not active until you click the link.</p>
</body></html>
"""


@app.get("/account/emails")
@login_required
def account_emails():
    email = request.user_email.lower()
    cust = _find_customer(email)
    if not cust:
        return redirect("/dashboard")
    flash = request.args.get("m") or ""
    return render_template_string(
        _ACCOUNT_EMAILS_HTML,
        primary_email=email,
        aliases=_list_aliases(cust["client_id"]),
        flash=flash,
    )


@app.post("/account/emails/add")
@login_required
def account_emails_add():
    email = request.user_email.lower()
    cust = _find_customer(email)
    if not cust:
        return redirect("/dashboard")
    new_email = (request.form.get("email") or "").strip().lower()
    if "@" not in new_email or len(new_email) > 254:
        return redirect("/account/emails?m=Enter+a+valid+email+address.")
    if new_email == email:
        return redirect("/account/emails?m=That+is+already+your+primary+email.")
    if _email_in_use(new_email, cust["client_id"]):
        return redirect("/account/emails?m=That+email+is+already+in+use+on+another+Harbor+account.")

    token = _EMAIL_SIGNER.dumps({"cid": cust["client_id"], "email": new_email})
    token_hash = _sha256(token.encode()).hexdigest()
    _add_pending(cust["client_id"], new_email, token_hash)

    verify_url = f"https://dashboard.harborprivacy.com/account/emails/verify/{token}"
    html = (
        "<p>Confirm this email as an alias on your Harbor Privacy account:</p>"
        f"<p><a href=\"{verify_url}\">{verify_url}</a></p>"
        "<p>Once verified, support tickets you submit from this address will be "
        "auto-linked to your account.</p>"
        "<p>If you did not request this, ignore the message.</p>"
    )
    send_email(new_email, "Confirm your Harbor email alias", html)
    return redirect("/account/emails?m=Verification+email+sent+to+" + new_email)


@app.get("/account/emails/verify/<token>")
def account_emails_verify(token):
    try:
        payload = _EMAIL_SIGNER.loads(token, max_age=60 * 60 * 24 * 7)
    except (_BadSig, _SigExp):
        return ("Link expired or invalid. Sign in and request a new verification "
                "email.", 400)
    cid = payload["cid"]
    email = (payload["email"] or "").lower()
    token_hash = _sha256(token.encode()).hexdigest()
    ok = _verify_alias(cid, email, token_hash)
    if not ok:
        return ("Could not verify this alias. It may have been removed or "
                "already confirmed.", 404)
    return redirect("/account/emails?m=" + email + "+is+now+confirmed.")


@app.post("/account/emails/remove")
@login_required
def account_emails_remove():
    email = request.user_email.lower()
    cust = _find_customer(email)
    if not cust:
        return redirect("/dashboard")
    target = (request.form.get("email") or "").strip().lower()
    if not target:
        return redirect("/account/emails?m=Missing+email.")
    _remove_alias(cust["client_id"], target)
    return redirect("/account/emails?m=Removed+" + target)
