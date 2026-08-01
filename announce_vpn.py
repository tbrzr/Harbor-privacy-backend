#!/usr/bin/env python3
# One-off announcement email for the Harbor VPN launch. Not wired to any
# cron -- run manually, once, then leave in place for reference/reuse.
import json, os, sys, requests

CUSTOMERS_LOG = "/var/log/harbor-customers.json"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
EXCLUDE = {"tim@harborprivacy.com", "admin@harborprivacy.com"}

SUBJECT = "New: Harbor VPN is here"

def load_customers():
    customers = []
    with open(CUSTOMERS_LOG) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except Exception:
                continue
            if r.get("status") == "active" and r.get("email") not in EXCLUDE:
                customers.append(r)
    return customers

def render_html(name):
    return f'''<div style="font-family:sans-serif;max-width:560px;margin:0 auto;color:#1a2420;">
<p style="font-family:monospace;font-size:11px;color:#4a7a5a;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:8px;">NEW FROM HARBOR PRIVACY</p>
<h1 style="font-family:Georgia,serif;font-weight:400;font-size:28px;margin:0 0 16px;">Harbor VPN is here.</h1>
<p>Hi {name},</p>
<p style="color:#3d4a45;line-height:1.6;">We just launched Harbor VPN &mdash; a privacy VPN built on the same philosophy as your current Harbor Privacy DNS protection: block threats at the network level, and never log what you do. It bundles three tunnel protocols and routes every connection's DNS through Harbor's own filtering resolver, so the ad and threat blocking you already rely on follows you wherever you connect.</p>

<div style="background:#f4eee2;border-left:3px solid #4a7a5a;padding:16px 24px;margin:24px 0;">
  <div style="font-family:monospace;font-size:10px;color:#4a7a5a;letter-spacing:0.15em;margin-bottom:10px;">WHAT YOU GET</div>
  <p style="margin:0 0 8px;color:#1a2420;">WireGuard, OpenVPN, and AmneziaWG &mdash; pick a protocol per device</p>
  <p style="margin:0 0 8px;color:#1a2420;">DNS-layer malware &amp; threat blocking on every tunnel, enforced so it can't be bypassed by switching DNS</p>
  <p style="margin:0 0 8px;color:#1a2420;">Up to 5 devices, 30 Mbps each, no connection or browsing logs</p>
  <p style="margin:0;color:#1a2420;">Masks your IP and hides your traffic from your ISP on public Wi-Fi and everywhere else</p>
</div>

<p style="color:#3d4a45;line-height:1.6;">As an existing Harbor Privacy customer, you can add it to your account for <strong>$4.99/mo or $49/yr</strong> &mdash; less than half the standalone price.</p>

<div style="text-align:center;margin:32px 0;">
  <a href="https://dashboard.harborprivacy.com/dashboard" style="display:inline-block;background:#4a7a5a;color:#ffffff;padding:12px 28px;text-decoration:none;font-family:monospace;font-size:13px;letter-spacing:0.05em;">Add Harbor VPN &rarr;</a>
</div>

<p style="color:#6b7a72;font-size:13px;">One honest note: Harbor VPN is built for private browsing, not for unblocking streaming services &mdash; we'd rather tell you that upfront than oversell it. Full details, setup guides, and pricing are at <a href="https://vpn.harborprivacy.com" style="color:#4a7a5a;">vpn.harborprivacy.com</a>.</p>

<p style="padding-top:24px;border-top:1px solid #e6dfd2;margin-top:24px;color:#6b7a72;font-size:12px;">
  Questions? Just reply to this email, or open a ticket at <a href="https://help.harborprivacy.com" style="color:#4a7a5a;">help.harborprivacy.com</a>.<br>
  - Tim | <a href="https://harborprivacy.com" style="color:#4a7a5a;">harborprivacy.com</a>
</p>
</div>'''

def send(email, name, dry_run=True):
    html = render_html(name)
    if dry_run:
        print(f"[dry-run] would send to {email} ({name})")
        return
    r = requests.post("https://api.resend.com/emails",
        headers={"Authorization": f"Bearer {RESEND_API_KEY}", "Content-Type": "application/json"},
        json={"from": FROM_EMAIL, "to": [email], "subject": SUBJECT, "html": html})
    print(f"Sent to {email}: {r.status_code}")

if __name__ == "__main__":
    dry_run = "--send" not in sys.argv
    customers = load_customers()
    print(f"{len(customers)} active customer(s) targeted (excluding {', '.join(EXCLUDE)})")
    for c in customers:
        send(c.get("email", ""), c.get("name", "there"), dry_run=dry_run)
    if dry_run:
        print("\nDry run only -- rerun with --send to actually deliver.")
