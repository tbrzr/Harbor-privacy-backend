#!/usr/bin/env python3
# One-off announcement email for the redesigned customer dashboard and the
# filtering updates. Same shape as announce_vpn.py: not wired to cron, dry-run
# by default, run manually once with --send.
import json, os, sys, requests

CUSTOMERS_LOG = "/var/log/harbor-customers.json"
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
FROM_EMAIL = os.environ.get("FROM_EMAIL", "info@mail.harborprivacy.com")
EXCLUDE = {"tim@harborprivacy.com", "admin@harborprivacy.com"}

SUBJECT = "Your Harbor dashboard just got easier to use"

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

def render_html(name, is_light_plan):
    # Harbor Brand Book v3.0 tokens (harbor-design-system/colors_and_type.css).
    # Inlined and with web-safe fallbacks: mail clients do not load webfonts or
    # honour CSS custom properties.
    BG, SURFACE = "#fbf7f1", "#ffffff"
    BORDER, BORDER_SOFT = "#e5dfd3", "#efe9dc"
    FG, FG_MUTED, FG_DIM = "#1a2420", "#6b7a72", "#828d86"
    ACCENT, ACCENT_LIFT = "#4a7a5c", "#8ca894"
    SERIF = "'DM Serif Display', 'Cormorant Garamond', Georgia, serif"
    SANS = "'DM Sans', -apple-system, 'Segoe UI', system-ui, sans-serif"
    MONO = "'DM Mono', 'JetBrains Mono', ui-monospace, Menlo, monospace"

    def eyebrow(text):
        return (f'<p style="font-family:{MONO};font-size:10px;color:{ACCENT};'
                f'letter-spacing:0.2em;text-transform:uppercase;margin:0 0 10px;">{text}</p>')

    def h2(text):
        return (f'<h2 style="font-family:{SERIF};font-weight:400;font-size:21px;'
                f'line-height:1.25;color:{FG};margin:36px 0 12px;">{text}</h2>')

    def para(text):
        return (f'<p style="font-family:{SANS};font-size:15px;line-height:1.65;'
                f'color:{FG};margin:0 0 14px;">{text}</p>')

    def check(text):
        # SVG would be stripped by several clients; a sage rule reads as brand.
        return (f'<tr><td style="padding:0 0 10px;font-family:{SANS};font-size:15px;'
                f'line-height:1.5;color:{FG};">'
                f'<span style="color:{ACCENT};font-weight:700;">&#8212;&nbsp;</span>{text}</td></tr>')

    kids_row = "" if is_light_plan else check(
        "<strong>Harbor Kids</strong> has its own page, plus a Screen Time wizard "
        "that locks a kid profile to the hours you choose")

    return f'''<!DOCTYPE html>
<html><body style="margin:0;padding:0;background:{BG};">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:{BG};">
<tr><td align="center" style="padding:32px 16px;">
<table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="max-width:560px;background:{SURFACE};border:1px solid {BORDER};">

<tr><td style="height:3px;background:{ACCENT};"></td></tr>

<tr><td style="padding:32px 32px 8px;">
  <p style="font-family:{MONO};font-size:13px;letter-spacing:0.1em;color:{ACCENT};margin:0 0 24px;">
    harbor<span style="color:{FG_DIM};">/</span>privacy
  </p>
  {eyebrow("Dashboard update")}
  <h1 style="font-family:{SERIF};font-weight:400;font-size:30px;line-height:1.15;color:{FG};margin:0 0 20px;">
    Fewer clicks to the thing you came for.
  </h1>
  {para(f"Hi {name},")}
  {para("Your Harbor dashboard used to stack everything onto one long page. It has "
        "been rebuilt: the front page is now a set of shortcut cards, and every "
        "section has its own page behind a single menu in the top left. Nothing "
        "about your protection changed and nothing needs reconfiguring. It is only "
        "easier to find.")}
</td></tr>

<tr><td style="padding:8px 32px 0;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0"
         style="background:{BG};border-left:3px solid {ACCENT};">
    <tr><td style="padding:20px 24px;">
      <p style="font-family:{MONO};font-size:10px;color:{ACCENT};letter-spacing:0.18em;
                text-transform:uppercase;margin:0 0 14px;">What moved</p>
      <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
        {check("<strong>Account</strong> for your plan, billing and devices")}
        {check("<strong>Filters</strong> for blocked categories and custom rules")}
        {check("<strong>Blocklists</strong> for choosing which lists apply to you, which is new")}
        {check("<strong>Usage</strong> for what got blocked and how much")}
        {check("<strong>Add-Ons</strong> for Family Safe and everything else you can turn on")}
        {kids_row}
        {check("<strong>Support</strong> for getting help without leaving the dashboard")}
      </table>
    </td></tr>
  </table>
</td></tr>

<tr><td style="padding:0 32px;">
  {h2("You can now pick your own lists")}
  {para("The new <strong>Blocklists</strong> page is the part we are most curious to "
        "hear about. Every list running on your account is shown by name, with its "
        "rule count and a link to the people who maintain it, and you decide which "
        "ones apply. Your choice covers your own devices and every Harbor Kids "
        "profile on the account at once.")}
  {para("If one list is too aggressive for how you use the internet, switch that one "
        "off and keep the rest. Unchecking everything puts you back on the full "
        "default set rather than turning blocking off, so there is no way to leave "
        "yourself unprotected from this page.")}

  {h2("Filtering updates")}
  {para("The lists behind your protection were reviewed and retuned. Harbor now runs "
        "six curated lists covering ads, trackers, malware hosts, and cookie and "
        "consent popups, with targeted exceptions so legitimate apps stop getting "
        "caught in the crossfire. If a streaming app or a login page ever misbehaved "
        "on you, that class of problem should be gone.")}
  {para("We would rather unblock one analytics hostname than have you turn Harbor off "
        "to watch a show. If something still breaks, tell us and we will fix the list "
        "rather than ask you to work around it.")}
</td></tr>

<tr><td align="center" style="padding:32px;">
  <a href="https://dashboard.harborprivacy.com/dashboard"
     style="display:inline-block;background:{ACCENT};color:{SURFACE};padding:14px 32px;
            text-decoration:none;font-family:{MONO};font-size:13px;letter-spacing:0.06em;">
    Open your dashboard &rarr;
  </a>
</td></tr>

<tr><td style="padding:0 32px 32px;border-top:1px solid {BORDER_SOFT};">
  <p style="font-family:{SANS};font-size:13px;line-height:1.6;color:{FG_MUTED};margin:20px 0 0;">
    Something broken or missing? Reply to this email, or open a ticket at
    <a href="https://help.harborprivacy.com" style="color:{ACCENT};">help.harborprivacy.com</a>.
  </p>
  <p style="font-family:{SANS};font-size:13px;color:{FG_MUTED};margin:12px 0 0;">
    &ndash; Tim &middot; <a href="https://harborprivacy.com" style="color:{ACCENT};">harborprivacy.com</a>
  </p>
</td></tr>

<tr><td style="height:2px;background:{ACCENT_LIFT};"></td></tr>
</table>
</td></tr></table>
</body></html>'''


def send(email, name, is_light_plan, dry_run=True):
    html = render_html(name, is_light_plan)
    if dry_run:
        plan = "light" if is_light_plan else "full"
        print(f"[dry-run] would send to {email} ({name}, {plan} plan, {len(html)} bytes)")
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
        send(c.get("email", ""), c.get("name", "there"),
             c.get("plan_type", "") == "harbor-remote-light", dry_run=dry_run)
    if dry_run:
        print("\nDry run only -- rerun with --send to actually deliver.")
