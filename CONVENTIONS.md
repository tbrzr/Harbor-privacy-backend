# Harbor Backend – Aider Context

## Stack
- Python 3 / Flask, served via gunicorn on port 7000 (harbor-dashboard.service)
- PostgreSQL: harbor_booking db (booking system), SQLite for fax (/home/ubuntu/harbor-fax.db)
- Nginx reverse proxy, Let's Encrypt SSL
- Resend API for email (SMTP via smtp.resend.com:465)
- Telnyx for fax send/receive (+17742549640)
- Stripe for fax payments
- AdGuard Home for DNS (port 5443)
- ntfy topic: harbor-brazer-monitor

## Key files
- dashboard.py — main Harbor Privacy dashboard (port 7000), customer management, DNS analytics
- fax.py — Harbor Fax service (port 7500), Telnyx + Stripe integration
- webhook.py — incoming webhooks (port 9000)
- run_pending_wipes.py — scheduled data wipe runner
- weekly_email.py — Monday customer digest email
- reddit_watcher.py — monitors Reddit mentions

## Critical rules
- NEVER modify harbor_kids or plan_type logic in dashboard.py
- Static sites live at /var/www/network/ — do not move them
- Do not touch harbor-booking or stats.harborprivacy.com nginx configs
- One focused change per session — don't refactor unrelated code
- No em dashes in output

## Services on this VM
- harbor-dashboard.service (port 7000)
- harbor-booking.service (port 7200)
- harbor-fax.service (port 7500)
- harbor-webhook.service (port 9000)
- brazer-dashboard.service (port 8200)
- ollama.service (port 11434, localhost only)
