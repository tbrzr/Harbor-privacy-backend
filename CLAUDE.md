# VM3 — Harbor Privacy + Brazer

Oracle Cloud VM (Ubuntu). All services run as systemd units. No Docker.

## Services & Ports

| Service | File | Port | Systemd unit |
|---|---|---|---|
| Harbor Dashboard | `/home/ubuntu/harbor-backend/dashboard.py` | 7000 | `harbor-dashboard.service` |
| Harbor Booking | `/home/ubuntu/harbor-booking/app.py` | 7200 | `harbor-booking.service` |
| Harbor Fax | `/home/ubuntu/harbor-backend/fax.py` | 7500 | `harbor-fax.service` |
| Harbor Webhook | `/home/ubuntu/harbor-backend/webhook.py` | 9000 | `harbor-webhook.service` |
| Brazer Dashboard | `/home/ubuntu/brazer-dashboard.py` | 8200 | `brazer-dashboard.service` |
| AdGuard Home | — | 8080 (admin), 5443 (DoH/DoT) | `AdGuardHome.service` |
| Nginx | — | 80/443 | `nginx.service` |

## Key File Locations

- **Live Harbor backend:** `/home/ubuntu/harbor-backend/` (git: tbrzr/Harbor-privacy-backend)
- **Live Brazer dashboard script:** `/home/ubuntu/brazer-dashboard.py` (NOT the repo copy)
- **Brazer repo:** `/home/ubuntu/brazer-startpage-repo/` (git: tbrzr/Brazer-Family-startpage)
- **Brazer live HTML template:** `/var/www/brazer/index.html` (read at startup by brazer-dashboard.py)
- **Brazer config/data:** `/var/www/brazer/config.json`, `/var/www/brazer/reminders.json`
- **Static customer sites:** `/var/www/network/`
- **AGH config:** `/opt/AdGuardHome/AdGuardHome.yaml` (requires sudo)
- **Nginx configs:** `/etc/nginx/sites-enabled/`

## Critical Rules

- NEVER modify `harbor_kids` or `plan_type` logic in `harbor-backend/dashboard.py`
- Static sites live at `/var/www/network/` — do not move or restructure them
- Do not touch harbor-booking or stats.harborprivacy.com nginx configs
- No em dashes in code comments or string output
- The live Brazer script is `/home/ubuntu/brazer-dashboard.py` — the repo copy at `brazer-startpage-repo/brazer-dashboard.py` must be kept in sync manually before committing
- The live Brazer HTML template is `/var/www/brazer/index.html` — changes there also need to be synced to `brazer-startpage-repo/index.html` before committing

## Restart Commands

```bash
sudo systemctl restart harbor-dashboard
sudo systemctl restart harbor-booking
sudo systemctl restart harbor-fax
sudo systemctl restart harbor-webhook
sudo systemctl restart brazer-dashboard
sudo systemctl restart nginx
```

Brazer dashboard is NOT managed by systemd — it runs as a background process:
```bash
kill $(ps aux | grep brazer-dashboard | grep python | awk '{print $2}') 2>/dev/null
sleep 1 && /home/ubuntu/harbor-booking/venv/bin/python3 /home/ubuntu/brazer-dashboard.py > /tmp/brazer.log 2>&1 &
```

## Credentials & Env Vars

Stored in systemd override files, not in code:
- `/etc/systemd/system/harbor-dashboard.service.d/override.conf`
- `/etc/systemd/system/harbor-webhook.service`

AGH credentials: `admin` / `Harbor2026!` (also in override.conf as `ADGUARD_PASS`)

## AGH Stats

- Stats interval: 7 days (set via API `POST /control/stats_config` with `{"interval": 7}`)
- Valid API presets: 1, 7, 30, 90 (days)
- Sub-day intervals (e.g. 6h) must be set directly in `/opt/AdGuardHome/AdGuardHome.yaml`
- Customer queries show as `client_id` in query log; stats `top_clients` uses same IDs
- DoH path format: `https://doh.harborprivacy.com/dns-query/{client_id}`

## CCR (Claude Code Router)

Installed at `/home/ubuntu/.local/bin/ccr`. Routes Claude Code requests to Gemini 2.5 Flash for free-tier use.

- **Config:** `~/.claude-code-router/config.json`
- **api_base_url must be:** `https://generativelanguage.googleapis.com/v1beta/models/` (trailing slash + full path required — base URL alone 404s)
- **API key:** same Gemini key as Benny (from `/var/www/brazer/config.json` `benny_api_key`)
- **Port:** 3456 (localhost only)
- **Start:** `ccr start` — **Stop:** `ccr stop` — **Status:** `ccr status`
- **Use:** `ccr code` instead of `claude` to route through Gemini 2.5 Flash
- **When to use CCR:** routine tasks, label changes, CSS tweaks, log checks
- **When to use Claude direct:** payment/booking logic, multi-file refactors, anything touching harbor_kids or plan_type

If the Gemini API key changes, update both `/var/www/brazer/config.json` AND `~/.claude-code-router/config.json`.

## Stack Notes

- Python 3 / Flask for harbor-backend and brazer; gunicorn for harbor-booking
- harbor-booking venv: `/home/ubuntu/harbor-booking/venv/` — use this Python for brazer-dashboard too
- Resend API for email, Telnyx for fax, Stripe for fax payments
- Gemini 2.5 Flash (google-genai) for Benny AI in Brazer — API key stored in `/var/www/brazer/config.json`
- AGH DoH proxied through nginx on port 5443 (TLS), nginx strips client IP so all queries appear as `127.0.0.0`
