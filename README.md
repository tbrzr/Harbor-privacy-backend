# Harbor Privacy — Backend

Webhook automation for customer onboarding.

## What It Does

1. Stripe fires a webhook when a customer pays
2. Script generates a unique client ID
3. Creates the client in AdGuard Home automatically
4. Sends a welcome email via Resend with their DoH address and setup instructions

## Files

- `webhook.py` — main webhook server (Python, no framework)
- `harbor-webhook.service` — systemd service file
- `requirements.txt` — Python dependencies
- `deploy.sh` — one-time setup script

## Setup

### 1. Deploy to Oracle VM2

```bash
pip3 install requests bcrypt --break-system-packages
mkdir -p /home/ubuntu/harbor-backend
cp webhook.py /home/ubuntu/harbor-backend/
sudo cp harbor-webhook.service /etc/systemd/system/
```

### 2. Add API Keys

```bash
sudo nano /etc/systemd/system/harbor-webhook.service
```

Fill in:
- `STRIPE_WEBHOOK_SECRET` — from Stripe Dashboard → Webhooks
- `RESEND_API_KEY` — from Resend dashboard
- `ADGUARD_PASS` — your AdGuard admin password

### 3. Start Service

```bash
sudo systemctl daemon-reload
sudo systemctl enable harbor-webhook
sudo systemctl start harbor-webhook
```

### 4. Add Nginx Route

Add to `/etc/nginx/sites-available/brazer-network` inside the harborprivacy.com server block:

```nginx
location /webhook {
    proxy_pass http://127.0.0.1:9000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
}
```

### 5. Create Stripe Webhook

Stripe Dashboard → Developers → Webhooks → Add endpoint:
- URL: `https://harborprivacy.com/webhook`
- Events: `checkout.session.completed`
- Copy the signing secret to the service file

## Logs

```bash
tail -f /var/log/harbor-webhook.log
cat /var/log/harbor-customers.json
```

## Customer DoH Address Format

```
doh.harborprivacy.com/dns-query/CLIENTID
```
