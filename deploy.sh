#!/bin/bash
# Harbor Privacy Backend — Deploy Script
# Run once on Oracle VM2 to set up the webhook server

set -e

echo "======================================"
echo "  Harbor Privacy Backend Setup"
echo "======================================"

# Install dependencies
pip3 install requests bcrypt --break-system-packages

# Create directory
mkdir -p /home/ubuntu/harbor-backend

# Copy files
cp webhook.py /home/ubuntu/harbor-backend/
cp harbor-webhook.service /etc/systemd/system/

echo ""
echo "Now edit the service file to add your API keys:"
echo "  sudo nano /etc/systemd/system/harbor-webhook.service"
echo ""
echo "Then enable and start:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable harbor-webhook"
echo "  sudo systemctl start harbor-webhook"
echo ""
echo "Then add Nginx route for /webhook"
echo "Then create Stripe webhook pointing to https://harborprivacy.com/webhook"
