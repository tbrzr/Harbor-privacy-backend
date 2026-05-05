#!/bin/bash
# Harbor home status beacon — runs on home Pi every minute
# Checks Homebridge and Unbound, POSTs results to VM3
TOKEN="15c07d23a56a6b46a08c21150e3d5baf5a87c0f34ab6b660db0a2bdb2040b5ad"
ENDPOINT="https://dashboard.harborprivacy.com/api/home-status"

# Check Homebridge (HTTP)
t0=$(date +%s%3N)
if curl -sf --max-time 3 -o /dev/null http://127.0.0.1:8581; then
  hb_ok=true
else
  hb_ok=false
fi
hb_ms=$(($(date +%s%3N) - t0))

# Check Unbound (DNS query)
t0=$(date +%s%3N)
if dig @127.0.0.1 -p 5335 +time=2 +tries=1 harborprivacy.com A +short > /dev/null 2>&1; then
  unb_ok=true
else
  unb_ok=false
fi
unb_ms=$(($(date +%s%3N) - t0))

curl -sf -X POST "$ENDPOINT" \
  -H "Content-Type: application/json" \
  -H "X-Home-Token: $TOKEN" \
  -d "{\"homebridge\":{\"ok\":$hb_ok,\"ms\":$hb_ms},\"unbound\":{\"ok\":$unb_ok,\"ms\":$unb_ms}}"
