#!/bin/bash

BASE="http://127.0.0.1:7500"
PASS=0
FAIL=0

check() {
  local label=$1
  local url=$2
  local method=${3:-GET}
  local code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "405" ]]; then
    echo "  ✓ $label ($code)"
    ((PASS++))
  else
    echo "  ✗ $label ($code) -- FAIL"
    ((FAIL++))
  fi
}

echo ""
echo "Harbor Privacy Fax -- Pre-restart Check"
echo "======================================="

check "Upload endpoint"          "$BASE/fax/upload" POST
check "Create payment intent"    "$BASE/fax/create-payment-intent" POST
check "Validate promo"           "$BASE/fax/validate-promo" POST
check "Status endpoint"          "$BASE/fax/status/test-token"
check "Telnyx webhook"           "$BASE/fax/telnyx-webhook" POST
check "Stripe webhook"           "$BASE/fax/stripe-webhook" POST

echo ""
if [ $FAIL -eq 0 ]; then
  echo "All $PASS checks passed. Safe to restart."
  sudo systemctl restart harbor-fax
  sleep 2
  sudo systemctl status harbor-fax --no-pager | head -5
else
  echo "FAILED: $FAIL check(s). NOT restarting."
  exit 1
fi
