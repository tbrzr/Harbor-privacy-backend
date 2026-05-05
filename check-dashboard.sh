#!/bin/bash

BASE="http://127.0.0.1:7000"
PASS=0
FAIL=0
ERRORS=""

check() {
  local label=$1
  local url=$2
  local code=$(curl -s -o /dev/null -w "%{http_code}" --cookie "session=skip" "$url" 2>/dev/null)
  if [[ "$code" == "200" || "$code" == "302" || "$code" == "401" || "$code" == "303" ]]; then
    echo "  ✓ $label ($code)"
    PASS=$((PASS+1))
  else
    echo "  ✗ $label ($code) -- FAIL"
    FAIL=$((FAIL+1))
    ERRORS="$ERRORS\n  - $label returned $code"
  fi
}

echo ""
echo "Harbor Privacy Dashboard -- Pre-restart Check"
echo "=============================================="

check "Login page"         "$BASE/login"
check "Admin redirect"     "$BASE/admin"
check "Social redirect"    "$BASE/social"
check "Settings redirect"  "$BASE/settings"
check "Dashboard redirect" "$BASE/dashboard"
check "API social status"  "$BASE/api/social/status"

echo ""
if [ $FAIL -eq 0 ]; then
  echo "All $PASS checks passed. Safe to restart."
  echo ""
  echo "Restarting harbor-dashboard..."
  sudo systemctl restart harbor-dashboard
  sleep 2
  sudo systemctl status harbor-dashboard --no-pager | head -5
else
  echo "FAILED: $FAIL check(s) failed. NOT restarting."
  echo -e "$ERRORS"
  echo ""
  echo "Fix the errors above before restarting."
  exit 1
fi
