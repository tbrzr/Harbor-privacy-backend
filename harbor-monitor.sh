#!/bin/bash
NTFY_TOPIC="harbor-brazer-monitor"
NTFY_URL="https://ntfy.sh/$NTFY_TOPIC"

alert() {
  local title=$1
  local msg=$2
  curl -s -X POST "$NTFY_URL" \
    -H "Title: $title" \
    -H "Priority: urgent" \
    -H "Tags: warning,harbor" \
    -d "$msg" > /dev/null
}

check_http() {
  local name=$1
  local url=$2
  local expected=$3
  local fail_file="/tmp/fail_http_${name// /_}"
  local response=$(curl -s -L -o /tmp/hcheck -w "%{http_code}" --max-time 10 "$url" 2>/dev/null)
  local body=$(cat /tmp/hcheck)
  if [ "$response" != "200" ] || [[ "$body" != *"$expected"* ]]; then
    COUNT=$(cat "$fail_file" 2>/dev/null || echo 0)
    COUNT=$((COUNT + 1))
    echo $COUNT > "$fail_file"
    if [ "$COUNT" -ge 2 ]; then
      alert "Harbor Alert -- $name DOWN" "$name returned HTTP $response. Body: ${body:0:200}"
    fi
  else
    echo 0 > "$fail_file"
  fi
}

check_service() {
  local name=$1
  local service=$2
  local fail_file="/tmp/fail_svc_${service}"
  if ! systemctl is-active --quiet "$service"; then
    COUNT=$(cat "$fail_file" 2>/dev/null || echo 0)
    COUNT=$((COUNT + 1))
    echo $COUNT > "$fail_file"
    if [ "$COUNT" -ge 2 ]; then
      alert "Harbor Alert -- $name DOWN" "$name service is not running on VM3. Attempting restart."
      systemctl restart "$service"
      sleep 5
      if systemctl is-active --quiet "$service"; then
        alert "Harbor Alert -- $name Recovered" "$name restarted successfully on VM3."
        echo 0 > "$fail_file"
      else
        alert "Harbor Alert -- $name FAILED" "$name failed to restart on VM3."
      fi
    fi
  else
    echo 0 > "$fail_file"
  fi
}

# Services
check_service "AdGuard Home" "AdGuardHome"
check_service "Unbound" "unbound"
check_service "Harbor Dashboard" "harbor-dashboard"
check_service "Harbor Webhook" "harbor-webhook"
check_service "Harbor Booking" "harbor-booking"

# HTTP endpoints
check_http "Harbor Booking" "https://booking.harborprivacy.com/health" '"status":"ok"'
check_http "Harbor Privacy" "https://harborprivacy.com" "harbor"
check_http "Harbor Dashboard" "https://dashboard.harborprivacy.com/login" "harbor"
check_http "Harbor DoH" "https://doh.harborprivacy.com/dns-query" ""

# DNS
DNS_FAIL="/tmp/fail_dns"
if ! dig @127.0.0.1 google.com +time=3 +tries=1 > /dev/null 2>&1; then
  COUNT=$(cat "$DNS_FAIL" 2>/dev/null || echo 0)
  COUNT=$((COUNT + 1))
  echo $COUNT > "$DNS_FAIL"
  if [ "$COUNT" -ge 2 ]; then
    alert "Harbor Alert -- DNS Down" "AGH DNS not responding on VM3."
    echo 0 > "$DNS_FAIL"
  fi
else
  echo 0 > "$DNS_FAIL"
fi

# Disk
DISK=$(df / | awk 'NR==2 {print $5}' | tr -d '%')
if [ "$DISK" -gt 80 ]; then
  alert "Harbor Alert -- Disk ${DISK}%" "Disk usage at ${DISK}% on VM3."
fi
