#!/bin/bash
# =============================================================================
# smoke-test.sh — CubeOS Cross-Service Smoke Test
# =============================================================================
# Quick health validation of all CubeOS services. Designed to run:
#   - After image flash + first boot (manual)
#   - After coreapps CI deploy (wired via P1-20)
#   - As part of QA cycles
#
# Exit code: 0 = all critical checks pass, 1 = failures detected
#
# Usage:
#   ./smoke-test.sh                          # defaults (localhost)
#   ./smoke-test.sh 10.42.24.1               # custom host
#   SMOKE_SKIP_PERF=1 ./smoke-test.sh        # skip performance checks
#
# Phase 1.4 (P1-19)
# =============================================================================
set -uo pipefail

HOST="${1:-127.0.0.1}"
API_URL="http://${HOST}:6010"
HAL_URL="http://${HOST}:6005"
DASHBOARD_URL="http://${HOST}:6011"
PIHOLE_URL="http://${HOST}:6001"
NPM_URL="http://${HOST}:81"
DOZZLE_URL="http://${HOST}:6012"
DOMAIN="cubeos.cube"
SKIP_PERF="${SMOKE_SKIP_PERF:-0}"

# Colors (disabled if not a terminal)
if [ -t 1 ]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
    BLUE='\033[0;34m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; NC=''
fi

PASSED=0
FAILED=0
WARNED=0
CRITICAL_FAIL=0

check_pass() { echo -e "${GREEN}OK${NC}    $1"; PASSED=$((PASSED + 1)); }
check_fail() { echo -e "${RED}FAIL${NC}  $1 — $2"; FAILED=$((FAILED + 1)); }
check_crit() { echo -e "${RED}CRIT${NC}  $1 — $2"; FAILED=$((FAILED + 1)); CRITICAL_FAIL=$((CRITICAL_FAIL + 1)); }
check_warn() { echo -e "${YELLOW}WARN${NC}  $1 — $2"; WARNED=$((WARNED + 1)); }
section()    { echo ""; echo -e "${BLUE}--- $1 ---${NC}"; }

echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  CubeOS Smoke Test${NC}"
echo -e "${BLUE}  Host: ${HOST}  Time: $(date -u +%Y-%m-%dT%H:%M:%SZ)${NC}"
echo -e "${BLUE}============================================================${NC}"

# ─── 1. Docker & Swarm ──────────────────────────────────────────────────
section "1. Docker & Swarm"

if docker info &>/dev/null; then
    check_pass "1.1 Docker daemon running"
else
    check_crit "1.1 Docker daemon" "not running"
fi

if docker info 2>/dev/null | grep -q "Swarm: active"; then
    check_pass "1.2 Swarm active"
else
    check_crit "1.2 Swarm" "not active"
fi

OVERLAY=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -c "^cubeos-network$" || true)
if [ "$OVERLAY" -ge 1 ]; then
    check_pass "1.3 cubeos-network overlay exists"
else
    check_fail "1.3 cubeos-network overlay" "missing"
fi

HAL_NET=$(docker network ls --format '{{.Name}}' 2>/dev/null | grep -c "^hal-internal$" || true)
if [ "$HAL_NET" -ge 1 ]; then
    check_pass "1.4 hal-internal overlay exists"
else
    check_fail "1.4 hal-internal overlay" "missing"
fi

# ─── 2. Core Services (HTTP health) ────────────────────────────────────
section "2. Core Services"

check_http() {
    local label="$1" url="$2" critical="${3:-0}"
    local status
    status=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 "$url" 2>/dev/null || echo "000")
    if [ "$status" -ge 200 ] && [ "$status" -lt 400 ]; then
        check_pass "$label (HTTP $status)"
    elif [ "$critical" = "1" ]; then
        check_crit "$label" "HTTP $status"
    else
        check_fail "$label" "HTTP $status"
    fi
}

check_http "2.1 API /health"        "${API_URL}/health"        1
check_http "2.2 HAL /health"        "${HAL_URL}/health"        1
check_http "2.3 Dashboard"          "${DASHBOARD_URL}/"        1
check_http "2.4 Pi-hole admin"      "${PIHOLE_URL}/admin/"     0
check_http "2.5 NPM API"           "${NPM_URL}/api/"          0
check_http "2.6 Dozzle"            "${DOZZLE_URL}/"           0

# ─── 3. API Authentication ──────────────────────────────────────────────
section "3. API Authentication"

LOGIN_RESP=$(curl -sf --max-time 10 -X POST \
    -H "Content-Type: application/json" \
    -d '{"username":"admin","password":"admin"}' \
    "${API_URL}/api/v1/auth/login" 2>/dev/null || echo "")

if [ -n "$LOGIN_RESP" ]; then
    TOKEN=$(echo "$LOGIN_RESP" | jq -r '.access_token // empty' 2>/dev/null)
    if [ -n "$TOKEN" ]; then
        check_pass "3.1 Login successful (token obtained)"

        # Test authenticated endpoint
        AUTH_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 \
            -H "Authorization: Bearer $TOKEN" \
            "${API_URL}/api/v1/apps" 2>/dev/null || echo "000")
        if [ "$AUTH_STATUS" = "200" ]; then
            check_pass "3.2 Authenticated request works"
        else
            check_fail "3.2 Authenticated request" "HTTP $AUTH_STATUS"
        fi
    else
        check_fail "3.1 Login" "no access_token in response"
        TOKEN=""
    fi
else
    check_fail "3.1 Login" "no response from auth endpoint"
    TOKEN=""
fi

# Test that unauthenticated requests are rejected
UNAUTH_STATUS=$(curl -sf -o /dev/null -w "%{http_code}" --max-time 10 \
    "${API_URL}/api/v1/apps" 2>/dev/null || echo "000")
if [ "$UNAUTH_STATUS" = "401" ]; then
    check_pass "3.3 Unauthenticated request rejected (401)"
else
    check_fail "3.3 Unauthenticated rejection" "expected 401, got $UNAUTH_STATUS"
fi

# ─── 4. Swarm Stacks ───────────────────────────────────────────────────
section "4. Swarm Stacks"

EXPECTED_STACKS="cubeos-api cubeos-dashboard dozzle kiwix registry"
for stack in $EXPECTED_STACKS; do
    if docker stack ls 2>/dev/null | grep -q "^${stack} "; then
        # Check replicas
        REPLICAS=$(docker service ls --filter "label=com.docker.stack.namespace=${stack}" \
            --format '{{.Replicas}}' 2>/dev/null | head -1)
        if echo "$REPLICAS" | grep -qE "^[1-9][0-9]*/[1-9]"; then
            check_pass "4.x Stack ${stack} (${REPLICAS})"
        else
            check_fail "4.x Stack ${stack}" "replicas: ${REPLICAS:-unknown}"
        fi
    else
        check_fail "4.x Stack ${stack}" "not deployed"
    fi
done

# ─── 5. Compose Services ───────────────────────────────────────────────
section "5. Compose Services"

EXPECTED_COMPOSE="cubeos-pihole cubeos-npm cubeos-hal"
for container in $EXPECTED_COMPOSE; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${container}$"; then
        check_pass "5.x Container ${container}"
    else
        check_fail "5.x Container ${container}" "not running"
    fi
done

# ─── 6. DNS Resolution ─────────────────────────────────────────────────
section "6. DNS Resolution"

check_dns() {
    local label="$1" fqdn="$2"
    local result
    result=$(dig +short "$fqdn" @127.0.0.1 2>/dev/null | head -1)
    if [ "$result" = "10.42.24.1" ]; then
        check_pass "$label ($fqdn -> $result)"
    elif [ -n "$result" ]; then
        check_warn "$label" "$fqdn -> $result (expected 10.42.24.1)"
    else
        check_fail "$label" "$fqdn did not resolve"
    fi
}

check_dns "6.1 cubeos.cube"      "cubeos.cube"
check_dns "6.2 api.cubeos.cube"  "api.cubeos.cube"
check_dns "6.3 pihole.cubeos.cube" "pihole.cubeos.cube"

# ─── 7. Network ────────────────────────────────────────────────────────
section "7. Network"

# Check wlan0 has correct IP
WLAN0_IP=$(ip -4 addr show wlan0 2>/dev/null | grep -oP '(?<=inet )\S+' | head -1)
if [ "$WLAN0_IP" = "10.42.24.1/24" ]; then
    check_pass "7.1 wlan0 IP ($WLAN0_IP)"
elif [ -n "$WLAN0_IP" ]; then
    check_warn "7.1 wlan0 IP" "got $WLAN0_IP (expected 10.42.24.1/24)"
else
    check_fail "7.1 wlan0 IP" "no address assigned"
fi

# Check hostapd
if systemctl is-active --quiet hostapd 2>/dev/null; then
    check_pass "7.2 hostapd running"
else
    check_fail "7.2 hostapd" "not running"
fi

# ─── 8. System Health ──────────────────────────────────────────────────
section "8. System Health"

# Disk usage
DISK_PCT=$(df / 2>/dev/null | awk 'NR==2{gsub(/%/,""); print $5}')
if [ "${DISK_PCT:-100}" -lt 85 ]; then
    check_pass "8.1 Disk usage (${DISK_PCT}%)"
elif [ "${DISK_PCT:-100}" -lt 95 ]; then
    check_warn "8.1 Disk usage" "${DISK_PCT}% (>85%)"
else
    check_fail "8.1 Disk usage" "${DISK_PCT}% (critical)"
fi

# Memory
MEM_AVAIL=$(awk '/MemAvailable/ {printf "%.0f", $2/1024}' /proc/meminfo 2>/dev/null)
if [ "${MEM_AVAIL:-0}" -gt 256 ]; then
    check_pass "8.2 Available memory (${MEM_AVAIL}MB)"
elif [ "${MEM_AVAIL:-0}" -gt 128 ]; then
    check_warn "8.2 Available memory" "${MEM_AVAIL}MB (low)"
else
    check_fail "8.2 Available memory" "${MEM_AVAIL}MB (critical)"
fi

# CubeOS version
if [ -f /etc/cubeos-version ]; then
    VER=$(cat /etc/cubeos-version)
    check_pass "8.3 CubeOS version: ${VER}"
else
    check_fail "8.3 CubeOS version" "/etc/cubeos-version missing"
fi

# ─── 9. Security Config (Phase 1.3) ────────────────────────────────────
section "9. Security Configuration"

# SSH hardening
if [ -f /etc/ssh/sshd_config.d/99-cubeos-hardening.conf ]; then
    check_pass "9.1 SSH hardening config present"
else
    check_warn "9.1 SSH hardening" "99-cubeos-hardening.conf missing"
fi

# sysctl security
REDIRECTS=$(sysctl -n net.ipv4.conf.all.accept_redirects 2>/dev/null)
if [ "$REDIRECTS" = "0" ]; then
    check_pass "9.2 sysctl: ICMP redirects disabled"
else
    check_warn "9.2 sysctl: ICMP redirects" "value=$REDIRECTS (expected 0)"
fi

# Journald volatile
JOURNALD_STORAGE=$(journalctl --header 2>/dev/null | grep -i "storage" | head -1 || true)
if echo "$JOURNALD_STORAGE" | grep -qi "volatile"; then
    check_pass "9.3 journald: volatile storage"
else
    check_warn "9.3 journald" "may not be volatile"
fi

# fail2ban
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    check_pass "9.4 fail2ban running"
else
    check_warn "9.4 fail2ban" "not running"
fi

# Watchdog
WD=$(systemctl show -p RuntimeWatchdogUSec 2>/dev/null | cut -d= -f2)
if [ -n "$WD" ] && [ "$WD" != "0" ]; then
    check_pass "9.5 systemd watchdog active ($WD)"
else
    check_warn "9.5 systemd watchdog" "not active"
fi

# ─── 10. Performance (optional) ────────────────────────────────────────
if [ "$SKIP_PERF" != "1" ]; then
    section "10. Response Times"

    check_perf() {
        local label="$1" url="$2" max_ms="${3:-2000}"
        local start end ms
        start=$(date +%s%N)
        curl -sf -o /dev/null --max-time 10 "$url" 2>/dev/null || true
        end=$(date +%s%N)
        ms=$(( (end - start) / 1000000 ))
        if [ "$ms" -lt "$max_ms" ]; then
            check_pass "$label (${ms}ms)"
        else
            check_warn "$label" "${ms}ms (>${max_ms}ms)"
        fi
    }

    check_perf "10.1 API /health"    "${API_URL}/health"    500
    check_perf "10.2 Dashboard"      "${DASHBOARD_URL}/"    2000
    check_perf "10.3 HAL /health"    "${HAL_URL}/health"    500
fi

# ─── Summary ────────────────────────────────────────────────────────────
TOTAL=$((PASSED + FAILED + WARNED))
echo ""
echo -e "${BLUE}============================================================${NC}"
echo -e "${BLUE}  SMOKE TEST SUMMARY${NC}"
echo -e "${BLUE}============================================================${NC}"
echo -e "  ${GREEN}Passed:${NC}   $PASSED"
echo -e "  ${RED}Failed:${NC}   $FAILED"
echo -e "  ${YELLOW}Warned:${NC}   $WARNED"
echo -e "  Total:    $TOTAL"
echo ""

if [ "$CRITICAL_FAIL" -gt 0 ]; then
    echo -e "  ${RED}CRITICAL FAILURES: $CRITICAL_FAIL — system not operational${NC}"
    exit 2
elif [ "$FAILED" -gt 0 ]; then
    echo -e "  ${RED}Some checks failed — review above${NC}"
    exit 1
else
    echo -e "  ${GREEN}All checks passed${NC}"
    exit 0
fi
