#!/bin/bash
# CubeOS Self-Healing Watchdog (Hybrid Compose + Swarm)
# Runs every minute via systemd timer
# 
# Services:
#   COMPOSE (host network): pihole, npm, cubeos-hal
#   SWARM (overlay): registry, cubeos-api, cubeos-dashboard, dozzle, ollama, chromadb
#
set -o pipefail

LOG="/var/log/cubeos-watchdog.log"
SWARM_ADVERTISE_ADDR="10.42.24.1"
OVERLAY_SUBNET="10.42.25.0/24"

mkdir -p /cubeos/alerts /cubeos/data/watchdog

log() { echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG"; }

# Rotate log if > 10MB
LOG_SIZE=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
[ "$LOG_SIZE" -gt 10485760 ] && mv "$LOG" "$LOG.old"

log "━━━ Health check starting ━━━"

# ─────────────────────────────────────────────────────────────
# SWARM INITIALIZATION
# ─────────────────────────────────────────────────────────────
ensure_swarm() {
    if ! docker info 2>/dev/null | grep -q "Swarm: active"; then
        log "Swarm not active, initializing..."
        docker swarm init --advertise-addr "$SWARM_ADVERTISE_ADDR" --task-history-limit 1 2>&1 | while read line; do log "  $line"; done
    fi
    
    # Check network scope (must be swarm, not local)
    NETWORK_SCOPE=$(docker network inspect cubeos-network --format '{{.Scope}}' 2>/dev/null || echo "none")
    if [ "$NETWORK_SCOPE" = "local" ]; then
        log "cubeos-network has wrong scope (local), recreating as swarm overlay..."
        docker network rm cubeos-network 2>/dev/null || true
        NETWORK_SCOPE="none"
    fi
    if [ "$NETWORK_SCOPE" = "none" ]; then
        log "Creating cubeos-network overlay..."
        docker network create --driver overlay --attachable --subnet "$OVERLAY_SUBNET" cubeos-network 2>&1 | while read line; do log "  $line"; done
    fi
}

# ─────────────────────────────────────────────────────────────
# COMPOSE SERVICES (host network)
# ─────────────────────────────────────────────────────────────
ensure_compose() {
    local name=$1
    local dir=$2
    
    if ! docker ps --format '{{.Names}}' | grep -q "^${name}$"; then
        log "$name not running, starting via compose..."
        if [ -f "$dir/docker-compose.yml" ]; then
            # Remove any existing stopped container
            docker rm -f "$name" 2>/dev/null || true
            (cd "$dir" && docker compose up -d 2>&1) | while read line; do log "  $line"; done
        else
            log "  ERROR: $dir/docker-compose.yml not found"
            return 1
        fi
    fi
    
    # Check if healthy (if healthcheck exists)
    local health=$(docker inspect --format='{{.State.Health.Status}}' "$name" 2>/dev/null || echo "none")
    if [ "$health" = "unhealthy" ]; then
        log "$name is unhealthy, restarting..."
        docker restart "$name" 2>&1 | while read line; do log "  $line"; done
    fi
}

# ─────────────────────────────────────────────────────────────
# SWARM STACKS
# ─────────────────────────────────────────────────────────────
ensure_stack() {
    local name=$1
    local dir=$2
    
    # Check stack exists and has running replicas
    local replicas=$(docker stack services "$name" --format "{{.Replicas}}" 2>/dev/null | head -1 || echo "")
    
    if [ -z "$replicas" ]; then
        # Stack doesn't exist
        log "$name stack not found, deploying..."
        deploy_stack "$name" "$dir"
    elif [ "$replicas" = "0/1" ]; then
        # Stack exists but no running replicas
        log "$name stack has 0/1 replicas, redeploying..."
        docker stack rm "$name" 2>/dev/null || true
        sleep 3
        deploy_stack "$name" "$dir"
    fi
}

deploy_stack() {
    local name=$1
    local dir=$2
    
    if [ -f "$dir/docker-compose.yml" ]; then
        # Remove stale networks
        docker network rm "${name}_default" 2>/dev/null || true
        docker stack deploy -c "$dir/docker-compose.yml" --resolve-image=never "$name" 2>&1 | while read line; do log "  $line"; done
    else
        log "  ERROR: $dir/docker-compose.yml not found"
    fi
}

# ─────────────────────────────────────────────────────────────
# HEALTH CHECKS
# ─────────────────────────────────────────────────────────────

# 0. Ensure Swarm is ready before checking stacks
ensure_swarm

# 1. Pi-hole (compose, CRITICAL - DNS/DHCP)
ensure_compose "cubeos-pihole" "/cubeos/coreapps/pihole/appconfig"
sleep 2

# Verify Pi-hole DHCP is active
if docker ps --format '{{.Names}}' | grep -q "cubeos-pihole"; then
    if ! docker exec cubeos-pihole pihole-FTL --config dhcp.active 2>/dev/null | grep -q "true"; then
        log "Pi-hole DHCP not active, checking config..."
        # Don't auto-restart, just log - DHCP config is intentional
    fi
fi

# 2. NPM (compose, CRITICAL - reverse proxy)
ensure_compose "cubeos-npm" "/cubeos/coreapps/npm/appconfig"

# 3. HAL (compose, CRITICAL - hardware abstraction)
ensure_compose "cubeos-hal" "/cubeos/coreapps/cubeos-hal/appconfig"

# 4. Registry (swarm)
ensure_stack "registry" "/cubeos/coreapps/registry/appconfig"

# 5. API (swarm)
ensure_stack "cubeos-api" "/cubeos/coreapps/cubeos-api/appconfig"

# 6. Dashboard (swarm)
ensure_stack "cubeos-dashboard" "/cubeos/coreapps/cubeos-dashboard/appconfig"

# 7. Dozzle (swarm)
ensure_stack "dozzle" "/cubeos/coreapps/dozzle/appconfig"

# 8. Ollama (swarm)
ensure_stack "ollama" "/cubeos/coreapps/ollama/appconfig"

# 9. ChromaDB (swarm)
ensure_stack "chromadb" "/cubeos/coreapps/chromadb/appconfig"

# ─────────────────────────────────────────────────────────────
# SYSTEM SERVICES
# ─────────────────────────────────────────────────────────────

# 10. hostapd (WiFi AP)
if ! systemctl is-active --quiet hostapd; then
    log "hostapd down, restarting..."
    systemctl restart hostapd 2>&1 | while read line; do log "  $line"; done
fi

# ─────────────────────────────────────────────────────────────
# MAINTENANCE
# ─────────────────────────────────────────────────────────────

# 11. Disk space cleanup
DISK_USED=$(df / | tail -1 | awk '{print $5}' | tr -d '%')
if [ "$DISK_USED" -gt 90 ]; then
    log "Disk usage ${DISK_USED}%, cleaning..."
    docker system prune -f >> "$LOG" 2>&1
fi

# 12. Clear old Swarm tasks (memory optimization)
# Swarm keeps failed task history which can consume memory
docker system prune -f --filter "until=24h" >/dev/null 2>&1 || true

log "━━━ Health check complete ━━━"
