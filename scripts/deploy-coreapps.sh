#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CubeOS Core Apps Deployment Script (Hybrid: Compose + Swarm)
# ═══════════════════════════════════════════════════════════════════════════════
#
# COMPOSE SERVICES (host network mode required):
#   - pihole   (DHCP broadcast)
#   - npm      (ports 80/443)
#
# SWARM STACKS (bridge network, self-healing):
#   - registry
#   - cubeos-api
#   - cubeos-dashboard
#   - dozzle
#   - ollama
#   - chromadb
#
# Usage: deploy-coreapps.sh [all|compose|stacks|stop|status|<service-name>]
# ═══════════════════════════════════════════════════════════════════════════════

set -e

COREAPPS_DIR="/cubeos/coreapps"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Service classification
COMPOSE_SERVICES="pihole npm"
STACK_SERVICES="registry cubeos-api cubeos-dashboard dozzle ollama chromadb"
ALL_SERVICES="$COMPOSE_SERVICES $STACK_SERVICES"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# ─────────────────────────────────────────────────────────────────────────────
# Helper Functions
# ─────────────────────────────────────────────────────────────────────────────

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_err() { echo -e "${RED}[ERROR]${NC} $1"; }

is_compose_service() {
    echo "$COMPOSE_SERVICES" | grep -qw "$1"
}

wait_for_health() {
    local name="$1"
    local url="$2"
    local timeout="${3:-60}"
    
    log_info "Waiting for $name to be healthy..."
    for i in $(seq 1 "$timeout"); do
        if curl -sf "$url" > /dev/null 2>&1; then
            log_ok "$name is healthy"
            return 0
        fi
        sleep 1
    done
    log_warn "$name health check timed out after ${timeout}s"
    return 1
}

# ─────────────────────────────────────────────────────────────────────────────
# Deploy Functions
# ─────────────────────────────────────────────────────────────────────────────

deploy_compose() {
    local service="$1"
    local compose_file="$COREAPPS_DIR/$service/appconfig/docker-compose.yml"
    
    if [ ! -f "$compose_file" ]; then
        log_err "Compose file not found: $compose_file"
        return 1
    fi
    
    log_info "Deploying $service via docker-compose..."
    cd "$COREAPPS_DIR/$service/appconfig"
    
    # Stop existing if running
    docker compose down --remove-orphans 2>/dev/null || true
    
    # Pull and start
    docker compose pull 2>/dev/null || true
    docker compose up -d
    
    log_ok "$service deployed (compose)"
}

deploy_stack() {
    local service="$1"
    local compose_file="$COREAPPS_DIR/$service/appconfig/docker-compose.yml"
    
    if [ ! -f "$compose_file" ]; then
        log_err "Compose file not found: $compose_file"
        return 1
    fi
    
    log_info "Deploying $service via docker stack..."
    
    # Remove existing stack first (ensures clean deploy)
    docker stack rm "$service" 2>/dev/null || true
    sleep 2
    
    # Deploy with ARM64 workaround
    docker stack deploy \
        -c "$compose_file" \
        --resolve-image=never \
        "$service"
    
    log_ok "$service deployed (swarm stack)"
}

remove_stack() {
    local service="$1"
    log_info "Removing stack: $service"
    docker stack rm "$service" 2>/dev/null || true
}

stop_compose() {
    local service="$1"
    log_info "Stopping compose service: $service"
    cd "$COREAPPS_DIR/$service/appconfig" 2>/dev/null && docker compose down --remove-orphans 2>/dev/null || true
}

# ─────────────────────────────────────────────────────────────────────────────
# Main Commands
# ─────────────────────────────────────────────────────────────────────────────

deploy_all() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  CubeOS Core Apps Deployment${NC}"
    echo -e "${BLUE}  Subnet: 10.42.24.0/24 | Gateway: 10.42.24.1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    # Verify Swarm
    if ! docker info 2>/dev/null | grep -q "Swarm: active"; then
        log_err "Swarm not initialized. Run init-swarm.sh first."
        exit 1
    fi
    
    # Ensure directories
    mkdir -p /cubeos/{config,coreapps,apps,data,mounts}
    mkdir -p /cubeos/data/registry
    
    # Deploy compose services first (DNS must be up)
    echo ""
    log_info "──────────────── COMPOSE SERVICES ────────────────"
    for service in $COMPOSE_SERVICES; do
        deploy_compose "$service"
    done
    
    # Wait for Pi-hole DNS
    wait_for_health "Pi-hole" "http://127.0.0.1:6001/admin/" 60
    
    # Wait for NPM
    wait_for_health "NPM" "http://127.0.0.1:81/api/" 60
    
    # Deploy swarm stacks
    echo ""
    log_info "──────────────── SWARM STACKS ────────────────"
    for service in $STACK_SERVICES; do
        deploy_stack "$service"
        sleep 3  # Brief pause between stacks
    done
    
    echo ""
    log_info "Waiting for services to stabilize..."
    sleep 10
    
    # Show status
    show_status
}

deploy_compose_only() {
    log_info "Deploying COMPOSE services only..."
    for service in $COMPOSE_SERVICES; do
        deploy_compose "$service"
    done
}

deploy_stacks_only() {
    log_info "Deploying SWARM stacks only..."
    for service in $STACK_SERVICES; do
        deploy_stack "$service"
        sleep 2
    done
}

stop_all() {
    log_info "Stopping all services..."
    
    # Stop stacks
    for service in $STACK_SERVICES; do
        remove_stack "$service"
    done
    
    # Stop compose
    for service in $COMPOSE_SERVICES; do
        stop_compose "$service"
    done
    
    log_ok "All services stopped"
}

show_status() {
    echo ""
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  Service Status${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${YELLOW}COMPOSE SERVICES:${NC}"
    for service in $COMPOSE_SERVICES; do
        container="cubeos-$service"
        status=$(docker inspect --format='{{.State.Status}}' "$container" 2>/dev/null || echo "not found")
        health=$(docker inspect --format='{{.State.Health.Status}}' "$container" 2>/dev/null || echo "n/a")
        printf "  %-20s %-12s (health: %s)\n" "$service" "$status" "$health"
    done
    
    echo ""
    echo -e "${YELLOW}SWARM STACKS:${NC}"
    for service in $STACK_SERVICES; do
        replicas=$(docker stack services "$service" --format "{{.Replicas}}" 2>/dev/null | head -1 || echo "0/0")
        printf "  %-20s replicas: %s\n" "$service" "$replicas"
    done
    
    echo ""
    echo -e "${YELLOW}DOCKER STATS:${NC}"
    docker stats --no-stream --format "table {{.Name}}\t{{.CPUPerc}}\t{{.MemUsage}}" 2>/dev/null | head -15
    echo ""
}

deploy_single() {
    local service="$1"
    
    if is_compose_service "$service"; then
        deploy_compose "$service"
    else
        deploy_stack "$service"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

if [ "$EUID" -ne 0 ]; then 
    log_err "Please run as root"
    exit 1
fi

case "${1:-}" in
    all)
        deploy_all
        ;;
    compose)
        deploy_compose_only
        ;;
    stacks)
        deploy_stacks_only
        ;;
    stop)
        stop_all
        ;;
    status)
        show_status
        ;;
    "")
        echo "Usage: $0 [all|compose|stacks|stop|status|<service-name>]"
        echo ""
        echo "Commands:"
        echo "  all      - Deploy all services (compose + stacks)"
        echo "  compose  - Deploy compose services only (pihole, npm)"
        echo "  stacks   - Deploy swarm stacks only"
        echo "  stop     - Stop all services"
        echo "  status   - Show service status"
        echo "  <name>   - Deploy single service"
        echo ""
        echo "Services:"
        echo "  Compose: $COMPOSE_SERVICES"
        echo "  Swarm:   $STACK_SERVICES"
        ;;
    *)
        if echo "$ALL_SERVICES" | grep -qw "$1"; then
            deploy_single "$1"
        else
            log_err "Unknown service: $1"
            exit 1
        fi
        ;;
esac
