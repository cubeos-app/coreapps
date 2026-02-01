#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# CubeOS Swarm Initialization Script
# ═══════════════════════════════════════════════════════════════════════════════
set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ADVERTISE_ADDR="10.42.24.1"
OVERLAY_SUBNET="10.42.25.0/24"

echo ""
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  CubeOS Swarm Initialization${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════════${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}Docker not found. Please install Docker first.${NC}"
    exit 1
fi

# Check if Swarm already active
if docker info 2>/dev/null | grep -q "Swarm: active"; then
    echo -e "${YELLOW}Swarm already initialized${NC}"
    
    # Still ensure settings are correct
    echo "Verifying task-history-limit..."
    docker swarm update --task-history-limit 1 2>/dev/null || true
else
    echo -e "${GREEN}Initializing Docker Swarm...${NC}"
    docker swarm init \
        --advertise-addr "$ADVERTISE_ADDR" \
        --task-history-limit 1
    
    echo -e "${GREEN}✓ Swarm initialized${NC}"
fi

# Create overlay network if not exists OR if wrong scope
NETWORK_SCOPE=$(docker network inspect cubeos-network --format '{{.Scope}}' 2>/dev/null || echo "none")
if [ "$NETWORK_SCOPE" = "local" ]; then
    echo -e "${YELLOW}Removing local cubeos-network (wrong scope)...${NC}"
    docker network rm cubeos-network 2>/dev/null || true
    NETWORK_SCOPE="none"
fi
if [ "$NETWORK_SCOPE" = "none" ]; then
    echo "Creating cubeos-network overlay..."
    docker network create \
        --driver overlay \
        --attachable \
        --subnet "$OVERLAY_SUBNET" \
        cubeos-network
    echo -e "${GREEN}✓ Network created: cubeos-network ($OVERLAY_SUBNET)${NC}"
else
    echo -e "${YELLOW}Network cubeos-network already exists (scope: $NETWORK_SCOPE)${NC}"
fi

# Verify
echo ""
echo -e "${BLUE}Swarm Status:${NC}"
docker node ls
echo ""
echo -e "${BLUE}Networks:${NC}"
docker network ls | grep -E "(NAME|cubeos|ingress|docker_gwbridge)"

echo ""
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Swarm initialization complete!${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Next: Run deploy-coreapps.sh to deploy services"
