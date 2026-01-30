#!/bin/bash
# CubeOS Core Apps Deployment Script
# Deploys all core services with the 6000-range port scheme

set -e

COREAPPS_DIR="/cubeos/coreapps"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo ""
echo -e "${BLUE}=========================================="
echo "  CubeOS Core Apps Deployment"
echo -e "==========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Create cubeos-network if it doesn't exist
echo -e "${YELLOW}Creating cubeos-network...${NC}"
docker network create cubeos-network 2>/dev/null || echo "Network already exists"

# Core apps in deployment order (dependencies first)
CORE_APPS=(
    "pihole"      # 6001 - DNS must be up first
    "npm"         # 6000 - Reverse proxy
    "dockge"      # 6002 - Stack manager
    "homarr"      # 6003 - Dashboard
    "dozzle"      # 6004 - Logs
    "backup"      # 6005 - Backup service
    "diagnostics" # 6006 - Diagnostics
    "reset"       # 6007 - Reset service
    "usb-monitor" # 6008 - USB monitoring
    "terminal"    # 6009 - Web terminal
    "terminal-ro" # 6010 - Read-only terminal
    "watchdog"    # Background - Health monitor
    "nettools"    # Background - Network tools
    "gpio"        # Background - GPIO access
)

# Port mapping for display
declare -A PORTS=(
    ["npm"]="6000 (+ 80/443)"
    ["pihole"]="6001 (+ 53)"
    ["dockge"]="6002"
    ["homarr"]="6003"
    ["dozzle"]="6004"
    ["backup"]="6005"
    ["diagnostics"]="6006"
    ["reset"]="6007"
    ["usb-monitor"]="6008"
    ["terminal"]="6009"
    ["terminal-ro"]="6010"
    ["watchdog"]="-"
    ["nettools"]="-"
    ["gpio"]="-"
)

echo "Core apps to deploy:"
for app in "${CORE_APPS[@]}"; do
    echo "  - $app (port ${PORTS[$app]})"
done
echo ""

read -p "Continue with deployment? (y/N) " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Deployment cancelled."
    exit 0
fi

# Deploy each core app
for app in "${CORE_APPS[@]}"; do
    echo ""
    echo -e "${BLUE}=== Deploying $app ===${NC}"
    
    app_dir="$COREAPPS_DIR/$app"
    config_dir="$app_dir/appconfig"
    data_dir="$app_dir/appdata"
    
    # Create directories
    mkdir -p "$config_dir" "$data_dir"
    
    # Copy compose file if source exists
    if [ -f "$SCRIPT_DIR/$app/appconfig/docker-compose.yml" ]; then
        cp "$SCRIPT_DIR/$app/appconfig/docker-compose.yml" "$config_dir/"
        [ -f "$SCRIPT_DIR/$app/appconfig/.env" ] && cp "$SCRIPT_DIR/$app/appconfig/.env" "$config_dir/"
    fi
    
    # Check if compose file exists
    if [ ! -f "$config_dir/docker-compose.yml" ]; then
        echo -e "${RED}  ✗ No docker-compose.yml found, skipping${NC}"
        continue
    fi
    
    # Deploy
    cd "$config_dir"
    
    # Pull latest images
    echo "  Pulling images..."
    docker compose pull 2>/dev/null || true
    
    # Start service
    echo "  Starting..."
    docker compose up -d
    
    echo -e "${GREEN}  ✓ $app deployed (port ${PORTS[$app]})${NC}"
done

echo ""
echo -e "${GREEN}=========================================="
echo "  Deployment Complete!"
echo -e "==========================================${NC}"
echo ""
echo "Core App Ports (192.168.42.1):"
echo "  6000 - Nginx Proxy Manager"
echo "  6001 - Pi-hole Admin"
echo "  6002 - Dockge"
echo "  6003 - Homarr Dashboard"
echo "  6004 - Dozzle Logs"
echo "  6005 - Backup Service"
echo "  6006 - Diagnostics"
echo "  6007 - Reset Service"
echo "  6008 - USB Monitor"
echo "  6009 - Terminal"
echo "  6010 - Terminal (Read-Only)"
echo ""
echo "Verify: docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep cubeos"
