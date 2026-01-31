#!/bin/bash
# CubeOS Core Apps Deployment Script
# Deploys all core services with the strict port scheme
# Subnet: 10.42.24.0/24 | Gateway: 10.42.24.1

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
echo "  Subnet: 10.42.24.0/24"
echo -e "==========================================${NC}"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}Please run as root${NC}"
    exit 1
fi

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p /cubeos/{config,coreapps,apps,data,mounts}
mkdir -p /cubeos/config/vpn/{wireguard,openvpn}
mkdir -p /cubeos/data/registry

# Copy defaults.env if not exists
if [ ! -f /cubeos/config/defaults.env ]; then
    cp "$SCRIPT_DIR/defaults.env" /cubeos/config/defaults.env
    echo "Created /cubeos/config/defaults.env"
fi

# Create empty secrets.env if not exists
if [ ! -f /cubeos/config/secrets.env ]; then
    cat > /cubeos/config/secrets.env << 'EOF'
# CubeOS Secrets (auto-generated on first boot)
# DO NOT COMMIT THIS FILE
JWT_SECRET=changeme
PIHOLE_PASSWORD=cubeos
EOF
    chmod 600 /cubeos/config/secrets.env
    echo "Created /cubeos/config/secrets.env"
fi

# Core apps in deployment order (dependencies first)
CORE_APPS=(
    "pihole"           # 6001 - DNS/DHCP must be up first
    "npm"              # 6000 - Reverse proxy
    "registry"         # 5000 - Local Docker registry
    "cubeos-api"       # 6010 - Backend API
    "cubeos-dashboard" # 6011 - Frontend
    "dozzle"           # 6012 - Log viewer
    "watchdog"         # -     - Health monitor
    "wireguard"        # 6020 - VPN client
    "openvpn"          # 6021 - VPN client
    "tor"              # 6022 - Privacy routing
    "ollama"           # 6030 - AI model server
    "chromadb"         # 6031 - Vector database
    "docs-indexer"     # 6032 - RAG indexer
    "diagnostics"      # 6040 - Diagnostics
    "reset"            # 6041 - Factory reset
    "terminal"         # 6042 - Web terminal
    "backup"           # -     - Backup service
)

# Port mapping for display
declare -A PORTS=(
    ["pihole"]="6001 (+ 53/67)"
    ["npm"]="6000 (+ 80/443)"
    ["registry"]="5000"
    ["cubeos-api"]="6010"
    ["cubeos-dashboard"]="6011"
    ["dozzle"]="6012"
    ["watchdog"]="-"
    ["wireguard"]="6020"
    ["openvpn"]="6021"
    ["tor"]="6022/6023"
    ["ollama"]="6030"
    ["chromadb"]="6031"
    ["docs-indexer"]="6032"
    ["diagnostics"]="6040"
    ["reset"]="6041"
    ["terminal"]="6042"
    ["backup"]="-"
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
        [ -f "$SCRIPT_DIR/$app/appconfig/config.yml" ] && cp "$SCRIPT_DIR/$app/appconfig/config.yml" "$config_dir/"
    fi
    
    # Check if compose file exists
    if [ ! -f "$config_dir/docker-compose.yml" ]; then
        echo -e "${YELLOW}  ⊘ No docker-compose.yml found, skipping${NC}"
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
echo "CubeOS Port Scheme (10.42.24.1):"
echo ""
echo "  Infrastructure:"
echo "    5000 - Local Registry"
echo "    6000 - Nginx Proxy Manager"
echo "    6001 - Pi-hole Admin"
echo ""
echo "  Platform:"
echo "    6010 - CubeOS API"
echo "    6011 - CubeOS Dashboard"
echo "    6012 - Dozzle Logs"
echo ""
echo "  Network:"
echo "    6020 - WireGuard"
echo "    6021 - OpenVPN"
echo "    6022 - Tor SOCKS"
echo ""
echo "  AI/ML:"
echo "    6030 - Ollama"
echo "    6031 - ChromaDB"
echo "    6032 - Docs Indexer"
echo ""
echo "  User Apps: 6100-6999 (dynamically allocated)"
echo ""
echo "Access dashboard: http://10.42.24.1:6011 or http://cubeos.cube"
echo ""
echo "Verify: docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep cubeos"
