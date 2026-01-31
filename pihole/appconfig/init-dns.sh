#!/bin/bash
# Initialize Pi-hole local DNS entries
# This runs after Pi-hole container starts

CUSTOM_LIST="/cubeos/coreapps/pihole/appdata/etc-pihole/custom.list"

# Only create if doesn't exist
if [ ! -f "$CUSTOM_LIST" ]; then
    echo "Creating Pi-hole custom DNS entries..."
    cat > "$CUSTOM_LIST" << 'ENTRIES'
# CubeOS DNS entries
# All services resolve to gateway IP

10.42.24.1 cubeos.cube
10.42.24.1 api.cubeos.cube
10.42.24.1 pihole.cubeos.cube
10.42.24.1 npm.cubeos.cube
10.42.24.1 logs.cubeos.cube
10.42.24.1 terminal.cubeos.cube
10.42.24.1 ollama.cubeos.cube
10.42.24.1 chromadb.cubeos.cube
10.42.24.1 registry.cubeos.cube
ENTRIES
    echo "✅ DNS entries created"
else
    echo "DNS entries already exist"
fi
