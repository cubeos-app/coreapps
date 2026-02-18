#!/bin/bash
# Initialize Pi-hole local DNS entries
# This runs after Pi-hole container starts (fallback only — seed_pihole_dns()
# in cubeos-boot-lib.sh is the primary seeding mechanism)

CUSTOM_LIST="/cubeos/coreapps/pihole/appdata/etc-pihole/hosts/custom.list"

# Only create if doesn't exist (seed_pihole_dns handles the authoritative copy)
if [ ! -f "$CUSTOM_LIST" ]; then
    echo "Creating Pi-hole custom DNS entries..."
    mkdir -p "$(dirname "$CUSTOM_LIST")"
    cat > "$CUSTOM_LIST" << 'ENTRIES'
# CubeOS DNS entries — must match CORE_DNS_HOSTS in cubeos-boot-lib.sh
# All services resolve to gateway IP (10.42.24.1)
10.42.24.1 cubeos.cube
10.42.24.1 api.cubeos.cube
10.42.24.1 npm.cubeos.cube
10.42.24.1 pihole.cubeos.cube
10.42.24.1 hal.cubeos.cube
10.42.24.1 dozzle.cubeos.cube
10.42.24.1 registry.cubeos.cube
10.42.24.1 docs.cubeos.cube
10.42.24.1 terminal.cubeos.cube
10.42.24.1 kiwix.cubeos.cube
ENTRIES
    echo "DNS entries created (10 entries)"
else
    echo "DNS entries already exist"
fi
