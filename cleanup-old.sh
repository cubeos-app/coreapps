#!/bin/bash
# CubeOS Cleanup Script
# Removes old mulecube-* containers before fresh deployment

set -e

echo "CubeOS Cleanup - Removing old containers"
echo "========================================="

# Old container prefixes to remove
OLD_CONTAINERS=(
    "mulecube-dockge"
    "mulecube-homarr"
    "mulecube-logs"
    "mulecube-backup"
    "mulecube-diagnostics"
    "mulecube-reset"
    "mulecube-usb-monitor"
    "mulecube-terminal"
    "mulecube-terminal-ro"
    "mulecube-watchdog"
    "mulecube-nettools"
    "mulecube-gpio"
    "pihole"
    "nginx-proxy"
    "watchtower-pihole"
)

echo "Stopping and removing old containers..."
for container in "${OLD_CONTAINERS[@]}"; do
    if docker ps -a --format '{{.Names}}' | grep -q "^${container}$"; then
        echo "  Removing $container..."
        docker stop "$container" 2>/dev/null || true
        docker rm "$container" 2>/dev/null || true
    fi
done

# Also remove any orphaned watchtowers
docker ps -a --format '{{.Names}}' | grep "^watchtower-" | while read c; do
    echo "  Removing orphan $c..."
    docker stop "$c" 2>/dev/null || true
    docker rm "$c" 2>/dev/null || true
done

# Clean up old compose projects
echo ""
echo "Cleaning up old compose projects..."
docker compose -f /srv/mulecube-controlpanel-admin/docker-compose.yml down 2>/dev/null || true
docker compose -f /srv/mulecube-controlpanel-user/docker-compose.yml down 2>/dev/null || true

# Prune unused networks
echo ""
echo "Pruning unused networks..."
docker network prune -f

echo ""
echo "Cleanup complete!"
echo ""
echo "Remaining containers:"
docker ps --format "table {{.Names}}\t{{.Status}}" | head -20
