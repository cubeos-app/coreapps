#!/bin/bash
# CubeOS Core Apps Stop Script
# Stops all core services

set -e

COREAPPS_DIR="/cubeos/coreapps"

echo "Stopping all CubeOS core apps..."

for app_dir in "$COREAPPS_DIR"/*/appconfig; do
    if [ -f "$app_dir/docker-compose.yml" ]; then
        app=$(basename $(dirname "$app_dir"))
        echo "Stopping $app..."
        cd "$app_dir"
        docker compose down 2>/dev/null || true
    fi
done

echo "All core apps stopped."
