#!/bin/bash
# Install CubeOS watchdog systemd files
# Called by CI pipeline after syncing scripts/
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR="/etc/systemd/system"

echo "Installing CubeOS watchdog systemd files..."

# Create symlink for backward compatibility (/cubeos/scripts -> /cubeos/coreapps/scripts)
if [ ! -L "/cubeos/scripts" ]; then
    sudo rm -rf /cubeos/scripts 2>/dev/null || true
    sudo ln -sf /cubeos/coreapps/scripts /cubeos/scripts
    echo "Created symlink: /cubeos/scripts -> /cubeos/coreapps/scripts"
fi

# Copy service and timer files
sudo cp "$SCRIPT_DIR/cubeos-watchdog.service" "$SYSTEMD_DIR/"
sudo cp "$SCRIPT_DIR/cubeos-watchdog.timer" "$SYSTEMD_DIR/"

# Set permissions
sudo chmod 644 "$SYSTEMD_DIR/cubeos-watchdog.service"
sudo chmod 644 "$SYSTEMD_DIR/cubeos-watchdog.timer"

# Reload systemd
sudo systemctl daemon-reload

# Enable and start timer (idempotent)
sudo systemctl enable cubeos-watchdog.timer
sudo systemctl start cubeos-watchdog.timer

echo "Watchdog timer status:"
sudo systemctl status cubeos-watchdog.timer --no-pager || true

echo "✅ Watchdog installed successfully"
