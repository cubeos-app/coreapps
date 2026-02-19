#!/bin/bash
# Install CubeOS watchdog systemd files
# Called by CI pipeline after syncing scripts/
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD_DIR="/etc/systemd/system"

echo "Installing CubeOS watchdog systemd files..."

sudo cp "$SCRIPT_DIR/cubeos-watchdog.service" "$SYSTEMD_DIR/"
sudo cp "$SCRIPT_DIR/cubeos-watchdog.timer" "$SYSTEMD_DIR/"
sudo chmod 644 "$SYSTEMD_DIR/cubeos-watchdog.service"
sudo chmod 644 "$SYSTEMD_DIR/cubeos-watchdog.timer"

sudo systemctl daemon-reload
sudo systemctl enable cubeos-watchdog.timer
sudo systemctl start cubeos-watchdog.timer

echo "Watchdog installed"
