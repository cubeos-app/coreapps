#!/usr/bin/env bash
# =============================================================================
# CubeOS Coreapps — Pi-side deploy script (executed via SSH from GPU VM)
# =============================================================================
# Called AFTER rsync has transferred /tmp/coreapps-sync/ from GPU VM.
# This script:
#   1. Cleans up apps deleted from git but still on Pi
#   2. Syncs configs from /tmp staging area to /cubeos/coreapps/
#   3. Ensures config directory structure
#   4. Installs watchdog systemd files
#
# Usage: bash /tmp/ci-deploy-coreapps.sh
# =============================================================================
set -euo pipefail

SYNC_DIR="/tmp/coreapps-sync"

echo "=== Coreapps Deploy (post-sync) ==="

if [ ! -d "$SYNC_DIR" ]; then
  echo "ERROR: Sync directory $SYNC_DIR not found"
  exit 1
fi

# --- Clean up apps deleted from git but still on Pi ---
for pidir in /cubeos/coreapps/*/; do
  [ ! -d "$pidir" ] && continue
  app=$(basename "$pidir")
  case "$app" in scripts|watchdog) continue;; esac
  if [ ! -d "${SYNC_DIR}/${app}" ] && [ -d "${pidir}appconfig" ]; then
    echo "Removing deleted app: $app"
    (cd "${pidir}appconfig" 2>/dev/null && docker compose down --remove-orphans 2>/dev/null) || true
    docker stack rm "$app" 2>/dev/null || true
    sleep 3
    rm -rf "$pidir"
    echo "  Cleaned up $app"
  fi
done

# --- Sync ALL configs (idempotent) ---
cd "$SYNC_DIR"
for dir in */; do
  if [ -d "${dir}appconfig" ]; then
    mkdir -p "/cubeos/coreapps/${dir}appconfig"
    mkdir -p "/cubeos/coreapps/${dir}appdata"
    rsync -a --delete "${dir}appconfig/" "/cubeos/coreapps/${dir}appconfig/"
    if [ -d "${dir}appdata" ]; then
      rsync -a "${dir}appdata/" "/cubeos/coreapps/${dir}appdata/"
    fi
  fi
done

# --- Sync defaults.env and image-versions.env ---
[ -f defaults.env ] && cp defaults.env /cubeos/coreapps/
[ -f image-versions.env ] && cp image-versions.env /cubeos/coreapps/

# --- Ensure config directory structure ---
mkdir -p /cubeos/config/vpn/{wireguard,openvpn}
mkdir -p /cubeos/data/registry

# Copy defaults.env to config if not exists
if [ ! -f /cubeos/config/defaults.env ]; then
  cp defaults.env /cubeos/config/defaults.env
fi

# Create empty secrets.env if not exists
if [ ! -f /cubeos/config/secrets.env ]; then
  touch /cubeos/config/secrets.env
  chmod 600 /cubeos/config/secrets.env
fi

# --- Sync scripts directory ---
if [ -d "scripts" ]; then
  mkdir -p /cubeos/coreapps/scripts
  rsync -a --delete scripts/ /cubeos/coreapps/scripts/
  chmod +x /cubeos/coreapps/scripts/*.sh 2>/dev/null || true

  if [ -f "/cubeos/coreapps/scripts/install-watchdog.sh" ]; then
    echo "Installing watchdog systemd files..."
    /cubeos/coreapps/scripts/install-watchdog.sh
  fi
fi

echo "Synced to /cubeos/coreapps/"

# --- Cleanup staging area ---
rm -rf "$SYNC_DIR"
echo "Staging area cleaned"
