#!/usr/bin/env bash
# =============================================================================
# CubeOS Coreapps — Pi-side restart script (executed via SSH from GPU VM)
# =============================================================================
# Usage: GHCR_TOKEN=... GHCR_USER=... CHANGED_APPS="app1 app2" bash /tmp/ci-restart-coreapps.sh
#
# Registry-first: compose files reference localhost:5000/ images.
# Per-repo CI (api, hal, dashboard, docsindex) handles pull+retag+push.
# This script only restarts services from cached images — no pulling.
# =============================================================================
set -e

echo "=== Coreapps Restart ==="

if [ -z "${CHANGED_APPS:-}" ]; then
  echo "No app changes detected, skipping restart"
  exit 0
fi

echo "Apps to restart: $CHANGED_APPS"

# --- GHCR login ---
echo "$GHCR_TOKEN" | docker login ghcr.io -u "$GHCR_USER" --password-stdin

# --- DNS Health Check ---
echo "Checking DNS resolution..."
DNS_OK=false
for attempt in 1 2 3; do
  if getent hosts registry-1.docker.io >/dev/null 2>&1; then
    DNS_OK=true
    break
  fi
  echo "  DNS attempt $attempt failed, waiting..."
  sleep 5
done

if [ "$DNS_OK" = "false" ]; then
  echo "DNS resolution failed - is Pi-hole running?"
  exit 1
fi
echo "  DNS OK"

# --- Ensure Swarm is initialized ---
if ! docker info 2>/dev/null | grep -q "Swarm: active"; then
  echo "Initializing Docker Swarm..."
  docker swarm init --advertise-addr 10.42.24.1 --task-history-limit 1 2>/dev/null || true
fi

# --- Ensure overlay network exists with SWARM scope ---
NETWORK_SCOPE=$(docker network inspect cubeos-network --format '{{.Scope}}' 2>/dev/null || echo "none")
if [ "$NETWORK_SCOPE" = "local" ]; then
  echo "Removing local cubeos-network (wrong scope)..."
  docker network rm cubeos-network 2>/dev/null || true
  NETWORK_SCOPE="none"
fi
if [ "$NETWORK_SCOPE" = "none" ]; then
  echo "Creating cubeos-network overlay (swarm scope)..."
  docker network create --driver overlay --attachable --subnet 10.42.25.0/24 cubeos-network
fi

# --- Ensure hal-internal overlay network ---
HAL_NET_SCOPE=$(docker network inspect hal-internal --format '{{.Scope}}' 2>/dev/null || echo "none")
if [ "$HAL_NET_SCOPE" = "local" ]; then
  echo "Removing local hal-internal (wrong scope)..."
  docker network rm hal-internal 2>/dev/null || true
  HAL_NET_SCOPE="none"
fi
if [ "$HAL_NET_SCOPE" = "none" ]; then
  echo "Creating hal-internal overlay (swarm scope)..."
  docker network create --driver overlay --attachable --subnet 10.42.26.0/24 hal-internal
fi

# --- Classify apps by deployment type ---
COMPOSE_APPS=""
STACK_APPS=""
HAS_PIHOLE=false

for app in $CHANGED_APPS; do
  case "$app" in
    pihole)
      HAS_PIHOLE=true
      ;;
    npm|cubeos-hal|terminal)
      COMPOSE_APPS="$COMPOSE_APPS $app"
      ;;
    registry|chromadb|cubeos-api|cubeos-dashboard|cubeos-docsindex|filebrowser|dozzle|kiwix|ollama|mosquitto|meshsat)
      STACK_APPS="$STACK_APPS $app"
      ;;
    *)
      COMPOSE_APPS="$COMPOSE_APPS $app"
      ;;
  esac
done
COMPOSE_APPS=$(echo "$COMPOSE_APPS" | xargs)
STACK_APPS=$(echo "$STACK_APPS" | xargs)

echo "Compose apps: ${COMPOSE_APPS:-none}"
echo "Swarm stacks: ${STACK_APPS:-none}"
echo "Pi-hole: $HAS_PIHOLE"

# --- Source env files for variable substitution in compose files ---
if [ -f /cubeos/config/defaults.env ]; then
  set -a
  # shellcheck disable=SC1091
  source /cubeos/config/defaults.env
  set +a
  echo "Sourced defaults.env (GATEWAY_IP=${GATEWAY_IP:-not set})"
fi
if [ -f /cubeos/config/secrets.env ]; then
  set -a
  # shellcheck disable=SC1091
  source /cubeos/config/secrets.env
  set +a
  echo "Sourced secrets.env"
fi

# --- Detect docker_gwbridge gateway (runtime override) ---
# docker_gwbridge subnet is assigned by Docker at Swarm init — not predictable.
# Detect the actual gateway IP so compose files can route to host services.
DETECTED_GW=$(docker network inspect docker_gwbridge \
  --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null) || true
if [ -n "$DETECTED_GW" ]; then
  export DOCKER_HOST_GW="$DETECTED_GW"
  echo "Docker host gateway (detected): ${DOCKER_HOST_GW}"
else
  echo "Docker host gateway (fallback): ${DOCKER_HOST_GW:-172.16.1.1}"
fi

# --- Deploy COMPOSE apps ---
for app in $COMPOSE_APPS; do
  COMPOSE_FILE="/cubeos/coreapps/${app}/appconfig/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Skipping $app (no docker-compose.yml)"
    continue
  fi

  echo "-- $app (compose) --"
  cd "/cubeos/coreapps/${app}/appconfig"

  echo "  Stopping existing..."
  docker rm -f "cubeos-${app}" 2>/dev/null || true
  docker compose down 2>/dev/null || true

  echo "  Using cached image (registry-first)..."

  echo "  Starting..."
  DOCKER_DEFAULT_PLATFORM=linux/arm64 docker compose up -d --pull never

  sleep 3
  CONTAINER=$(docker compose ps -q 2>/dev/null | head -1)
  if [ -n "$CONTAINER" ]; then
    for i in $(seq 1 10); do
      STATUS=$(docker inspect --format='{{.State.Status}}' "$CONTAINER" 2>/dev/null || echo "unknown")
      if [ "$STATUS" = "running" ]; then
        echo "  $app running"
        break
      fi
      [ "$i" -eq 10 ] && echo "  $app status: $STATUS"
      sleep 3
    done
  else
    echo "  $app started"
  fi
done

# --- Deploy SWARM stacks ---
for app in $STACK_APPS; do
  COMPOSE_FILE="/cubeos/coreapps/${app}/appconfig/docker-compose.yml"
  if [ ! -f "$COMPOSE_FILE" ]; then
    echo "Skipping $app (no docker-compose.yml)"
    continue
  fi

  echo "-- $app (swarm) --"

  echo "  Removing existing stack..."
  docker stack rm "$app" 2>/dev/null || true
  docker network rm "${app}_default" 2>/dev/null || true
  sleep 3

  echo "  Deploying stack..."
  docker stack deploy \
    -c "$COMPOSE_FILE" \
    --resolve-image=never \
    "$app"

  sleep 5
  for i in $(seq 1 12); do
    REPLICAS=$(docker stack services "$app" --format "{{.Replicas}}" 2>/dev/null | head -1 || echo "0/0")
    RUNNING=$(echo "$REPLICAS" | cut -d'/' -f1)
    DESIRED=$(echo "$REPLICAS" | cut -d'/' -f2)
    if [ "$RUNNING" = "$DESIRED" ] && [ "$RUNNING" != "0" ]; then
      echo "  $app running ($REPLICAS)"
      break
    fi
    [ "$i" -eq 12 ] && echo "  $app may still be starting ($REPLICAS)"
    sleep 5
  done
done

# --- Restart pihole LAST (if changed) ---
if [ "$HAS_PIHOLE" = "true" ]; then
  echo ""
  echo "-- pihole (compose - DNS will briefly drop) --"
  cd "/cubeos/coreapps/pihole/appconfig"

  echo "  Using cached image (registry-first)..."

  RESOLV_BAK=""
  if [ -f /etc/resolv.conf ]; then
    RESOLV_BAK=$(cat /etc/resolv.conf)
  fi

  # Temporarily use external DNS while pihole is down
  set +e
  echo "nameserver 1.1.1.1" > /etc/resolv.conf 2>/dev/null || true

  echo "  Stopping existing..."
  docker rm -f cubeos-pihole 2>/dev/null || true
  docker compose down --remove-orphans 2>/dev/null || true

  echo "  Starting (from cached image)..."
  DOCKER_DEFAULT_PLATFORM=linux/arm64 docker compose up -d --pull never

  echo "  Waiting for Pi-hole DNS..."
  for i in $(seq 1 30); do
    if getent hosts google.com >/dev/null 2>&1; then
      echo "  Pi-hole DNS responding"
      break
    fi
    [ "$i" -eq 30 ] && echo "  Pi-hole may still be starting..."
    sleep 2
  done

  # Restore original resolv.conf
  if [ -n "$RESOLV_BAK" ]; then
    echo "$RESOLV_BAK" > /etc/resolv.conf 2>/dev/null || true
  fi
  set -e
fi

# --- Final status ---
echo ""
echo "======================================="
echo "Final Status"
echo "======================================="
echo ""
echo "COMPOSE CONTAINERS:"
docker ps --format "table {{.Names}}\t{{.Status}}" 2>/dev/null | grep -E "cubeos-|NAME" || echo "  None"
echo ""
echo "SWARM STACKS:"
docker stack ls 2>/dev/null || echo "  None"
echo ""
echo "Restart complete"
