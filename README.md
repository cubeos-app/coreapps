# CubeOS Core Apps

Docker service configurations for [CubeOS](../docs) — an open-source ARM64 server OS for Raspberry Pi.

This repo holds **configuration only** — Docker Compose files, deployment scripts, and shared environment config. Source code for CubeOS-built services lives in dedicated repositories:

| Service | Source | Image |
|---------|--------|-------|
| API | [cubeos/api](../api) | `ghcr.io/cubeos-app/api` |
| Dashboard | [cubeos/dashboard](../dashboard) | `ghcr.io/cubeos-app/dashboard` |
| HAL | [cubeos/hal](../hal) | `ghcr.io/cubeos-app/hal` |
| Docsindex | [cubeos/docsindex](../docsindex) | `ghcr.io/cubeos-app/cubeos-docsindex` |

## Repository Structure

```
coreapps/
├── defaults.env                  # Shared env config (ports, paths, versions)
├── .gitlab-ci.yml                # CI: validate → deploy → restart
│
├── chromadb/appconfig/           # Vector database (AI search)
├── cubeos-api/appconfig/         # Go backend API
├── cubeos-dashboard/appconfig/   # Vue.js web dashboard
├── cubeos-docsindex/appconfig/   # Documentation indexer
├── cubeos-hal/appconfig/         # Hardware Abstraction Layer (privileged)
├── dozzle/appconfig/             # Container log viewer
├── filebrowser/appconfig/        # Web file manager
├── kiwix/appconfig/              # Offline wiki server
├── npm/appconfig/                # Nginx Proxy Manager (reverse proxy)
├── ollama/appconfig/             # LLM inference engine
├── pihole/appconfig/             # DNS/DHCP server
├── registry/appconfig/           # Local Docker registry (offline installs)
├── terminal/appconfig/           # Web terminal (ttyd)
│
└── scripts/
    ├── watchdog-health.sh        # Self-healing health check (V4)
    ├── cubeos-watchdog.service   # systemd oneshot unit
    ├── cubeos-watchdog.timer     # Runs every 60s after boot
    └── install-watchdog.sh       # Installs systemd units on Pi
```

## Services

### Compose Services (host networking)

These require host network access for DHCP broadcasts, real client IPs, or privileged hardware access.

| Service | Image | Ports | Purpose |
|---------|-------|-------|---------|
| **pihole** | `pihole/pihole` | 53, 67, 6001 | DNS/DHCP server |
| **npm** | `jc21/nginx-proxy-manager` | 80, 443, 6000 | Reverse proxy + SSL |
| **cubeos-hal** | `ghcr.io/cubeos-app/hal` | 6005 | Hardware abstraction (privileged) |
| **terminal** | `tsl0922/ttyd` | 6042 | Web terminal |

### Swarm Stacks (overlay networking)

Deployed via `docker stack deploy` on the `cubeos-network` overlay. Self-healing, rolling updates, resource limits.

| Service | Image | Port | Purpose |
|---------|-------|------|---------|
| **cubeos-api** | `ghcr.io/cubeos-app/api` | 6010 | Backend REST API |
| **cubeos-dashboard** | `ghcr.io/cubeos-app/dashboard` | 6011 | Web management UI |
| **cubeos-docsindex** | `ghcr.io/cubeos-app/cubeos-docsindex` | 6032 | RAG documentation indexer |
| **dozzle** | `amir20/dozzle` | 6012 | Container log viewer |
| **filebrowser** | `filebrowser/filebrowser:s6` | 6013 | Web file manager |
| **chromadb** | `chromadb/chroma` | 6031 | Vector database |
| **ollama** | `ollama/ollama` | 6030 | LLM inference |
| **kiwix** | `kiwix/kiwix-serve` | 6043 | Offline wiki |
| **registry** | `registry:2` | 5000 | Local Docker registry |

### VPN (OS-level, managed by HAL)

WireGuard, OpenVPN, and Tor are installed at the OS level and managed by the HAL service via `/hal/vpn/*` endpoints. They are not Docker services — containerizing them would conflict with HAL's host-level management and add unnecessary `NET_ADMIN`/`SYS_MODULE` complexity.

## Network

| Setting | Value |
|---------|-------|
| Subnet | `10.42.24.0/24` |
| Gateway | `10.42.24.1` |
| Domain | `cubeos.cube` |
| DHCP range | `10.42.24.10–250` |

## Port Allocation

```
22           SSH (host)
53, 67       DNS/DHCP (Pi-hole, host mode)
80, 443      HTTP/HTTPS (NPM, host mode)
5000         Local Docker Registry

6000-6009    Infrastructure
             6000  NPM admin
             6001  Pi-hole admin
             6005  HAL

6010-6019    Platform
             6010  API
             6011  Dashboard
             6012  Dozzle
             6013  FileBrowser

6020-6029    Network/VPN (OS-level, not Docker)
             6020  WireGuard
             6021  OpenVPN
             6022  Tor SOCKS

6030-6039    AI/ML
             6030  Ollama
             6031  ChromaDB
             6032  Docsindex

6040-6049    System Tools
             6042  Terminal
             6043  Kiwix

6100-6999    User applications (dynamically allocated)
```

## CI/CD Pipeline

**Stages:** `validate` → `deploy` → `restart`

| Job | Stage | What it does |
|-----|-------|-------------|
| `shellcheck` | validate | Lints all shell scripts |
| `validate-compose` | validate | Validates all `docker-compose.yml` files |
| `deploy` | deploy | Rsyncs changed services to Pi, cleans deleted apps |
| `restart-changed` | restart | Restarts only services whose config changed |

The pipeline auto-detects which services changed per commit and only restarts those. Compose services use `docker compose up -d`, Swarm stacks use `docker stack deploy`.

## Configuration

`defaults.env` is the shared environment file sourced by all services. It lives at `/cubeos/config/defaults.env` on the Pi and defines ports, paths, network settings, and version info. Service-specific overrides go in each service's `appconfig/.env`.
