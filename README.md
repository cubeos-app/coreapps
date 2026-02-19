# CubeOS Core Apps

Docker service configurations for CubeOS — an open-source ARM64 server OS for Raspberry Pi.

## What This Repo Contains

This repo holds **configuration only** — Docker Compose files and deployment scripts.
Source code for CubeOS services lives in their own repositories:

| Service | Source Repo | Image |
|---------|------------|-------|
| HAL | [cubeos/hal](../hal) | `ghcr.io/cubeos-app/hal` |
| API | [cubeos/api](../api) | `ghcr.io/cubeos-app/api` |
| Dashboard | [cubeos/dashboard](../dashboard) | `ghcr.io/cubeos-app/dashboard` |
| Docsindex | [cubeos/docsindex](../docsindex) | `ghcr.io/cubeos-app/cubeos-docsindex` |

## Network

| Setting | Value |
|---------|-------|
| Subnet | 10.42.24.0/24 |
| Gateway | 10.42.24.1 |
| Domain | cubeos.cube |
| DNS/DHCP | Pi-hole (port 6001) |
| Reverse Proxy | NPM (ports 80/443) |

## Services

Each service has a directory with `appconfig/docker-compose.yml`.

### Compose Services (host networking)
- **pihole** — DNS/DHCP server (port 6001)
- **npm** — Nginx Proxy Manager (ports 80/443, admin 6000)
- **cubeos-hal** — Hardware Abstraction Layer (port 6005, privileged)
- **terminal** — Web terminal

### Swarm Stacks (overlay networking)
- **cubeos-api** — Backend API (port 6010)
- **cubeos-dashboard** — Web dashboard (port 6011)
- **cubeos-docsindex** — Documentation indexer (port 6032)
- **chromadb** — Vector database (port 6031)
- **ollama** — LLM inference (port 6030)
- **registry** — Local Docker registry (port 5000)
- **filebrowser** — Web file manager (port 6013)
- **dozzle** — Container log viewer (port 6012)
- **kiwix** — Offline wiki (port 6043)

### VPN (OS-level, managed by HAL)
WireGuard, OpenVPN, and Tor run at the OS level and are managed by the HAL
service via `/hal/vpn/*` endpoints. They are NOT Docker services.

## Port Allocation

```
6000-6009  Infrastructure (NPM: 6000, Pi-hole: 6001, HAL: 6005)
6010-6019  Platform (API: 6010, Dashboard: 6011, Dozzle: 6012, FileBrowser: 6013)
6020-6029  Network/VPN (WireGuard: 6020, OpenVPN: 6021, Tor: 6022) — OS-level
6030-6039  AI/ML (Ollama: 6030, ChromaDB: 6031, Docsindex: 6032)
6100-6999  User applications
```
