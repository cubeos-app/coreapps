# CubeOS Core Apps

System services for CubeOS - an open-source ARM64 server OS for Raspberry Pi.

## Network Configuration

| Setting | Value |
|---------|-------|
| Subnet | 10.42.24.0/24 |
| Gateway | 10.42.24.1 |
| DHCP Range | 10.42.24.10 - 10.42.24.250 |
| Domain | cubeos.cube |

## Port Allocation (Strict Scheme)

### Infrastructure (6000-6009)
| Port | Service | Description |
|------|---------|-------------|
| 5000 | registry | Local Docker Registry |
| 6000 | npm | Nginx Proxy Manager Admin |
| 6001 | pihole | Pi-hole Admin |

### Platform (6010-6019)
| Port | Service | Description |
|------|---------|-------------|
| 6010 | cubeos-api | Backend API |
| 6011 | cubeos-dashboard | Web Frontend |
| 6012 | dozzle | Container Logs |

### Network (6020-6029)
| Port | Service | Description |
|------|---------|-------------|
| 6020 | wireguard | WireGuard VPN |
| 6021 | openvpn | OpenVPN Client |
| 6022 | tor | Tor SOCKS Proxy |
| 6023 | tor | Tor Control Port |

### AI/ML (6030-6039)
| Port | Service | Description |
|------|---------|-------------|
| 6030 | ollama | LLM Server |
| 6031 | chromadb | Vector Database |
| 6032 | docs-indexer | RAG Indexer |

### User Apps
| Range | Description |
|-------|-------------|
| 6100-6999 | Dynamically allocated for user-installed apps |

## Directory Structure

```
/cubeos/
├── config/
│   ├── defaults.env      # Shared configuration
│   ├── secrets.env       # Generated secrets (not in git)
│   └── vpn/
│       ├── wireguard/
│       └── openvpn/
├── coreapps/             # System services
│   ├── pihole/
│   ├── npm/
│   ├── registry/
│   ├── cubeos-api/
│   ├── cubeos-dashboard/
│   └── ...
├── apps/                 # User-installed apps
├── data/
│   ├── cubeos.db         # SQLite database
│   └── registry/         # Registry storage
└── mounts/               # SMB/NFS mount points
```

## Core Services

### Infrastructure Layer
- **pihole** - DNS + DHCP server (host network mode)
- **npm** - Nginx Proxy Manager (host network mode)
- **registry** - Local Docker registry for offline-first

### Platform Layer
- **cubeos-api** - Go backend API
- **cubeos-dashboard** - Vue.js 3 frontend
- **dozzle** - Container log viewer
- **watchdog** - Health monitoring

### Network Layer
- **wireguard** - WireGuard VPN client
- **openvpn** - OpenVPN client
- **tor** - Tor privacy proxy

### AI/ML Layer
- **ollama** - Local LLM server
- **chromadb** - Vector database for RAG
- **docs-indexer** - Documentation indexer

## Deployment

```bash
# Deploy all core apps
sudo ./deploy-coreapps.sh

# Verify
docker ps --format 'table {{.Names}}\t{{.Ports}}' | grep cubeos
```

## CI/CD

This repository uses GitLab CI/CD. On push to main:
1. Validates all compose files
2. Syncs configs to `/cubeos/coreapps/`
3. Restarts changed services
4. Verifies DNS (Pi-hole) health

## License

Apache 2.0
