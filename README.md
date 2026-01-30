# CubeOS Core Apps

Infrastructure services for CubeOS. Each service follows the structure:
- `appconfig/` - docker-compose.yml + .env (tracked in git)
- `appdata/` - runtime data (not tracked)

## Services

| Service | Port | Description |
|---------|------|-------------|
| pihole | 6001, 53 | Network-wide ad blocking & DNS |
| npm | 6000, 80, 443 | Nginx Proxy Manager |
| dockge | 6002 | Docker Compose manager |
| homarr | 6003 | Dashboard |
| dozzle | 6004 | Container log viewer |
| backup | 6005 | Backup service |
| diagnostics | 6006 | Health checks |
| reset | 6007 | Factory reset |
| usb-monitor | 6008 | USB device monitoring |
| terminal | 6009 | Web terminal (full access) |
| terminal-ro | 6010 | Web terminal (read-only) |
| watchdog | - | System monitoring |
| nettools | - | Network diagnostics |
| gpio | - | GPIO control |

## Orchestrator (Separate Deployment)

The `orchestrator/` folder contains the main CubeOS compose file for the API and Dashboard services. 

**Note:** Orchestrator is NOT deployed by `deploy-coreapps.sh`. The API and Dashboard have their own dedicated CI/CD pipelines in their respective repos (`api/` and `dashboard/`) that handle building, testing, and deployment automatically.

## Deployment
```bash
# Deploy all core services (excludes orchestrator)
/cubeos/coreapps/deploy-coreapps.sh

# Stop all core services
/cubeos/coreapps/stop-coreapps.sh
```

## CI/CD Pipeline

- **validate-compose**: Validates all docker-compose.yml files
- **shellcheck**: Lints shell scripts
- **deploy**: Syncs configs to `/cubeos/coreapps/` on Pi (main branch only)

## Port Scheme

CubeOS core services use the 6000-range:
- `6000-6010` - Web UIs accessible on `192.168.42.1`
- `53` - DNS (Pi-hole)
- `80/443` - HTTP/HTTPS proxy (NPM)
