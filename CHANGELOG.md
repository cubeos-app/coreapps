# Changelog — coreapps

All notable changes to this project. Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) + [Conventional Commits](https://www.conventionalcommits.org/).

Generated from git history + tags by `scripts/sdd-generate-changelog.py` on 2026-05-18.


## [v0.2.0-beta.05] - 2026-03-01

### Changed

- bump version to 0.2.0-beta.05 (d285654a)

### Fixed

- Pi-hole healthcheck uses FTL readiness probe instead of /admin/ (9421ec8e)


## [v0.2.0-beta.04] - 2026-02-28

### Changed

- bump version to v0.2.0-beta.04 (361eba4a)

### Fixed

- use GATEWAY_IP variable for dashboard nginx proxy_pass (d7361a2b)


## [v0.2.0-beta.03] - 2026-02-27

_No commits within window._


## [v0.2.0-beta.02] - 2026-02-27

### Added

- add hal-internal overlay network for HAL access isolation (6668dcca)

### Changed

- HAL ACL key distribution via compose environment [Phase 8.4] (966e330b)


## [v0.2.0-beta.01] - 2026-02-24

### Added

- migrate Dufs + ChromaDB to localhost:5000 registry refs (c3aec58a)

### Changed

- bump version to 0.2.0-beta.01 (0e6cf795)
- registry-first batch 2: all images reference localhost:5000 with pinned tags (518fdf0c)
- P1-19: cross-service smoke test script (220c772b)

### Fixed

- deploy image-versions.env to Pi + disable Dufs healthcheck (b6206d70)
- ci-restart uses --pull never for registry-first compose refs (acf84e36)


## [v0.2.0-alpha.01] - 2026-02-22

### Added

- replace FileBrowser with Dufs file manager (8a05b142)

### Changed

- bump version to 0.2.0-alpha.01 (ade569aa)

### Fixed

- escape dollar sign in Dufs healthcheck (10770dc1)
- nsenter for host shell access instead of container bash (91a6b0e0)
- healthcheck root path instead of /health (f45e0160)


## [v0.1.0-alpha.25] - 2026-02-21

### Changed

- bump CUBEOS_VERSION to alpha.25 (2aa34448)


## [v0.1.0-alpha.24] - 2026-02-20

### Changed

- alpha.24: version bump (bbcbdd57)


## [v0.1.0-alpha.23] - 2026-02-19

### Added

- migrate deploy+restart to SSH from GPU VM (no Pi runner needed) (63a48f18)

### Changed

- version bump to 0.1.0-alpha.23 (5c12a1db)
- rewrite README to reflect current repo state (30edef4d)
- remove phantoms, VPN stubs, rename filebrowser (ffab33e6)
- extract HAL and docsindex to own repos (77be86f1)
- adopt hal-test.sh from scripts repo (2dba012a)

### Fixed

- properly ignore appdata dirs at all depths (2863225b)
- add chromadb and ollama to Swarm stacks classification (b3f7b954)
- remove accidentally tracked appdata files (88fc4872)


## [v0.1.0-alpha.22] - 2026-02-19

### Added

- T10 — WriteNetplan endpoint for netplan management (345a0ca8)

### Changed

- alpha.22: version bump defaults.env + docsindex (40e7af56)
- alpha.22 batch 3: GPS exclusion for serial scan (B68) (717c0390)
- alpha.22 batch1: X728 sysfs GPIO (B80), HAL 501 allowlist (B70), I2C recovery logging (B81) (fa3f1e7e)
- redeploy pihole with fixed CI pipeline (370eb73d)
- T07,T08,T25: pihole env var audit, expandHosts fix, dns cleanup (881c49f2)

### Fixed

- pull pihole image before stopping (DNS chicken-and-egg) (7a4a6cc7)


## [v0.1.0-alpha.21] - 2026-02-18

### Changed

- bump docsindex version to alpha.21 (1d095f6d)

### Fixed

- FR01 country default US→NL + version bump alpha.21 (1faad6b1)


## [v0.1.0-alpha.20] - 2026-02-17

### Added

- UPS user-confirmed selection — Batch 1 HAL foundation (7dff1641)

### Changed

- bump version to 0.1.0-alpha.20 (1c9dfbdd)
- bump memory limit 64M→128M (T13) (c7eaf7e6)

### Fixed

- B35 mount boot page over /var/www/html/index.html (642686fc)


## [v0.1.0-alpha.19] - 2026-02-17

### Added

- add kiwix swarm stack, fix terminal image ref, add ports to defaults.env (0139a5c1)

### Fixed

- 3 compose file bugs for alpha.19 (3655fca0)
- remove :ro from NPM boot page bind mount (chown fails on read-only) (0d37eb2d)
- classify kiwix as swarm stack, terminal as compose, remove stale ollama/chromadb (ceb1cc34)
- B35 volume mount boot page over NPM default site (865a497e)
- B45 safe git sync + disable clone by default (7bc03889)


## [v0.1.0-alpha.17] - 2026-02-16

_No commits within window._


## [v0.1.0-alpha.18] - 2026-02-16

### Changed

- alpha.17: NPM volume mounts for boot log + custom pages (990fd142)


## [v0.1.0-alpha.16] - 2026-02-16

### Changed

- alpha.16: B01 uncomment env vars, B02 CUBEOS_VERSION in HAL, version bump (886244af)


## [v0.1.0-alpha.15] - 2026-02-16

### Added

- add package-docsindex CI job to push multi-arch image to GHCR (95553a19)
- add GET /wifi/status/{iface} with signal, IP, gateway, DNS, channel (2c0248f5)
- Add /network/ports/listening endpoint for host port scanning (9afe4657)
- add AP blocklist endpoint (BUG-10) (394f9d6c)
- add hostname and OS info endpoints to HAL (BUG-04) (b62aa098)
- add hostname GET/SET endpoints to HAL (BUG-04) (ca9abcdd)
- Phase 2b — BLE transport for Meshtastic driver (ee7e818c)
- add Meshtastic protobuf serial driver (Phase 2a) (0d051ce4)
- add I2C bus recovery for DesignWare controller lockup (649e243f)
- multi-UPS power monitor with auto-detection (b1758e65)
- Add missing WiFi saved networks and storage SMART alias endpoints (19f7c15d)
- Add FileBrowser coreapp as Swarm stack (c2225d68)
- Complete HAL implementation with ~80 endpoints (3f933153)
- add OpenAPI docs at /hal/docs and /hal/openapi.yaml (7660b682)
- add peripherals support (2625c966)
- add Iridium SBD (RockBLOCK 9603) support (16273c8b)
- add Meshtastic LoRa mesh support (21ecd38b)
- add cellular modem support (cadce3dd)
- add GPS support with NMEA parsing (df83ba61)
- add Tor VPN support (SOCKS proxy mode) (bd52b533)
- add logs and support bundle endpoints (3bd3e2c9)
- add storage endpoints (230856fb)
- add EEPROM and boot config endpoints (247ba2fe)
- add voltage-based battery percentage estimate (f304e6cc)
- add CPU throttle/temperature endpoints (b419d5de)
- add interface traffic stats endpoint + hostapd socket fix (4fc5a16c)
- add power management, UPS, RTC, watchdog, uptime (e3b95d59)
- add AP clients endpoint for connected device listing (869d848b)
- add cubeos-hal - hardware abstraction layer service (6a21df41)
- add pid host mode for WiFi interface access via nsenter (7a7bef47)
- updated watchdog for hybrid compose/swarm architecture (98b7a8e0)
- Swarm-ready compose files + deployment scripts (d896c219)
- reduce chunk size to 300 for better RAG precision (f9b61bb8)
- add docs-indexer for RAG (syncs docs from Git, indexes to ChromaDB) (41c12144)
- add ollama as standalone coreapp (6a2a2c24)
- deploy chromadb vector store (e9ed01f0)
- add chromadb vector store for AI assistant (6eda65d0)
- add Ollama service for AI assistant (f3a98a0e)
- add dashboard, use local image tags (76376279)
- add memory limits and healthchecks to critical containers (a5da6d0a)
- persist custom.list DNS entries in repo (7d18e707)
- use local registry image, auto-restart changed apps (46700b85)
- auto-restart changed coreapps and health check (bb4755f8)
- enable DHCP server via environment variables (f013adf0)
- add orchestrator (core api + dashboard compose) (b894f07e)
- initial sync of CubeOS core apps (14 services) (2c04f7f9)

### Changed

- Alpha.15: docsindex AI guards, version bump, empty Ollama/ChromaDB defaults (656cd5a4)
- alpha.14: remove Ollama/ChromaDB env, version bump, docsindex filesystem mode (a13252da)
- version tag in startup log for alpha.12 (4bbc413c)
- alpha.12: version bump + docsindex fallback (B40, VER-1) (39218fe9)
- alpha.10: wire UPS driver shutdown into HAL power handler, fix API compose (B24, B17, B16) (a91f464f)
- alpha.9: HAL reboot/shutdown + hostapd_cli log spam fixes (a645f936)
- HF-09 G01: Implement POST /hal/meshtastic/channel (last 501 stub) (13c765fa)
- HF-08 G03: expose Meshtastic radio config from handshake (a0ba6288)
- HF-08 G02: Iridium ring alert monitor, auto-reconnect, SBDIX timeout env var (a5acf44d)
- HF-08 G01 fix: isHostapdActive uses /proc scan instead of systemctl (8005488f)
- HF-08 G01: BLE safety gate & adapter selection (bf792720)
- HF-07 G02: Global polish — fix swagger double-prefix, extract CORS env var, remove dead handlers (9a1e5098)
- HF-07 G01: missing endpoints, route cleanup, cellular path param (3d8fdd4e)
- HF-05 Ext P1 hotfix2: validate send input before auto-connect (42ebcd0c)
- HF-05 Ext P1 hotfix: SSE timeout bypass + clear validation ordering (6fc70efa)
- HF-05 Extended Phase 1: Production Iridium HAL driver (c173c9e2)
- HF-05 G01: GPS, Cellular, Meshtastic, Iridium — serial port validation, AT injection fix, orphan wiring, execWithTimeout migration (ca0a7bdd)
- HF-03 G01: VPN & Mounts — mount injection, unmount traversal, bash -c elimination, input validation (3dbabdd7)
- HF-02 G01: Network, WiFi & Firewall hardening (04486a59)
- HF-01 G02: system/power/sensors hardening (4638164e)
- HF-01 G01: validators library, graceful shutdown, request timeouts, CORS restriction (db7f2c3b)
- HF-00: Infrastructure hardening (09efbc52)
- Rename docs-indexer to cubeos-docsindex, add HTTP docs API (caba3d24)
- Fix OpenAPI spec injection into Docker build (04d8eab3)
- Add swaggo OpenAPI generation to HAL build pipeline (e316a8dd)
- remove debug fields from ServiceStatus handler (4c5ced55)
- expose D-Bus errors in ServiceStatus (e6cd2b0a)
- add error logging to ServiceStatus for nsenter troubleshooting (fff7c465)
- add cubeos-hal to self-healing checks (f5f110c1)
- trigger HAL build (998b23bc)
- add HAL build/package stages following API pattern (370125ee)
- add cubeos-hal to compose services for hardware abstraction (be22c994)
- retrigger pipeline (86c7925c)
- force redeploy all swarm stacks (241bc18f)
- force redeploy all services (2503fba0)
- trigger pipeline to deploy Swarm stacks (755a5a51)
- Sprint 0: Add VPN coreapps (wireguard, openvpn, tor) (69504ed9)
- Add docker compose down before up to handle existing containers (49a84c7f)
- Sprint 0: AppArmor workarounds, healthcheck fixes, port corrections (fca91da5)
- Retry CI after fixing Pi permissions (b44e55f6)
- Sprint 0: Coreapps cleanup and restructure (2bda8fc3)
- trigger docs-indexer build (6bf84ada)
- trigger docs-indexer build (72433174)
- remove ollama from orchestrator (now standalone coreapp) (4eb4ff94)
- remove terminal-ro (keeping single terminal with root access) (167873a8)
- remove homarr (redundant with CubeOS dashboard) (b3d888f9)
- trigger pihole restart via pipeline (2fcd01e9)
- update README with orchestrator info and port scheme (6b1818a7)

### Fixed

- B41 - return 501 for unsupported RTC/watchdog, fix Pi4 RTC false positive (8542903b)
- restore deploy/arm64 tags on deploy and restart jobs (08795c74)
- restore multiarch tags on validate jobs, keep deploy untagged (4476f5b4)
- remove deploy/arm64 tags to match Pi runner config (5ac5f9d1)
- HAL I2C autodetect, hostapd_cli socket, system endpoints (68c637c9)
- coreapps P0-P3 fixes (9f5932d1)
- mount secrets.env in API container for NPM bootstrap credentials (4e43a3a5)
- pihole offline-first config with FTLCONF_ env vars (61782049)
- force redeploy all services after recovery (dc573fcb)
- filter storage usage to real block devices, exclude overlays/tmpfs (dbd239e6)
- reuse saved network credentials instead of remove_network all (1af77665)
- OpenVPN auth-user-pass support, disable missing scripts (045a1c4b)
- use nsenter + direct openvpn binary instead of systemd template (0f87cbb2)
- use full config path + nsenter for wg-quick, fixes config not found (45a8fbb6)
- remove duplicate freqToChannel declaration (32e3854a)
- use select_network, remove orphans before connect (04d011e2)
- run dhclient/dhcpcd via nsenter, fallback chain for DHCP (9916eb16)
- wrap wpa_cli with nsenter to fix reply-socket timeout in container (d25aa73d)
- map numeric protocol IDs to names (0→all, 6→tcp, 17→udp) (d3a154b8)
- correct iptables parsing indices, add ping RTT to network status (e0620727)
- transform ip -j addr to structured interface format (3ea2bf21)
- skip Alpine hostapd_cli, use nsenter directly (instant vs timeout) (dea202f0)
- use hostapdCLI helper with socket path + nsenter fallback (d34cae75)
- rewrite AP status/clients/wifi-scan to return structured typed data (8f72099d)
- mount host root for volume browser + add CUBEOS_HOST_ROOT env (74723e12)
- mount host /etc/os-release into HAL container (BUG-04) (44bc30f5)
- Fix HAL_HOST: bind 0.0.0.0 instead of 127.0.0.1 for Swarm container access (7fab0397)
- Fix pipeline: cubeos-docsindex as Swarm stack, auto-build, deleted app cleanup (e804a189)
- Fix journal logs: use nsenter to access host journalctl from Alpine container (7a7182b5)
- Add missing firewall/network endpoints with Swagger annotations, add smartmontools (27760c1b)
- Use sysfs for temperature/throttle - vcgencmd doesn't work in Alpine containers (065ef694)
- Use Pi 5 lib paths for vcgencmd (not /opt/vc) (a07a34a5)
- Add LD_LIBRARY_PATH for vcgencmd shared libraries (23b5a048)
- Add /hal prefix to HAL_URL for correct endpoint paths (912d792c)
- Add HAL_URL environment variable for HAL client connectivity (b6dbece0)
- Add cubeos-filebrowser to STACK_APPS case pattern (c92bd927)
- rename support bundle endpoint to bundle.zip (1b43805e)
- use nsenter for vcgencmd + fix test script (4e344f0e)
- add hostapd package for hostapd_cli (fc979cb4)
- comprehensive network status + AP client management (23aa6271)
- add CubeOS Pi-hole v6 DHCP lease path for AP client hostnames (c8ade15e)
- remove --remove-orphans flag that was killing pihole during HAL deploy (e3e54347)
- correct D-Bus socket mount path for systemd communication (50d6570d)
- force fresh image pull on deploy (59e07370)
- use D-Bus instead of nsenter for systemctl (154adcd2)
- use nsenter for systemctl in HAL (host namespace access) (98c1e0c1)
- add AP clients route to cmd/cubeos-hal/main.go (31614e86)
- add go.sum for HAL dependencies (9b29e95f)
- rename services to match stack names for Swarm status lookup (858032f0)
- add sudo for systemd operations in watchdog install (20fbc314)
- add dryrun field to registry uploadpurging config (bad059cc)
- ensure cubeos-network is swarm scope, not local (e4d0c547)
- force remove containers before compose up (82501e79)
- hybrid compose/swarm CI pipeline (a4ab2992)
- Fix CI: create dummy env files for compose validation (a2bf6d28)
- use correct ChromaDB v2 API path with tenant/database (65b11bba)
- log HTTP status code on ChromaDB errors (2e51793e)
- sync src/ directories and auto-detect build vs pull (c14b7a72)
- use ChromaDB default port 8000 (env var not respected) (f9cd558e)
- use v2 API for healthcheck (23275bf6)
- add Ollama and ChromaDB host config for container networking (5bc1fae5)
- remove --remove-orphans flag (was killing unrelated containers) (cfc4ec21)
- smarter restart - only changed apps, DNS check, pull before up (a298aa5e)
- expose ollama port 11434 (dc683254)
- add ollama service with proper volumes section (c8718c1f)
- add I2C device for UPS battery monitoring (8755b892)
- restart pihole LAST to prevent DNS outage cascade (619be7a6)

### Security

- add HAL public-ip endpoint, fix script-security for OpenVPN up/down (34e23936)
- use script-security 2 with /bin/true override for up/down scripts (7a5fb43e)
- HF-06 G01: Camera & Audio security hardening (2e5884af)
- HF-04 G01: GPIO, I2C, USB, Bluetooth security hardening (d4e69c6a)
- HF-03 G02: Storage, USB Storage & Logs security hardening (472e431c)

