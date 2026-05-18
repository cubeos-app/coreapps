# Requirements — Compose stack orchestration (spec/001 — RETROSPECTIVE)

Source: `scripts/ci-deploy.sh`, `scripts/smoke-test.sh`, `scripts/watchdog-health.sh`, every `coreapps/<name>/appconfig/docker-compose.yml` (CGC-verified 2026-05-18).

> Retrospective. 13 coreapps + ci-deploy + watchdog + smoke-test all shipped. ID convention: 001-block (`001..099`).

## Compose-file convention

REQ-001: The system shall require each coreapp to live under `coreapps/<name>/` with `appconfig/docker-compose.yml` as the single source of truth (Article C-I).
REQ-002: The system shall require every `image:` line in every compose file to reference `localhost:5000/cubeos-app/<name>:<tag>` (Article C-II).
REQ-003: The system shall require every image tag to be a `${<NAME>_TAG:-<default>}` envsubst reference resolved from `image-versions.env` at deploy time (Article C-III).

## Smoke test (DoD gate)

REQ-004: When `scripts/smoke-test.sh` runs in `--check-only` mode, the system shall verify every compose file parses as valid YAML.
REQ-005: When `scripts/smoke-test.sh` runs, the system shall verify every `image:` line in every compose file is `localhost:5000`-prefixed.
REQ-006: When `scripts/smoke-test.sh` runs, the system shall verify every service has a `healthcheck:` block.
REQ-007: When `scripts/smoke-test.sh` runs, the system shall verify every volume mount points to a path under `/cubeos/data/` OR `/cubeos/coreapps/<name>/` OR a docker-managed volume name.
REQ-008: If any check fails, then the system shall exit non-zero with a per-failure error line on stderr.

## CI deploy

REQ-009: When `scripts/ci-deploy.sh` runs on the Pi (invoked via SSH from a CI runner), the system shall rsync from `/tmp/coreapps-sync/` to `/cubeos/coreapps/`.
REQ-010: The system shall detect coreapps deleted from git via `rsync --delete --dry-run` diff and tear down their swarm services BEFORE the rsync proceeds (Article C-VII).
REQ-011: The system shall execute `docker stack deploy -c <compose>.yml --resolve-image=never <name>` for every coreapp present after rsync.
REQ-012: The system shall pass `--resolve-image=never` to ensure Swarm uses the locally-tagged image rather than attempting external pull.

## Watchdog (self-healing)

REQ-013: The system shall run `scripts/watchdog-health.sh` every 5 minutes via `cubeos-watchdog.timer`.
REQ-014: The system shall verify `docker info` returns 0 (daemon healthy).
REQ-015: The system shall verify the local node is the swarm leader (or a manager).
REQ-016: While iterating over the list of expected coreapps, the system shall verify each one's `docker service ls --filter name=<name>` reports `Replicas: 1/1`.
REQ-017: If a service is `0/1` for more than 2 consecutive watchdog runs, then the system shall log to syslog at ERROR and run `docker service update --force <name>` to trigger a restart.
REQ-018: While the watchdog is in cooldown after a forced restart (15 min), the system shall not re-fire `update --force` for the same service.

## Defaults + secrets separation

REQ-019: The system shall load `defaults.env` (non-secrets) for every coreapp via `env_file:` in its compose.
REQ-020: The system shall load `/etc/cubeos/secrets.env` (per-device secrets from firstboot) for coreapps that need them via `env_file:` in their compose.
REQ-021: When smoke-test runs, the system shall verify no key appears in BOTH defaults.env AND secrets.env (overlap detection).

## Per-coreapp README

REQ-022: The system shall require every `coreapps/<name>/README.md` to contain sections: "What it does", "Port", "Volumes", "Dependencies" (Article C-VIII).

## Out of scope

REQ-023: The system shall NOT manage external (non-coreapp) services — covered by HAL's process supervisor for host-level services.
REQ-024: The system shall NOT include orchestration across multiple CubeOS boxes — a single CubeOS is single-node Swarm.
