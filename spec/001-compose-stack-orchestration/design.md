# Design — Compose stack orchestration (spec/001 — RETROSPECTIVE)

CGC-grounded against `scripts/ci-deploy.sh`, `scripts/smoke-test.sh`, `scripts/watchdog-health.sh` 2026-05-18.

## Real shape

```
GitLab CI
  |
  v
SSH to Pi -> rsync /tmp/coreapps-sync/ -> /cubeos/coreapps/
  |
  v
scripts/ci-deploy.sh
  |
  +-> detect deletions (rsync --delete --dry-run diff)
  |    +-> docker stack rm <deleted-coreapp>
  |
  +-> for each present coreapp:
  |    docker stack deploy -c appconfig/docker-compose.yml \
  |                       --resolve-image=never <name>
  |
  v
systemd cubeos-watchdog.timer (every 5 min)
  |
  v
scripts/watchdog-health.sh
  |
  +-> docker info  # daemon alive?
  +-> docker node ls  # leader?
  +-> for each expected coreapp:
  |    docker service ls --filter name=<name>
  |    if 0/1 for 2 consecutive runs:
  |       docker service update --force <name>
  |       enter 15-min cooldown
  v
log to journal
```

## Real file paths (CGC-verified)

| File | Status |
|---|---|
| `scripts/ci-deploy.sh` | EXISTS — rsync + stack deploy orchestrator |
| `scripts/ci-restart.sh` | EXISTS — selective service restart |
| `scripts/smoke-test.sh` | EXISTS — DoD gate |
| `scripts/cubeos-watchdog.service` | EXISTS — systemd unit |
| `scripts/cubeos-watchdog.timer` | EXISTS — 5-min cadence |
| `scripts/watchdog-health.sh` | EXISTS — health probe + auto-restart |
| `scripts/install-watchdog.sh` | EXISTS — called by releases firstboot |
| `defaults.env` | EXISTS — non-secret defaults |
| `image-versions.env` | EXISTS — pinned tags |
| 13 × `coreapps/<name>/appconfig/docker-compose.yml` | ALL EXIST |
| 13 × `coreapps/<name>/README.md` | EXISTS for most; smoke-test catches missing |

## Smoke-test pseudocode (REQ-004..008)

```bash
for compose in coreapps/*/appconfig/docker-compose.yml; do
  yq eval . "$compose" >/dev/null || fail "$compose: yaml parse"
  yq eval '.services.*.image' "$compose" | grep -v '^localhost:5000/' \
    && fail "$compose: non-localhost image"
  yq eval '.services.* | select(.healthcheck == null)' "$compose" \
    | grep -q . && fail "$compose: missing healthcheck"
  # ... etc
done
```

## Watchdog cooldown (REQ-018)

State file at `/var/lib/cubeos/watchdog-cooldown.json`:

```json
{
  "<coreapp-name>": {
    "last_force_restart": "2026-05-18T12:00:00Z",
    "cooldown_until": "2026-05-18T12:15:00Z",
    "consecutive_failures_before_restart": 2
  }
}
```

## Out of scope

- HA / multi-node Swarm (single-Pi today)
- External service management (HAL handles host-level)
- Per-coreapp resource limits (compose `deploy.resources` is per-coreapp's own responsibility)
