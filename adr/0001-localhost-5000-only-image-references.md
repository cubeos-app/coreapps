# ADR-0001 — `image: localhost:5000/...` ONLY in coreapp compose files

## Status

Accepted (retrospective, 2026-05-18).

## Context

CubeOS ships to customer Pis that may or may not have reliable internet. The 13 bundled coreapps need to start up offline-by-default. Three plausible postures:

1. **Pull from Docker Hub at first boot** — requires WAN at install + per-install bandwidth + leaks customer fingerprint to Docker Hub
2. **Bundle images as `.tar.gz` + load via `docker load`** — works but doesn't survive `docker system prune`; complicates updates
3. **Local registry (`localhost:5000`) seeded at image build time + compose files reference local** — survives prune (registry persists), supports updates via re-deploy

## Decision

Option 3: every compose file references `localhost:5000/cubeos-app/<name>:<tag>`. The local registry coreapp runs first. The build pipeline (in `releases/`) pre-pulls every image via `skopeo` and copies them into the registry's seed volume.

## Consequences

- Pro: offline install (no WAN needed at customer first boot)
- Pro: deterministic version pinning (image-versions.env)
- Pro: customer privacy (no pull leakage to public registries)
- Pro: `docker system prune` is safe (registry data persists separately)
- Con: image updates require either: (a) full re-image install OR (b) authenticated push from build host to customer registry. We chose (a) via `releases/` SD-card re-image.
- Con: smoke test must enforce the rule (Article C-V)

## Alternatives rejected

- **Docker Hub pulls at runtime** — fragile, privacy leak
- **Bundle as tarballs** — doesn't survive prune
- **Customer pulls from cubeos.io upon install** — bandwidth + privacy + reliability concerns

## Related Articles

- C-II (localhost:5000 only)
- C-III (image-versions.env pinning)
- Parent Article XIV (local registry coreapp pulls)
