Feature: Compose stack orchestration (spec/001 — RETROSPECTIVE)

  # Covers: REQ-001, REQ-002, REQ-003, REQ-004, REQ-005, REQ-006, REQ-007, REQ-008, REQ-009, REQ-010, REQ-011, REQ-012, REQ-013, REQ-014, REQ-015, REQ-016, REQ-017, REQ-018, REQ-019, REQ-020, REQ-021, REQ-022, REQ-023, REQ-024

  Background:
    Given a CubeOS Pi running docker swarm in single-node mode

  # REQ-002 — image: localhost:5000/ enforcement
  Scenario: Compose file with non-localhost image fails smoke test
    Given a compose file with image: docker.io/foo/bar:latest
    When scripts/smoke-test.sh --check-only runs
    Then it exits non-zero
    And the error line cites parent Article XIV

  # REQ-005 — smoke test catches localhost violation
  Scenario: Smoke test passes when every image is localhost:5000-prefixed
    When scripts/smoke-test.sh --check-only runs against all 13 coreapps
    Then it exits 0

  # REQ-009 + REQ-010 — ci-deploy detects deletions
  Scenario: Removing a coreapp from git tears down its Swarm service on next deploy
    Given coreapp foo was previously deployed
    When ci-deploy.sh runs after foo/ is deleted from git
    Then docker stack rm foo is invoked BEFORE the rsync
    And /cubeos/coreapps/foo/ is pruned post-rsync

  # REQ-011 + REQ-012 — --resolve-image=never
  Scenario: Stack deploy uses local images only
    When ci-deploy.sh deploys cubeos-api
    Then docker stack deploy is invoked with --resolve-image=never
    And Swarm does NOT attempt an external registry pull

  # REQ-013 + REQ-016 — watchdog detects 0/1 replica
  Scenario: Watchdog detects unhealthy coreapp after 2 consecutive failures
    Given cubeos-api service is in state Replicas: 0/1
    When watchdog-health.sh has fired twice (10 min apart)
    Then docker service update --force cubeos-api is invoked
    And /var/lib/cubeos/watchdog-cooldown.json records the action

  # REQ-018 — cooldown
  Scenario: Watchdog cooldown prevents restart loop
    Given cubeos-api was force-restarted 5 min ago
    When watchdog-health.sh runs again and finds 0/1 replicas
    Then NO new docker service update --force is invoked
    And syslog notes "in cooldown until <timestamp>"

  # REQ-021 — defaults/secrets overlap
  Scenario: Smoke test catches secret accidentally moved to defaults.env
    Given JWT_SIGNING_KEY exists in BOTH defaults.env AND /etc/cubeos/secrets.env
    When scripts/smoke-test.sh runs
    Then it exits non-zero
    And the error cites Article C-VI

  # REQ-022 — README sections
  Scenario: Per-coreapp README must have required sections
    Given coreapp foo has README.md without "Port:" section
    When scripts/smoke-test.sh runs
    Then it exits non-zero
    And the error cites Article C-VIII

  # REQ-023 + REQ-024 — out of scope
  Scenario: Spec does NOT cover host-level service management
    Then host-level services are explicitly out of scope (HAL handles them)

  Scenario: Spec does NOT cover multi-box Swarm
    Then multi-node Swarm orchestration is explicitly out of scope (single-Pi target)
