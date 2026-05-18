# iCloud Mount Implementation Tickets

This backlog decomposes `docs/icloud-mount-integration-plan.md` into implementation-ready tickets.

## Conventions

- Priority: `P0` (must-have), `P1` (high), `P2` (nice-to-have)
- Size: `S` (≤2 days), `M` (3–5 days), `L` (1+ sprint)
- Type: `Architecture`, `Backend`, `Frontend`, `Security`, `Ops`, `QA`

---

## Epic A — Decision, Compliance, and Threat Model

### ICLOUD-001 — ADR: iCloud access approach decision
- **Type:** Architecture
- **Priority:** P0
- **Size:** M
- **Artifact:** `docs/adr/0001-icloud-access-approach-for-mvp.md`
- **Description:** Create an architecture decision record selecting one supported iCloud approach for MVP:
  - server-side credential/session integration, or
  - desktop connector agent model.
- **Acceptance Criteria:**
  - ADR in `docs/adr/` with chosen approach, rejected alternatives, and rollback path.
  - Explicitly documents API/legal constraints and operational risks.
  - Sign-off from eng + security stakeholders.
- **Dependencies:** None

### ICLOUD-002 — Security threat model for iCloud mount
- **Type:** Security
- **Priority:** P0
- **Size:** M
- **Artifact:** `docs/icloud-mount-threat-model.md`
- **Description:** Produce STRIDE-style threat model for credential intake, storage, and mounted file access.
- **Acceptance Criteria:**
  - Threat model doc includes data-flow diagram and trust boundaries.
  - Mitigations mapped to controls and owners.
  - Residual risks and compensating controls documented.
- **Dependencies:** ICLOUD-001

### ICLOUD-003 — Credential retention + revocation policy
- **Type:** Security
- **Priority:** P0
- **Size:** S
- **Artifact:** `docs/icloud-mount-credential-retention-revocation-policy.md`
- **Description:** Define policy for what credential/session material is stored, retention duration, and revocation triggers.
- **Acceptance Criteria:**
  - Policy doc approved by security.
  - Concrete retention TTLs and audit obligations defined.
  - Revocation workflow mapped to API and support runbook.
- **Dependencies:** ICLOUD-002

---

## Epic B — Mount Framework (Provider-Agnostic)

### ICLOUD-010 — Introduce storage provider interface
- **Type:** Backend
- **Priority:** P0
- **Size:** L
- **Artifact:** `app/services/filemanager_provider.py`, `tests/test_filemanager_provider_dispatch.py`
- **Description:** Refactor filemanager service to a provider interface (`list/stat/read/write/delete/mkdir/move`) with S3-backed default implementation.
- **Acceptance Criteria:**
  - Existing `/v1/fs/*` behavior unchanged for non-mounted paths.
  - Provider interface and base dispatch module merged.
  - Unit tests cover dispatch and fallback behavior.
- **Dependencies:** ICLOUD-001

### ICLOUD-011 — Mount metadata schema + persistence
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Artifact:** `app/services/filemanager_mounts.py`, `scripts/migrations/20260306_filemgr_mounts_schema.py`, `tests/test_filemanager_mounts.py`
- **Description:** Create mount records (owner, provider, mount path, status, secret ref, timestamps).
- **Acceptance Criteria:**
  - DDB schema/indexes defined + migration applied.
  - CRUD service methods implemented with validation (unique mount path per user).
  - Tests for create/read/update/delete and invalid states.
- **Dependencies:** ICLOUD-010

### ICLOUD-012 — Path-to-mount resolution in file operations
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Artifact:** `app/routers/filemanager.py`, `app/services/filemanager_mounts.py`, `app/services/filemanager_provider.py`, `tests/test_filemanager_routes.py`, `tests/test_filemanager_mounts.py`
- **Description:** Resolve mount by path prefix and route operations to provider.
- **Acceptance Criteria:**
  - Requests under mount path route to remote provider.
  - Non-mounted paths continue using default provider.
  - Collision/protected path edge cases covered by tests.
- **Dependencies:** ICLOUD-011

### ICLOUD-013 — Provider-aware audit and usage metering
- **Type:** Backend
- **Priority:** P1
- **Size:** M
- **Artifact:** `app/routers/filemanager.py`, `app/metrics.py`, `docs/dashboards/filemanager-provider-ops-dashboard.json`, `tests/test_filemanager_routes.py`
- **Description:** Add provider/mount dimensions to audit events and metering for list/read/write/delete operations.
- **Acceptance Criteria:**
  - Audit events include `provider`, `mount_id`, and target path.
  - Metrics emit operation counts/latency segmented by provider.
  - Dashboard queries updated for new dimensions.
- **Dependencies:** ICLOUD-012

---

## Epic C — Credential Onboarding & Secrets

### ICLOUD-020 — Secrets manager integration for mount credentials
- **Type:** Security
- **Priority:** P0
- **Size:** M
- **Artifact:** `app/services/filemanager_mount_secrets.py`, `app/core/aws_clients.py`, `app/core/aws.py`, `app/metrics.py`, `tests/test_filemanager_mount_secrets.py`, `docs/dashboards/filemanager-mount-secrets-dashboard.json`
- **Description:** Implement secure storage/retrieval for iCloud auth artifacts in AWS Secrets Manager + KMS.
- **Acceptance Criteria:**
  - Secrets stored encrypted with least-privilege IAM policies.
  - Secret references (not secret contents) saved in mount records.
  - Secret access logged and monitored.
- **Dependencies:** ICLOUD-003, ICLOUD-011

### ICLOUD-021 — API: initiate iCloud mount onboarding
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Artifact:** `app/routers/filemanager.py`, `app/services/filemanager_mount_onboarding.py`, `app/services/rate_limit.py`, `tests/test_filemanager_routes.py`
- **Description:** Implement `POST /v1/fs/mounts/icloud/initiate` for onboarding session creation and preliminary credential validation.
- **Acceptance Criteria:**
  - Endpoint validates request shape and rate limits attempts.
  - No sensitive data appears in logs/errors.
  - Returns onboarding session id + next action state.
- **Dependencies:** ICLOUD-020

### ICLOUD-022 — API: verify/challenge completion
- **Type:** Backend
- **Priority:** P0
- **Size:** M
- **Description:** Implement `POST /v1/fs/mounts/icloud/verify` to handle MFA/challenge steps and activate mount.
- **Acceptance Criteria:**
  - Handles `mfa_required`, `auth_failed`, `active` outcomes.
  - Activates mount record only on successful verification.
  - Retry policy and lockout thresholds enforced.
- **Dependencies:** ICLOUD-021

### ICLOUD-023 — API: rotate/revoke credentials
- **Type:** Backend
- **Priority:** P1
- **Size:** S
- **Description:** Implement credential rotation and explicit revoke endpoints/process.
- **Acceptance Criteria:**
  - Rotation updates secret reference atomically.
  - Revoke disables mount and clears active sessions.
  - Audit entries emitted for both actions.
- **Dependencies:** ICLOUD-022

---

## Epic D — iCloud Provider Adapter

### ICLOUD-030 — Implement iCloud provider skeleton (read-only)
- **Type:** Backend
- **Priority:** P0
- **Size:** L
- **Description:** Add `ICloudProvider` with read-only list/stat/read contract under feature flag.
- **Acceptance Criteria:**
  - Supports mounted path browse + file download.
  - Provider-specific error mapping to stable API errors.
  - Contract tests pass against mock iCloud transport.
- **Dependencies:** ICLOUD-012, ICLOUD-022

### ICLOUD-031 — Error taxonomy and retry/backoff policy
- **Type:** Backend
- **Priority:** P1
- **Size:** M
- **Description:** Classify provider failures (`auth_expired`, `mfa_required`, `throttled`, transient, permanent).
- **Acceptance Criteria:**
  - Unified error mapper used by provider calls.
  - Exponential backoff on retryable failures.
  - Non-retryable failures surface actionable error codes.
- **Dependencies:** ICLOUD-030

### ICLOUD-032 — Implement write/delete/move for iCloud provider
- **Type:** Backend
- **Priority:** P0
- **Size:** L
- **Description:** Add write-path support and commit semantics with conflict policy support.
- **Acceptance Criteria:**
  - Upload/write/delete/move work for mounted paths.
  - Conflict policy per mount: `fail`, `rename`, `last_write_wins`.
  - Idempotency key support prevents duplicate writes.
- **Dependencies:** ICLOUD-030, ICLOUD-031

### ICLOUD-033 — Optional hot-file read cache
- **Type:** Backend
- **Priority:** P2
- **Size:** M
- **Description:** Add temporary cache layer for large/frequently accessed iCloud files.
- **Acceptance Criteria:**
  - Cache hit/miss metrics available.
  - Cache invalidation on writes/moves/deletes.
  - Feature flag for enable/disable.
- **Dependencies:** ICLOUD-030

---

## Epic E — Frontend (Files UX)

### ICLOUD-040 — “Connect iCloud” onboarding wizard UI
- **Type:** Frontend
- **Priority:** P0
- **Size:** M
- **Description:** Add UI flow for initiate + verify endpoints, including challenge handling and error states.
- **Acceptance Criteria:**
  - User can complete onboarding from Files page.
  - MFA/challenge states are represented clearly.
  - Sensitive fields masked and never persisted in client logs.
- **Dependencies:** ICLOUD-021, ICLOUD-022

### ICLOUD-041 — Mount management panel
- **Type:** Frontend
- **Priority:** P1
- **Size:** M
- **Description:** Add list/status/rotate/revoke actions for mounts.
- **Acceptance Criteria:**
  - Displays status badges (`active`, `degraded`, `re-auth required`, `revoked`).
  - Action buttons for rotate/reconnect/disconnect.
  - Permission-aware rendering and optimistic refresh.
- **Dependencies:** ICLOUD-023

### ICLOUD-042 — Provider badging in file browser
- **Type:** Frontend
- **Priority:** P1
- **Size:** S
- **Description:** Show provider badge/icon for mounted files/folders and route operations appropriately.
- **Acceptance Criteria:**
  - iCloud-mounted nodes visually distinguished.
  - Breadcrumb and path actions preserve mount context.
  - Snapshot/unit tests updated.
- **Dependencies:** ICLOUD-030

---

## Epic F — Reliability, Observability, and Ops

### ICLOUD-050 — Provider health metrics + dashboards
- **Type:** Ops
- **Priority:** P1
- **Size:** M
- **Description:** Add metrics for operation volume, latency, error class, and auth failures by provider/mount.
- **Acceptance Criteria:**
  - Dashboard panels for p50/p95 latency and error rates.
  - Alert thresholds for sustained auth failures and 5xx rates.
  - Runbook links embedded in dashboard descriptions.
- **Dependencies:** ICLOUD-013, ICLOUD-031

### ICLOUD-051 — Mount degradation/circuit breaker
- **Type:** Backend
- **Priority:** P1
- **Size:** M
- **Description:** Automatically mark mounts degraded/read-only/unavailable after repeated failures.
- **Acceptance Criteria:**
  - State transition policy implemented and tested.
  - User-visible status updated within defined SLA.
  - Auto-recovery and manual override supported.
- **Dependencies:** ICLOUD-031

### ICLOUD-052 — Reconciliation job for remote/local drift
- **Type:** Backend
- **Priority:** P2
- **Size:** L
- **Description:** Background job compares cached/indexed metadata with provider state and repairs drift.
- **Acceptance Criteria:**
  - Scheduled job with incremental scan cursor.
  - Drift report and correction actions logged.
  - Safe-mode dry-run capability.
- **Dependencies:** ICLOUD-032

### ICLOUD-053 — Operational runbooks and on-call playbook
- **Type:** Ops
- **Priority:** P1
- **Size:** S
- **Description:** Document incident handling for auth storms, provider outages, and credential compromise.
- **Acceptance Criteria:**
  - Runbooks committed under `docs/`.
  - Paging criteria + escalation matrix defined.
  - Recovery and customer-comms templates included.
- **Dependencies:** ICLOUD-050

---

## Epic G — Testing, Rollout, and Release

### ICLOUD-060 — Provider contract test suite
- **Type:** QA
- **Priority:** P0
- **Size:** M
- **Description:** Build a reusable provider contract test suite run against S3 provider and iCloud provider mock.
- **Acceptance Criteria:**
  - Contract enforces operation parity and expected error semantics.
  - Executed in CI for both providers.
  - Flake-free for 10 consecutive CI runs.
- **Dependencies:** ICLOUD-010, ICLOUD-030

### ICLOUD-061 — Failure-injection integration tests
- **Type:** QA
- **Priority:** P1
- **Size:** M
- **Description:** Add integration tests for MFA challenges, expired auth, throttling, and partial write failure.
- **Acceptance Criteria:**
  - Test cases validate recovery/retry behaviors.
  - Circuit breaker transitions verified.
  - Re-auth UX path validated end-to-end.
- **Dependencies:** ICLOUD-031, ICLOUD-040

### ICLOUD-062 — Feature flag + staged rollout controls
- **Type:** Backend/Ops
- **Priority:** P0
- **Size:** S
- **Description:** Implement `filemgr_icloud_mount_enabled` controls by environment and tenant.
- **Acceptance Criteria:**
  - Flag configurable without deploy.
  - Rollout cohorts supported (internal/beta/ga).
  - Kill-switch tested.
- **Dependencies:** ICLOUD-030

### ICLOUD-063 — Beta launch checklist
- **Type:** Ops
- **Priority:** P1
- **Size:** S
- **Description:** Create go/no-go checklist for internal dogfood and external beta.
- **Acceptance Criteria:**
  - Checklist covers SLOs, alerting, support readiness, legal copy, and rollback plan.
  - Stakeholder sign-offs tracked.
- **Dependencies:** ICLOUD-050, ICLOUD-061, ICLOUD-062

---

## Suggested Sprint Sequencing

- **Sprint 1:** ICLOUD-001, 002, 003, 010 (start), 011
- **Sprint 2:** ICLOUD-010 (finish), 012, 013, 020, 021, 060 (start)
- **Sprint 3:** ICLOUD-022, 030, 031, 040, 062
- **Sprint 4:** ICLOUD-032, 041, 042, 050, 051, 061
- **Sprint 5+:** ICLOUD-023, 052, 053, 033, 063

## MVP Cutline

For an initial **read-only beta**:

- Must-have: ICLOUD-001, 002, 003, 010, 011, 012, 020, 021, 022, 030, 031, 040, 050, 060, 062
- Deferred to post-beta: write-path tickets (ICLOUD-032+), cache, reconciliation.
