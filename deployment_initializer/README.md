# Deployment Initializer (TKT-001 Scaffold)

This directory contains the initial monorepo-style scaffold for the internal deployment initializer tool.

## Structure
- `frontend/`: React + TypeScript UI shell.
- `backend/`: FastAPI + Pydantic API scaffold.
- `infra/`: IaC wrapper placeholders for plan/deploy stages.

## Quick Start

### Frontend
```bash
cd deployment_initializer/frontend
npm ci
npm run dev
```

Expected: a placeholder page titled **Deployment Initializer UI**.

### Backend
```bash
python -m pip install -r deployment_initializer/backend/requirements.txt
uvicorn app.main:app --reload --port 8001 --app-dir deployment_initializer/backend
```

Expected: `GET http://127.0.0.1:8001/health` returns `{"status":"ok"}`.

### Convenience Make targets
```bash
cd deployment_initializer
make frontend-install frontend-lint frontend-test
make backend-install backend-test
```

## CI
A dedicated GitHub Actions workflow (`.github/workflows/deployment-initializer-ci.yml`) runs:
- frontend lint + tests
- backend unit tests


## TKT-002 session persistence baseline
- `POST /sessions`: create a deployment session.
- `GET /sessions/{session_id}`: fetch a session.
- `PUT /sessions/{session_id}`: update metadata/config/status/execution mode.
- Status transitions are validated server-side (`draft -> validated -> ready -> deploying -> deployed`, with `failed` recovery paths).
- SQLite-backed persistence is enabled by default and auto-migrates from `backend/migrations/001_create_deployment_sessions.sql`.
- Override DB path with `DEPLOYMENT_SESSIONS_DB_PATH`.


## TKT-003 canonical typed config model
- Canonical model is `DeploymentConfigV1` in `backend/app/config_schema.py` and is used by session create/update APIs.
- The model includes typed sections for:
  - `deployment_context`
  - `required_secrets`
  - `optional_features`
  - `feature_config`
  - `deployment_options`
- Machine-readable JSON Schema is available at `GET /config/schema` and can be exported to frontend artifacts:
  - `make backend-export-schema`
  - output file: `frontend/schemas/deployment-config.schema.v1.json`
- Versioning strategy: schema uses semantic versioning (`schema_version`).
  - Major changes may introduce `DeploymentConfigV2`.
  - Minor/patch changes are backward-compatible additive changes within the same major version.


## TKT-004 multi-layer validation engine
- Validation endpoint: `POST /sessions/{session_id}/validate`
- Validation layers:
  1. `schema` (schema-version compatibility checks)
  2. `business` (cross-field conditional rules)
  3. `readiness` (deploy gate aggregation rules)
- Response includes:
  - `ready_to_deploy`
  - `blocking_issue_count`
  - `warning_count`
  - structured `issues[]` with stable `code`, `severity`, `layer`, `message`, and optional `path`
- Warnings do not block readiness; errors are blocking.


## TKT-005 required-input form UI
- Required form sections are implemented in `frontend/src/App.tsx`:
  - session metadata
  - deployment context
  - required secrets
  - required deployment options
- Inline field-level validation is shown immediately, and form-level validation summary updates live.
- Autosave behavior:
  - local draft is persisted in browser storage on every change
  - valid drafts autosave to backend session via `POST /sessions` (create) and `PUT /sessions/{id}` (update)
  - session ID is cached and restored so refresh reloads the existing session state


## TKT-006 optional features and advanced settings UI
- Optional module toggles are rendered dynamically from schema metadata (`frontend/schemas/deployment-config.schema.v1.json`) with fallback defaults.
- Enabling a module reveals its advanced settings panel:
  - Helpdesk: routing queue, auto-assign
  - Messaging: retention days, external sharing
  - File Manager: max upload size, virus scan
  - Alerting: Slack webhook, email notifications
  - Signature Packets: reminder interval
- Disabling a module hides its advanced fields and deactivates module-specific validations.
- Optionality guidance is exposed with inline help text/tooltips per module and setting.


## TKT-007 review screen with config preview/diff
- Added a final **Review & Deploy** section in `frontend/src/App.tsx` with:
  - validation summary controls (`Run validation summary`) and actionable issue lists
  - readiness checklist showing unresolved blocking items before deploy
  - artifact preview generation with output names, schema versions, and content hashes
  - config diff preview table (`before` vs `after`) based on generated payload snapshots
- Added entry-point actions:
  - `Generate artifact preview`
  - `Deploy (entry point)` (disabled until blocking issues are resolved)


## TKT-008/TKT-009 credential adapter framework
- Credential adapters are defined in `backend/app/services/provider_credentials.py` via a pluggable protocol (`CredentialAdapter`) and registry (`CredentialAdapterRegistry`).
- Initial providers implemented:
  - `openai`
  - `stripe`
- Credential test endpoint:
  - `POST /sessions/{session_id}/test-credentials`
  - optional body: `{ "providers": ["openai", "stripe"] }`
- Normalized statuses returned per provider:
  - `pass`, `fail`, `warning`, `unknown`
- Timeout/retry policy is configurable via env vars:
  - `CREDENTIAL_TEST_TIMEOUT_SECONDS`
  - `CREDENTIAL_TEST_MAX_RETRIES`
  - `CREDENTIAL_TEST_RETRY_BACKOFF_SECONDS`
- Unknown providers return structured non-500 results (`status=unknown`).


## TKT-010 deterministic artifact generation
- Artifact generation endpoint:
  - `POST /sessions/{session_id}/generate`
- Generated outputs:
  - `.env.template`
  - `service.config.json`
  - `iac.params.json`
- Generator guarantees deterministic byte-stable content for the same input (canonical ordering/serialization).
- Response includes artifact metadata per output:
  - `version`
  - `hash`
  - `generated_at`
- Generation runs are persisted in SQLite (`artifact_generation_runs`) with hashes and contents.


## TKT-011 artifact storage and retrieval
- Storage abstraction implemented in `backend/app/services/artifact_storage.py`.
- Current implementation uses local file-backed storage (`LocalArtifactStorage`) with signed token support.
- Generation writes artifacts to storage and records trace metadata (`run_id`, `name`, `version`, `hash`, `generated_at`, `storage_key`) in DB.
- Retrieval flow:
  - `GET /sessions/{session_id}/artifacts` (authorized caller only; created_by or admin role)
  - returns signed download URLs for artifacts
  - `GET /sessions/artifacts/download?...` validates token + record and returns artifact content
- Access control headers:
  - `X-Operator-Email` (must match session creator) or
  - `X-Operator-Role: admin`


## TKT-012 deploy orchestrator pipeline (live mode)
- Live deploy endpoint:
  - `POST /sessions/{session_id}/deploy`
- Pipeline stages execute in order and emit persisted stage events:
  1. `preflight_checks`
  2. `plan_change_set`
  3. `apply_changes`
  4. `post_deploy_checks`
- Fail-fast behavior:
  - A failed stage stops downstream execution.
  - Session status transitions to `failed` and returns actionable stage error message.
- Success behavior:
  - Session transitions `deploying -> deployed`.
  - Final response includes created resource outputs (e.g., `stack_name`, `api_url`, `artifact_bucket`) and health summary.
- Stage events are persisted in SQLite table `deploy_stage_events` (migration `004_create_deploy_stage_events.sql`) and traceable by `session_id` + `run_id`.


## TKT-013 idempotency and environment locking
- Deploy endpoint now supports idempotency via request header:
  - `Idempotency-Key`
- Duplicate deploy requests with the same key for the same session are safely deduplicated and return the original persisted deploy response.
- Environment lock manager prevents concurrent deploys for the same `(env, region)` pair.
- Conflict semantics:
  - when a lock already exists, `POST /sessions/{session_id}/deploy` returns `409` with deterministic detail code `environment_deploy_locked`.
- Persistence tables added:
  - `deploy_idempotency_records`
  - `deploy_environment_locks`


## TKT-014 validation-only dry-run mode
- `execution_mode: dry_run` is supported on `POST /sessions/{session_id}/deploy`.
- Dry-run behavior:
  - runs full validation summary
  - simulates deterministic artifact generation report
  - simulates deploy stage report with "SIMULATED:" event messages and would-do steps
- No real cloud mutations are performed in dry-run responses; output is explicitly marked with `simulated: true`.
- Session status is not transitioned to `deploying`/`deployed` for dry-run requests.


## TKT-015 full mock mode with synthetic outcomes
- `execution_mode: mock` is supported on `POST /sessions/{session_id}/deploy`.
- Mock mode uses shared mock cloud/provider execution clients to return synthetic deploy stage events and resource identifiers.
- Scenario control header:
  - `X-Mock-Scenario` (`success`, `plan_failure`, `apply_failure`, `post_deploy_failure`)
- Scenario fixtures are deterministic and allow reproducible success/failure branches for training/testing.
- Mock responses are explicitly marked with `simulated: true` and include `synthetic_outputs`.


## TKT-016 secret handling and redaction safeguards
- Centralized redaction utility (`backend/app/services/redaction.py`) masks `required_secrets` in session API payloads.
- Session create/get/update responses are redacted and never return plaintext secret values.
- Secret storage abstraction is integrated through session-store secret methods and backed by `session_secrets` persistence (migration `006_create_session_secrets.sql`).
- Credential tests read secrets from secret storage instead of client-facing payloads.
- Security regression tests (`backend/tests/test_security_redaction.py`) fail if plaintext secrets appear in critical API responses.


## TKT-017 AuthN/AuthZ (SSO + RBAC)
- Added auth middleware dependency for session APIs via `backend/app/services/auth.py`.
- Supported identity inputs:
  - `Authorization: Bearer sso:<email>:<role>`
  - or headers `X-SSO-Email` + `X-SSO-Role`
- Supported roles: `viewer`, `operator`, `admin`.
- RBAC policy highlights:
  - session/deploy/generate/credential-test mutations require `operator` or `admin`
  - deploy action is restricted to `operator`/`admin` only
  - artifact retrieval is additionally owner-or-admin scoped
- Unauthorized requests return `401 unauthorized`; insufficient role returns `403 forbidden_insufficient_role`.


## TKT-018 audit trail and approvals
- Immutable audit event capture is enabled for key actions (`session.create`, `session.update`, `session.validate`, `credentials.test`, `artifacts.generate`, deploy actions) with actor + timestamp metadata.
- Audit query endpoint:
  - `GET /sessions/{session_id}/audit-events`
- Deploy approval workflow endpoint:
  - `POST /sessions/{session_id}/approvals`
- Optional two-person approval gate for live deploy is controlled by env var:
  - `DEPLOY_REQUIRE_TWO_PERSON_APPROVAL=true`
- When policy is enabled, live deploy is blocked with deterministic `approval_required` response until two distinct approvals exist.


## TKT-019 deployment event timeline and status stream
- Session/deploy events are persisted and available via:
  - `GET /sessions/{session_id}/events`
- Timeline response includes merged audit events and deploy stage events sorted by timestamp for post-completion history and live polling.
- Frontend Review & Deploy page now includes a **Deployment event timeline** component that polls `/sessions/{id}/events` and updates progress/failure visibility in near-real time.


## TKT-020 metrics, alerts, and dashboards
- Ops metrics instrumentation is available via admin-only endpoints:
  - `GET /ops/metrics`
  - `GET /ops/alerts`
  - `GET /ops/dashboard-template`
- Instrumented metrics include:
  - `validation_failures_total`
  - deploy duration average (`deploy_duration_avg_seconds`)
  - deploy success/failure totals and success rate
- Alerting threshold controls:
  - `DEPLOY_FAILURE_ALERT_THRESHOLD`
  - `DEPLOY_FAILURE_ALERT_WINDOW_MINUTES`
- Repeated deploy failures trigger `repeated_deploy_failures` alert payloads including runbook links.


## TKT-021 end-to-end test suite (live-safe + mock)
- Added deterministic backend E2E suite: `backend/tests/test_e2e_flow.py`.
- Core flow coverage includes:
  - create session
  - configure required/optional inputs
  - validate
  - test credentials
  - generate artifacts
  - deploy (`dry_run` and `mock`)
- Includes deterministic failure-branch scenario for mock deploy (`X-Mock-Scenario: apply_failure`) with actionable assertion diagnostics.
- Added CI E2E stage `backend-e2e` in `.github/workflows/deployment-initializer-ci.yml`.
- Added local make target: `make backend-e2e`.

## TKT-022 go-live hardening checklist
- Added signed-off production readiness checklist:
  - `docs/GO_LIVE_HARDENING_CHECKLIST.md`
- Added approved launch + rollback plan:
  - `docs/LAUNCH_PLAN_AND_ROLLBACK.md`
- Checklist covers:
  - threat model review
  - load/performance smoke validation
  - backup/recovery rehearsal verification
  - on-call/runbook handoff completion
  - stakeholder sign-off (Engineering, Security, Operations)
- Launch plan defines:
  - phased rollout gates
  - SLO-based promotion criteria
  - explicit rollback triggers
  - rollback execution steps and communications plan
  - rehearsal evidence expectations
