# Internal Deployment Initializer Tool Plan

## 1) Goal and Scope
Build a lightweight internal web application that helps operators initialize a production deployment by:
- collecting required credentials/secrets and deployment settings,
- exposing optional feature toggles and advanced configuration,
- validating inputs (schema + business rules),
- testing external API credentials via a Python backend,
- generating deployment-ready configuration artifacts,
- allowing a final **Deploy** action to provision/update AWS resources,
- supporting a full **mock/dry-run mode** for safe rehearsals.

## 2) Primary User Flow
1. **Start Session**
   - User opens the tool and creates a “deployment init session” (e.g., environment = `prod-us-east-1`).
2. **Required Inputs**
   - User enters mandatory values: AWS account/region, app-level secrets, third-party API keys, domain/base URLs, etc.
3. **Optional Configuration**
   - User chooses optional modules/features and sets advanced parameters.
4. **Validation + Credential Tests**
   - Backend validates structure and constraints.
   - Backend performs live API key checks (where supported).
5. **Review + Generate Config**
   - Tool shows a generated config diff/preview and a checklist of unresolved issues.
6. **Deploy**
   - If all required checks pass, user triggers deployment workflow for AWS resources.
7. **Audit Output**
   - Tool stores logs, generated artifacts metadata, and operation status.

## 3) Suggested Architecture
### Frontend (simple web UI)
- **Stack**: React + TypeScript (or plain server-rendered pages if speed is preferred).
- **Responsibilities**:
  - Dynamic forms for required/optional settings.
  - Inline validation feedback.
  - “Test keys” actions and status indicators.
  - Review screen with generated config preview.
  - Deploy button + real-time progress/events.

### Backend (Python)
- **Stack**: FastAPI + Pydantic.
- **Responsibilities**:
  - Strong input validation.
  - Secret handling + secure persistence strategy.
  - API key test adapters (per provider).
  - Config generation engine.
  - Deployment orchestration (AWS SDK/CLI wrappers).
  - Dry-run simulation mode.

### Data & State
- Session-based model persisted in DB (Postgres or DynamoDB).
- Secrets stored in AWS Secrets Manager (or encrypted at rest in DB for temporary drafts).
- Generated artifacts written to S3 (or secure internal storage) with versioning metadata.

## 4) Configuration Model Design
Define a canonical typed model (single source of truth), e.g.:
- `DeploymentContext`: environment, region, account, app name.
- `RequiredSecrets`: DB password, signing keys, API tokens.
- `OptionalFeatures`: booleans/enums for optional modules.
- `FeatureConfig`: per-module advanced settings.
- `DeploymentOptions`: scaling, networking, observability options.

Use this model to drive:
- UI form rendering,
- backend validation,
- generated config files,
- deploy pipeline variable mapping.

## 5) Validation Strategy
### Layer 1: Schema Validation
- Type checks, required fields, formats, bounds.

### Layer 2: Cross-field/Business Validation
- Conditional requirements (e.g., if `feature_x=true`, require `feature_x_api_key`).
- Environment-specific rules (prod stricter than non-prod).

### Layer 3: External Credential Validation
- Provider-specific endpoint calls to verify key/token validity.
- Capture test results, timestamps, and sanitized error messages.

### Layer 4: Deploy Readiness Gate
- “Ready to deploy” only when all blocking checks pass.
- Non-blocking warnings surfaced separately.

## 6) API Key Testing (Python backend)
Implement a pluggable adapter interface:
- `test_credentials(provider: str, payload: dict) -> TestResult`
- Adapters for each provider (OpenAI, Stripe, internal APIs, etc.).

Design notes:
- Use short timeouts + retries for transient issues.
- Never log raw secrets.
- Return normalized status: `pass | fail | warning | unknown`.

## 7) Config Generation
Generate deterministic artifacts from validated model:
- `.env` templates (without exposing secret values in logs/UI),
- service config YAML/JSON,
- IaC parameter files (Terraform vars / CloudFormation params),
- optional runbook summary.

Include:
- Preview/diff before write,
- Artifact version stamp,
- Hash/signature for auditability.

## 8) Deploy Execution (AWS)
Provide a backend deploy orchestrator with stages:
1. Preflight checks (AWS identity, permissions, quotas, naming collisions).
2. Plan/build (IaC plan or change set).
3. Apply/provision.
4. Post-deploy health checks.
5. Final summary (outputs/endpoints/resources created).

Operational controls:
- Idempotent deployment requests.
- Concurrency lock per environment.
- Rollback or compensating steps where possible.

## 9) Dry-Run / Mock Mode
Support two safe rehearsal modes:

### A) Validation-only dry-run
- Runs full input + business + credential simulation checks.
- Skips real AWS changes.
- Produces “would-generate” and “would-deploy” report.

### B) Full mock mode
- Uses mocked provider clients and mocked AWS layer.
- Simulates successful/failed branches for test/training.
- Returns synthetic resource IDs and status events.

Implementation options:
- Backend flag per session: `execution_mode = live | dry_run | mock`.
- Abstraction layer for cloud/provider clients so live and mock implementations share interface.

## 10) Security and Compliance
- Enforce SSO + RBAC (operator/admin roles).
- Encrypt secrets in transit and at rest.
- Strict secret redaction in logs and UI.
- Audit trail for every change, validation run, and deployment action.
- Optional “two-person approval” before live deploy.

## 11) Observability
- Structured logs with correlation/session IDs.
- Metrics: validation failures, deploy duration, success rate.
- Event timeline per deployment session.
- Alerting for failed deploys or repeated credential test failures.

## 12) Delivery Plan (Phased)
### Phase 1: Foundations
- Canonical config schema.
- Basic UI for required inputs.
- Backend validation endpoints.
- Artifact generation (single config output).

### Phase 2: Optionality + Credential Testing
- Dynamic optional feature forms.
- Adapter-based API key tests.
- Readiness gate and review screen.

### Phase 3: AWS Deploy + Dry-run
- Deploy orchestration pipeline.
- Dry-run and mock implementations.
- Deployment logs/events UI.

### Phase 4: Hardening
- RBAC/SSO, audit features, approval workflow.
- Robust error handling and rollback strategies.
- Performance/security testing.
- Go-live readiness artifacts: signed checklist + launch/rollback plan (`deployment_initializer/docs/GO_LIVE_HARDENING_CHECKLIST.md`, `deployment_initializer/docs/LAUNCH_PLAN_AND_ROLLBACK.md`).

## 13) Suggested Initial API Endpoints
- `POST /sessions` – create deployment init session
- `GET /sessions/{id}` – fetch session state
- `PUT /sessions/{id}/config` – update inputs/options
- `POST /sessions/{id}/validate` – run all validations
- `POST /sessions/{id}/test-credentials` – run provider checks
- `POST /sessions/{id}/generate` – produce config artifacts
- `POST /sessions/{id}/deploy` – deploy (live/dry-run/mock)
- `GET /sessions/{id}/events` – retrieve progress timeline

## 14) Risks and Mitigations
- **Risk**: Secret leakage in logs/UI.
  - **Mitigation**: centralized redaction utilities and secret scanning tests.
- **Risk**: Non-idempotent deploy actions.
  - **Mitigation**: deployment lock + idempotency keys.
- **Risk**: Provider test endpoints are flaky.
  - **Mitigation**: retry strategy + explicit “unknown” state handling.
- **Risk**: Drift between generated config and IaC expectations.
  - **Mitigation**: contract tests on generated parameter files.

## 15) Success Criteria
- Operator can complete end-to-end setup without editing files manually.
- 100% required fields validated before deploy.
- Credential tests integrated for all required third-party services.
- Deploy action supports live + dry-run + mock modes.
- Full auditability for security and operations teams.
