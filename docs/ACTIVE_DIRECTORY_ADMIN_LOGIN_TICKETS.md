# Active Directory Admin Login — Implementation Tickets

This ticket set operationalizes `docs/ACTIVE_DIRECTORY_ADMIN_LOGIN_PLAN.md` into executable work items for backend, frontend, security, and operations.

## Epic AD-1: Discovery, Security Baseline, and Architecture

### AD-001 — Identity topology discovery and protocol decision
**Type:** Research / Architecture
**Priority:** P0
**Dependencies:** None

**Scope**
- Confirm target deployment shapes (on-prem AD, hybrid, Entra-only).
- Document customer requirements for OIDC vs SAML.
- Produce ADR for protocol sequencing (OIDC-first, SAML follow-up if required).

**Deliverables**
- Architecture Decision Record (ADR) with approved protocol strategy.
- Tenant capability matrix and assumptions.

**Acceptance Criteria**
- ADR approved by security + platform owners.
- Required identity claims and tenant constraints documented.

---

### AD-002 — Threat model and security controls definition
**Type:** Security
**Priority:** P0
**Dependencies:** AD-001

**Scope**
- Threat-model admin SSO flows (state/nonce, replay, signature bypass, role escalation).
- Define mandatory controls for token/assertion validation and key rotation.
- Define break-glass root access policy.

**Deliverables**
- Security threat model document.
- Control checklist mapped to implementation tasks.

**Acceptance Criteria**
- Security sign-off on required controls.
- Explicit “root cannot be assigned via external claims” policy documented.

---

## Epic AD-2: Data Model, Config Storage, and Secrets

### AD-003 — Schema migration for identity providers and external identities
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-002

**Scope**
- Create DB tables for `identity_providers`, `identity_provider_role_mappings`, `external_identities`.
- Add indexes/constraints on `(provider_id, external_subject, external_tenant)`.
- Add migration rollback strategy.

**Deliverables**
- SQL migration(s) and model updates.
- Data access layer methods + unit tests.

**Acceptance Criteria**
- Migrations run forward/backward in CI.
- Uniqueness and foreign-key constraints enforce linkage correctness.

---

### AD-004 — Secure storage model for IdP credentials
**Type:** Feature / Security
**Priority:** P0
**Dependencies:** AD-003

**Scope**
- Integrate client secret/certificate storage with existing secret-store abstraction.
- Persist only references (`secret_ref`) in app database.
- Implement secret validation and rotation hooks.

**Deliverables**
- Secret-store integration service methods.
- Validation errors for missing/invalid secret references.

**Acceptance Criteria**
- No plaintext secret material persisted in DB.
- Secret read/write audit events emitted.

---

## Epic AD-3: Authentication Flow (OIDC-first)

### AD-005 — Admin SSO start endpoint and state/nonce handling
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-004

**Scope**
- Implement `/auth/admin/sso/start` endpoint.
- Generate and store signed state/nonce with expiration.
- Redirect to configured IdP authorization endpoint.

**Deliverables**
- Endpoint + request validation.
- State/nonce store and expiration logic.

**Acceptance Criteria**
- Endpoint rejects disabled/misconfigured providers.
- State and nonce are single-use and expire correctly.

---

### AD-006 — Admin SSO callback endpoint and token validation
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-005

**Scope**
- Implement `/auth/admin/sso/callback` endpoint.
- Validate signature, issuer, audience, nonce, token expiry.
- Normalize external identity claims (`sub`, `email`, `groups`, `tenant_id`).

**Deliverables**
- Callback handler and validation service.
- Structured failure reason codes for audit/metrics.

**Acceptance Criteria**
- Invalid/malformed/expired tokens are rejected with non-200 response.
- Valid callbacks produce normalized identity payload.

---

### AD-007 — External identity linking and session issuance
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-006

**Scope**
- Upsert/link external identity to internal user by immutable `(subject, tenant)`.
- Reuse existing admin session issuance after successful federation.
- Tag session with `auth_method=ad_sso`.

**Deliverables**
- Identity link service.
- Session payload extension + backward-compatible handling.

**Acceptance Criteria**
- Repeated login reuses linked admin identity.
- Session includes `auth_method=ad_sso` marker.

---

## Epic AD-4: Authorization and Role Mapping

### AD-008 — Group/claim to internal role mapping engine
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-007

**Scope**
- Implement deterministic mapping with explicit priority.
- Deny by default when no mapping/default role is configured.
- Add mapping simulation utility for config validation.

**Deliverables**
- Role mapping service + tests.
- Mapping simulation endpoint or internal helper.

**Acceptance Criteria**
- Precedence behavior deterministic across test cases.
- Unmapped users are denied with explicit reason code.

---

### AD-009 — Root-role protection and auth policy guardrails
**Type:** Security
**Priority:** P0
**Dependencies:** AD-008

**Scope**
- Enforce hard rule preventing external assignment of `root` role.
- Preserve local root login as break-glass.
- Add optional policy toggle for “enforce SSO for admins except root”.

**Deliverables**
- Policy checks in auth pipeline.
- Configurable enforcement flag with defaults.

**Acceptance Criteria**
- Attempted external `root` assignment always rejected.
- Root local login works regardless of SSO enforcement state.

---

## Epic AD-5: Root Admin Configuration API + UI

### AD-010 — Root-only Identity & SSO configuration APIs
**Type:** Feature
**Priority:** P0
**Dependencies:** AD-004

**Scope**
- Add root-protected CRUD endpoints for IdP config and role mappings.
- Validate required fields by protocol type.
- Implement staged lifecycle: `draft -> validated -> active`.

**Deliverables**
- Root-only API endpoints with policy checks.
- Validation schema and protocol-specific validators.

**Acceptance Criteria**
- Non-root principals receive authorization failures.
- Invalid protocol config cannot transition to `active`.

---

### AD-011 — Connection test and staged activation workflow
**Type:** Feature
**Priority:** P1
**Dependencies:** AD-010

**Scope**
- Add “test configuration” API call that performs non-destructive checks.
- Require explicit activate action after successful validation.
- Add rollback endpoint to disable SSO and restore local-only admin login.

**Deliverables**
- Validation/test endpoint.
- Activate/deactivate/rollback workflow endpoints.

**Acceptance Criteria**
- Failed validation blocks activation.
- Rollback action is auditable and effective immediately.

---

### AD-012 — Root admin UI for AD integration settings
**Type:** Feature
**Priority:** P1
**Dependencies:** AD-010, AD-011

**Scope**
- Build root-only “Identity & SSO” admin page.
- Include protocol selection, metadata/client config, role mappings.
- Include save, validate, activate, and rollback actions.

**Deliverables**
- UI route/components and API integration.
- Permission-aware rendering for root-only controls.

**Acceptance Criteria**
- Root can complete end-to-end config lifecycle from UI.
- Non-root users cannot access page or mutate settings.

---

## Epic AD-6: Auditability, Observability, and Operations

### AD-013 — Audit event coverage for auth and config changes
**Type:** Feature / Compliance
**Priority:** P0
**Dependencies:** AD-006, AD-010

**Scope**
- Emit audit events for config create/update/activate/deactivate.
- Emit login success/failure events with reason codes and mapped roles.
- Ensure actor identity and timestamp integrity in logs.

**Deliverables**
- Audit event schema updates.
- Logging instrumentation and persistence.

**Acceptance Criteria**
- All critical actions produce auditable records.
- Events include `auth_method`, provider context, and failure reason when applicable.

---

### AD-014 — Metrics, dashboards, and alerting for admin SSO
**Type:** Ops / Feature
**Priority:** P1
**Dependencies:** AD-013

**Scope**
- Add metrics for SSO login outcomes, callback latency, and config validation failures.
- Define alert thresholds for denial spikes and callback errors.
- Build dashboard panels for support/on-call.

**Deliverables**
- Metrics instrumentation.
- Dashboard + alert configuration.

**Acceptance Criteria**
- Key SSO health metrics visible in dashboard.
- Alert triggers tested in non-prod.

---

### AD-015 — Operational runbooks and incident recovery playbooks
**Type:** Documentation / Operations
**Priority:** P1
**Dependencies:** AD-014

**Scope**
- Write runbooks for key rotation/certificate rollover.
- Document IdP outage procedures and lockout recovery via root account.
- Define escalation path and ownership.

**Deliverables**
- Runbook docs linked from on-call handbook.
- Recovery checklist tested in staging.

**Acceptance Criteria**
- On-call can execute recovery without engineering escalation in tabletop exercise.
- Runbook steps validated against current APIs and UI.

**Implementation Artifacts**
- `docs/ad-admin-sso-oncall-handbook.md`
- `docs/ad-admin-sso-operational-runbook.md`
- `docs/ad-admin-sso-recovery-checklist-staging.md`

---

## Epic AD-7: Testing and Release Management

### AD-016 — Unit/integration/security test suite for AD auth
**Type:** Test
**Priority:** P0
**Dependencies:** AD-006, AD-008, AD-009

**Scope**
- Unit tests for token validation and role mapping precedence.
- Integration tests for SSO start/callback and root-only config authorization.
- Security tests for replay, nonce tampering, signature bypass, privilege escalation.

**Deliverables**
- Automated tests in CI.
- Negative test matrix for common auth failures.

**Acceptance Criteria**
- CI gates on passing auth/security tests.
- Critical bypass scenarios have explicit regression coverage.

**Implementation Artifacts**
- `deployment_initializer/backend/tests/test_admin_sso_unit.py`
- `deployment_initializer/backend/tests/test_admin_sso.py`
- `deployment_initializer/backend/tests/test_admin_sso_config_api.py`
- `deployment_initializer/backend/tests/test_auth.py`
- `docs/ad-admin-sso-negative-test-matrix.md`

---

### AD-017 — E2E rollout validation and feature-flag launch plan
**Type:** Release
**Priority:** P1
**Dependencies:** AD-012, AD-016

**Scope**
- Add E2E scenario: root configures IdP, admin logs in via AD, role enforced.
- Add rollback E2E scenario for IdP outage path.
- Launch with feature flag (`admin_ad_sso`) and pilot tenant sequencing.

**Deliverables**
- E2E suites and release checklist.
- Feature flag rollout stages and abort criteria.

**Acceptance Criteria**
- Pilot runbook includes success metrics and rollback triggers.
- E2E scenarios pass in staging before pilot activation.

**Implementation Artifacts**
- `deployment_initializer/backend/tests/test_admin_sso_e2e_rollout.py`
- `docs/ad-admin-sso-rollout-launch-plan.md`
- `docs/ad-admin-sso-recovery-checklist-staging.md`

---

## Epic AD-8: Local Keycloak Dev Provider

### AD-018 — Local Keycloak host-mode startup and bootstrap
**Type:** DevEx / Infrastructure
**Priority:** P1
**Dependencies:** AD-017

**Scope**
- Add optional host-mode Keycloak startup to local stack scripts.
- Add deterministic bootstrap/seed (realm, client, test users/groups).
- Add health checks for OIDC discovery and JWKS endpoints.

**Deliverables**
- Host-mode startup wiring.
- Seed/bootstrap script(s) with idempotent behavior.

**Acceptance Criteria**
- `DEV_ENABLE_KEYCLOAK=1` brings up Keycloak locally with seeded realm/client/groups.
- Discovery and JWKS endpoints are reachable after bootstrap.

---

### AD-019 — Dev scripts for Keycloak lifecycle and config generation
**Type:** DevEx
**Priority:** P1
**Dependencies:** AD-018

**Scope**
- Add `scripts/local-ad-sso-up.sh` and `scripts/local-ad-sso-down.sh` wrappers.
- Add helper command/script to print root API payload for provider setup from local Keycloak metadata.
- Integrate status output into `scripts/run_dev.sh` when Keycloak mode enabled.

**Deliverables**
- Lifecycle scripts + helper CLI output.
- Updated dev-run status diagnostics.

**Acceptance Criteria**
- Developers can start/stop local Keycloak in one command.
- Generated provider payload works with root provider create/validate flow.

**Implementation Artifacts**
- `scripts/local-ad-sso-up.sh`
- `scripts/local-ad-sso-down.sh`
- `scripts/local-ad-sso-provider-config.py`
- `scripts/run_dev.sh`

---

### AD-020 — Local Keycloak integration tests (real issuer/JWKS)
**Type:** Test / Integration
**Priority:** P0
**Dependencies:** AD-018, AD-019

**Scope**
- Add integration test profile using Keycloak-issued tokens (non-synthetic path).
- Validate callback token checks against real issuer/JWKS metadata.
- Validate group claim mapping with seeded test groups.

**Deliverables**
- Test suite/profile for local-real-IdP flow.
- CI/nightly test target documentation.

**Acceptance Criteria**
- Real-IdP callback test passes in local/staging profile.
- Fail-closed behavior remains validated for invalid issuer/audience/nonce/signature.

**Implementation Artifacts**
- `deployment_initializer/backend/tests/test_admin_sso_keycloak_integration.py`
- `docs/local-dev-stack.md` (local command + profile docs)

---

### AD-021 — Key rotation simulation for local Keycloak
**Type:** Security / Test
**Priority:** P1
**Dependencies:** AD-020

**Scope**
- Add reproducible local key rotation exercise for Keycloak realm keys.
- Validate app behavior across stale key and refreshed key windows.
- Verify audit/metrics for callback failures during rotation.

**Deliverables**
- Rotation drill script/checklist.
- Regression tests/assertions for rotation failure/success windows.

**Acceptance Criteria**
- Rotation drill demonstrates expected failure then recovery without manual DB edits.
- Metrics/alerts reflect callback error conditions during stale key interval.

**Implementation Artifacts**
- `scripts/local-keycloak-rotate-keys.py`
- `deployment_initializer/backend/tests/test_admin_sso_keycloak_rotation.py`
- `docs/ad-admin-sso-key-rotation-drill.md`

---

### AD-022 — Local dev documentation and onboarding path
**Type:** Documentation / DevEx
**Priority:** P1
**Dependencies:** AD-018, AD-019

**Scope**
- Document local Keycloak setup, env vars, and troubleshooting in dev stack docs.
- Add explicit decision tree: fast mock mode vs local Keycloak mode.
- Add sample provider/mapping setup walkthrough for root users.

**Deliverables**
- Updated `docs/local-dev-stack.md` and AD SSO docs.
- Troubleshooting section (ports, realm reset, seed drift).

**Acceptance Criteria**
- New engineer can complete local Keycloak AD SSO setup end-to-end using docs only.
- Troubleshooting section resolves common startup/config errors.

**Implementation Artifacts**
- `docs/local-dev-stack.md`
- `docs/ad-admin-sso-local-keycloak-dev-plan.md`

---



### AD-023 — Optional Samba AD federation spike (non-default)
**Type:** Research / Spike
**Priority:** P2
**Dependencies:** AD-018

**Scope**
- Evaluate Samba AD DC + Keycloak LDAP federation in optional compose profile.
- Validate claim/group mapping parity with enterprise AD-like schema.
- Record complexity, stability, and maintenance trade-offs.

**Deliverables**
- Spike report with recommendation (adopt/defer).
- Optional non-default profile prototype (if viable).

**Acceptance Criteria**
- Team has explicit go/no-go recommendation for maintaining AD bridge mode.
- Risks and operational burden are documented for roadmap decision.

---


## Epic AD-9: Dev UI Directory Inspection and User Management

### AD-024 — Dev directory management API surface (users/groups/activity)
**Type:** Backend / DevEx
**Priority:** P1
**Dependencies:** AD-018, AD-022

**Scope**
- Add dev-only API endpoints to inspect local AD/Keycloak users, groups, and recent auth events.
- Add dev-only endpoints to create/update/disable users and assign/remove seeded groups.
- Add guardrails so endpoints are disabled outside local/dev environments.

**Deliverables**
- Backend API routes + service layer for local directory user/group management.
- Activity query endpoint (recent login attempts, callback failures, mapping decisions).

**Acceptance Criteria**
- Root/dev user can list and manage local Keycloak users/groups via API.
- Activity endpoint returns correlated AD SSO auth events for local troubleshooting.

**Implementation Artifacts**
- `deployment_initializer/backend/app/routers/admin_sso.py` (or dedicated dev-directory router)
- `deployment_initializer/backend/app/services/*` (dev directory service module)
- `deployment_initializer/backend/tests/test_admin_sso_dev_directory_api.py`

---

### AD-025 — Dev UI for AD user provisioning and group assignment
**Type:** Frontend / DevEx
**Priority:** P1
**Dependencies:** AD-024

**Scope**
- Add a Dev UI section to inspect directory users/groups and user status.
- Add create/edit/disable user workflows and group assignment controls.
- Add quick actions to seed common test personas (admin, ops, denied/unmapped).

**Deliverables**
- Dev UI panel for directory user management.
- Frontend API integration + optimistic refresh/state handling.

**Acceptance Criteria**
- New engineer can add a local AD user, assign `group-admins`/`group-ops`, and test login without leaving the UI.
- Dev UI clearly indicates seeded vs custom users and active/disabled state.

**Implementation Artifacts**
- `deployment_initializer/frontend/src/App.tsx` (or extracted Dev UI component)
- `deployment_initializer/frontend/tests/App.test.tsx` (or dedicated dev-directory tests)

---

### AD-026 — Dev UI AD activity explorer (auth timeline + filters)
**Type:** Frontend + Backend / Observability
**Priority:** P1
**Dependencies:** AD-024, AD-025

**Scope**
- Provide AD activity timeline in Dev UI (starts, callbacks, denies, failures, role mapping outcomes).
- Add filters by user, provider, outcome, and time window.
- Surface key troubleshooting context (issuer/audience mismatch, nonce failures, JWKS errors).

**Deliverables**
- Activity API response shape and UI timeline/table.
- Filter controls and detail drawer for event payload metadata.

**Acceptance Criteria**
- Developer can diagnose a failed local AD login from the Dev UI without direct DB queries.
- Activity explorer shows stale-key/JWKS-related failures during AD-021 drill.

**Implementation Artifacts**
- `deployment_initializer/backend/tests/test_admin_sso_dev_activity_api.py`
- `deployment_initializer/frontend/tests/*` for activity explorer interactions
- `docs/local-dev-stack.md` troubleshooting references

---

### AD-027 — Docs + onboarding for Dev UI AD management workflow
**Type:** Documentation / DevEx
**Priority:** P1
**Dependencies:** AD-025, AD-026

**Scope**
- Extend local dev docs with “manage users in Dev UI” walkthrough.
- Add decision guidance for when to use UI actions vs scripts.
- Add troubleshooting for common Dev UI directory errors (stale session, disabled user, mapping gaps).

**Deliverables**
- Updated onboarding steps in `docs/local-dev-stack.md` and related AD SSO docs.
- Quick-reference matrix mapping common login failures to remediation steps.

**Acceptance Criteria**
- New engineer can complete user provisioning + activity diagnosis using Dev UI docs only.
- Docs resolve top local support issues without requiring backend code inspection.

**Implementation Artifacts**
- `docs/local-dev-stack.md`
- `docs/ad-admin-sso-local-keycloak-dev-plan.md`
- `docs/ad-admin-sso-oncall-handbook.md`

---

## Suggested Delivery Sequence
1. **Sprint 1:** AD-001 to AD-004 (architecture + schema/secrets baseline)
2. **Sprint 2:** AD-005 to AD-009 (OIDC auth + role mapping + guardrails)
3. **Sprint 3:** AD-010 to AD-012 (root-only configuration API and UI)
4. **Sprint 4:** AD-013 to AD-015 (audit/metrics/runbooks)
5. **Sprint 5:** AD-016 to AD-017 (test hardening + staged launch)
6. **Sprint 6:** AD-018 to AD-022 (local Keycloak dev provider + docs/tests)
7. **Sprint 7:** AD-023 (optional AD bridge spike and recommendation)
8. **Sprint 8:** AD-024 to AD-027 (Dev UI directory management + activity explorer)
