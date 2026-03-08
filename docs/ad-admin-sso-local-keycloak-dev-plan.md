# AD Admin SSO Local Keycloak Dev Plan

## Goal
Provide a realistic local Active Directory-like provider for developer workflows by running Keycloak locally, while preserving the fast existing token-mock path for most tests.

## Why Keycloak for local AD simulation
- Emulates real OIDC metadata and JWKS behavior (issuer, discovery, key rotation) unlike static token fixtures.
- Supports LDAP federation in a later phase if we need deeper AD parity.
- Fits existing local provider-stack approach (similar to local Cognito/S3 mock services).

## Modes of operation

### Mode A — Fast mock (existing default)
- Keep current deterministic token fixtures for unit/integration speed.
- Required for CI baseline and quick local loops.

### Mode B — Local OIDC IdP (new)
- Run Keycloak in local stack (host mode only, no Docker container).
- Seed realm/client/users/groups for admin SSO scenarios.
- Exercise real `/authorize` + callback semantics and key material retrieval.

### Mode C — Optional AD bridge (later)
- Run Samba AD DC and federate through Keycloak LDAP user federation.
- Use only for enterprise-schema compatibility checks.

## Delivery phases

### Phase 1: Local Keycloak infrastructure
1. Add host-mode Keycloak startup to local stack scripts with stable dev ports.
2. Add bootstrap/seed script to create:
   - realm: `local-ad`
   - client: `deployment-initializer-admin-sso`
   - users: `admin@example.com`, `ops@example.com`
   - groups: `group-admins`, `group-ops`, `group-root-test`
3. Document required local env vars:
   - `ADMIN_SSO_DEV_PROVIDER_MODE=keycloak`
   - `ADMIN_SSO_DEV_ISSUER=http://localhost:<keycloak-port>/realms/local-ad`
   - `ADMIN_SSO_DEV_CLIENT_ID=deployment-initializer-admin-sso`
   - `ADMIN_SSO_DEV_REDIRECT_URI=http://localhost:8000/auth/admin/sso/callback`

### Phase 2: Backend dev integration path
1. Add a dev-only helper command that prints provider config payload for root API setup (`python3 scripts/local-ad-sso-provider-config.py`).
2. Add `scripts/local-ad-sso-up.sh` / `scripts/local-ad-sso-down.sh` wrappers to start/stop Keycloak + seed data in one command.
3. Integrate run status in `scripts/run_dev.sh` so Keycloak discovery/JWKS readiness is surfaced when `DEV_ENABLE_KEYCLOAK=1`.
4. Keep app behavior unchanged in production; this is strictly local-dev workflow scaffolding.

### Phase 3: E2E coverage with real local IdP
1. Add `pytest` E2E profile (manual/nightly) that uses Keycloak-issued tokens instead of synthetic HS256 fixtures.
   - Command: `RUN_LOCAL_KEYCLOAK_INTEGRATION=1 PYTHONPATH=deployment_initializer/backend pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_integration.py`
2. Validate scenarios:
   - root configures provider and activates it,
   - admin login via Keycloak path yields mapped role,
   - callback checks issuer/audience/nonce against real issuer/JWKS metadata,
   - fail-closed behavior remains for invalid issuer/audience/nonce/signature.

### Phase 4: Key rotation drill and optional LDAP federation experiment
1. Add reproducible local key-rotation drill command (`python3 scripts/local-keycloak-rotate-keys.py`).
2. Add regression profile for stale-key failure then recovery (`test_admin_sso_keycloak_rotation.py`).
3. Add an optional host-mode or containerized Samba AD DC profile (non-default).
4. Federate AD users/groups into Keycloak.
5. Run compatibility checks for group claim mappings and tenant constraints.

## Proposed local stack integration
- Extend `scripts/local-stack-up.sh` with optional host-mode gate:
  - `DEV_ENABLE_KEYCLOAK=1` starts host-mode Keycloak and runs seed bootstrap.
  - `DEV_ENABLE_KEYCLOAK=0` leaves current stack unchanged.
- Extend `scripts/run_dev.sh` status output to include Keycloak state when enabled.
- Add health checks:
  - `GET /realms/local-ad/.well-known/openid-configuration`
  - JWKS endpoint reachability.

## Security and guardrails
- Keycloak local secrets are dev-only and never reused outside local environment.
- Root-role prohibition remains unchanged: external claims cannot map to `root`.
- Keep `ADMIN_SSO_ENFORCE_FOR_ADMINS` default `false` in local startup; enable explicitly during validation scenarios.

## Rollout sequencing for this dev feature
1. Ship infra + docs first (no app auth behavior change).
2. Enable for internal developer pilot.
3. Add nightly real-IdP E2E lane.
4. Promote to recommended local-auth workflow for AD SSO feature development.

## Success criteria
- Developers can run one command to start a local AD-like IdP and complete admin SSO start/callback flow.
- Local Keycloak mode validates config/activation/rollback paths without production dependencies.
- Existing fast mock mode remains available and unchanged.

## Non-goals
- Replacing production identity integration decisions.
- Introducing LDAP bind authentication into app runtime.
- Making local Keycloak mode mandatory for all CI jobs.


## Onboarding path (AD-022)
- Primary onboarding source: `docs/local-dev-stack.md`.
- New engineers should follow the decision tree and E2E walkthrough there to complete:
  1. host-mode startup,
  2. provider payload generation,
  3. provider create/validate/activate,
  4. real-IdP integration profile,
  5. optional key-rotation drill.
- Troubleshooting entries for port conflicts, realm reset, and seed drift are maintained in `docs/local-dev-stack.md` and should be kept current with script behavior.


## Dev UI management workflow (AD-027)

### Objective
Document a UI-first onboarding path so engineers can provision users, adjust group mappings, and diagnose local auth failures without backend DB inspection.

### UI-first onboarding checklist
1. Start local Keycloak mode (`scripts/local-ad-sso-up.sh`) and app (`scripts/run_dev.sh --no-clean`).
2. In TypeScript Dev UI, set Acting Role to `root`.
3. Open **Dev Directory** and click **Load Directory Data**.
4. Create/sync a user and assign `group-admins` or `group-ops`.
5. Execute login flow and use **AD Activity Explorer** filters for diagnosis.
6. Validate troubleshooting hints for callback failures (issuer/audience/nonce/JWKS).

### UI vs script guidance
- **Use UI** for: day-to-day local user/group edits, enable/disable toggles, and fast failure diagnosis.
- **Use scripts** for: full realm bootstrap/reset, key rotation drills, deterministic regression setup, and generated provider payload refresh.

### Top support issues to cover in onboarding
- **Stale session/role context:** ensure Acting Role is `root`, then reload directory data.
- **Disabled user:** re-enable user in UI before retrying auth.
- **Mapping gaps:** assign `group-admins`/`group-ops` and confirm role mapping exists for active provider.
- **JWKS/key drift:** run rotation recovery flow and verify activity feed moves from failure to success.
