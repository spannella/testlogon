# Local Dev Stack Playbook

This document is the **single source of truth** for running and validating the local provider stack (DynamoDB, LocalStack/Cognito/S3/SES, Stripe mock, CCBill mock, PayPal mock wiring, Twilio local testing, and UPS mock).

## 0) Fast path (mock mode)

For a quick local mock run + validation:

```bash
scripts/run_dev.sh
# optional real backend mode:
# scripts/run_dev.sh --real-backend
```

`run_dev.sh` in mock mode now auto-bootstraps local DynamoDB tables on first run and writes a marker at `.local/run/ddb-bootstrap.done`.

Bootstrap controls (environment variables):
- `DEV_DDB_BOOTSTRAP=1` (default): run table bootstrap logic.
- `DEV_DDB_BOOTSTRAP=0`: skip DynamoDB bootstrap entirely.
- `DEV_FORCE_DDB_BOOTSTRAP=1`: ignore marker and force table bootstrap again.
- `DEV_DDB_SEED=1`: run `scripts/local-ddb-seed.py` after table creation.

In another terminal:

```bash
scripts/test_mock_mode.sh
```

## AD Admin SSO local IdP option (Keycloak)

For AD SSO feature work, we support an optional local Keycloak mode to emulate a real OIDC IdP.

- Plan/documentation: `docs/ad-admin-sso-local-keycloak-dev-plan.md`
- Goal: keep default fast mock flow, but allow realistic local issuer/JWKS/start/callback validation.

### Decision tree: fast mock mode vs local Keycloak mode

Use this rule-of-thumb before starting your local session:

1. **Do you only need normal backend/frontend development (non-SSO-specific)?**
   - Use **Fast mock mode**.
   - Command: `scripts/run_dev.sh`
2. **Do you need to validate admin SSO callback behavior, issuer/JWKS verification, or role mapping from IdP groups?**
   - Use **Local Keycloak mode**.
   - Command: `scripts/local-ad-sso-up.sh`
3. **Do you need key-rotation/stale-key recovery behavior?**
   - Use **Local Keycloak mode** plus AD-021 drill commands.
   - Command: `python3 scripts/local-keycloak-rotate-keys.py` and run the rotation regression profile.

Host-mode toggle (used by startup scripts):
- `DEV_ENABLE_KEYCLOAK=1` (start local Keycloak host process + bootstrap seed)
- `DEV_ENABLE_KEYCLOAK=0` (default; unchanged local stack behavior)

### Local Keycloak defaults and env vars

Defaults used by scripts:
- `KEYCLOAK_BASE_URL=http://localhost:8081`
- `KEYCLOAK_REALM=local-ad`
- `KEYCLOAK_CLIENT_ID=deployment-initializer-admin-sso`
- `KEYCLOAK_ADMIN=admin`
- `KEYCLOAK_ADMIN_PASSWORD=admin`
- Seeded test users:
  - `admin@example.com` / `DevAdmin123!`
  - `ops@example.com` / `DevOps123!`
- Seeded test groups:
  - `group-admins`, `group-ops`, `group-root-test`

Health endpoints checked by startup wiring:
- `http://localhost:8081/realms/local-ad/.well-known/openid-configuration`
- `http://localhost:8081/realms/local-ad/protocol/openid-connect/certs`

### End-to-end onboarding walkthrough (docs-only path)

This is the recommended "new engineer" path to complete local AD SSO setup.

1. **Start local Keycloak and stack dependencies**
   ```bash
   scripts/local-ad-sso-up.sh
   ```
2. **Generate provider payload from live Keycloak metadata**
   ```bash
   python3 scripts/local-ad-sso-provider-config.py
   ```
   - Save the printed provider JSON to `provider.json`.
   - Save role mapping JSON to `role-mappings.json` (or post each mapping individually).
3. **Start backend/frontend (if not already running)**
   ```bash
   scripts/run_dev.sh --no-clean
   ```
4. **Create provider as root**
   ```bash
   curl -s -X POST http://localhost:8000/auth/admin/sso/providers \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer root:<token>' \
  -d @provider.json
   ```
5. **Create role mappings**
   - Use `/auth/admin/sso/providers/{provider_id}/role-mappings` with values like:
     - `group-admins -> admin`
     - `group-ops -> ops`
6. **Validate and activate provider**
   ```bash
   curl -s -X POST http://localhost:8000/auth/admin/sso/providers/<provider_id>/validate \
     -H 'authorization: Bearer root:<token>'
   curl -s -X POST http://localhost:8000/auth/admin/sso/providers/<provider_id>/activate \
     -H 'authorization: Bearer root:<token>'
   ```
7. **Run real-IdP integration profile**
   ```bash
   RUN_LOCAL_KEYCLOAK_INTEGRATION=1 \
  PYTHONPATH=deployment_initializer/backend \
  pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_integration.py
   ```
8. **Optional: run key-rotation drill**
   ```bash
   python3 scripts/local-keycloak-rotate-keys.py
   RUN_LOCAL_KEYCLOAK_ROTATION=1 \
  PYTHONPATH=deployment_initializer/backend \
  pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_rotation.py
   ```
9. **Stop local AD SSO dependencies when done**
   ```bash
   scripts/local-ad-sso-down.sh
   ```

### Troubleshooting (ports, realm reset, seed drift)

#### 1) Port conflicts
- Symptoms: Keycloak/mocks fail to start, health checks time out.
- Default ports:
  - Keycloak: `8081`
  - Backend: `8000`
  - Vite frontend: `5173`
  - Moto AWS mock: `4566`
  - DynamoDB Local: `8001`
  - Stripe mock: `12111`
- Fixes:
  - Stop stale processes: `scripts/local-stack-down.sh`
  - Check listeners: `ss -ltnp | rg '8081|8000|5173|4566|8001|12111'`

#### 2) Realm reset / broken realm state
- Symptoms: local realm missing clients/groups, login flow errors, discovery still up but callbacks fail.
- Fixes:
  1. Stop stack: `scripts/local-ad-sso-down.sh`
  2. Remove local Keycloak tool state (optional hard reset): `rm -rf .local/tools/keycloak`
  3. Start again: `scripts/local-ad-sso-up.sh`
  4. Re-generate provider payload and re-run provider create/validate/activate.

#### 3) Seed drift (users/groups/client differ from expected)
- Symptoms: group mappings no longer resolve, integration tests fail for missing `group-admins`.
- Fixes:
  - Re-run bootstrap idempotently:
    ```bash
    PYTHONPATH=deployment_initializer/backend python3 scripts/local-keycloak-init.py
    ```
  - Re-check seeded users/groups/client in Keycloak admin UI.
  - Re-apply provider mappings from `scripts/local-ad-sso-provider-config.py` output.

#### 4) Provider metadata/JWKS mismatch
- Symptoms: callback fails with issuer/audience/JWKS errors.
- Fixes:
  - Ensure provider `issuer` matches `/.well-known/openid-configuration` `issuer` exactly.
  - Ensure `client_id` matches seeded client.
  - Ensure `secret_ref` points to current client secret.


#### 5) Diagnose AD login failures in Dev UI Activity Explorer
- Use the Dev Directory panel in the TypeScript UI and open **AD Activity Explorer**.
- Apply filters to narrow failures quickly:
  - `Actor Email`: isolate one test identity.
  - `Provider ID`: isolate one local IdP config.
  - `Outcome`: `failure` / `denied` / `success`.
  - `Since Minutes`: constrain to the latest repro window.
- Select an event in the timeline to view troubleshooting metadata:
  - `failure_reason`
  - `troubleshooting_category`
  - `troubleshooting_hint`
- Common hints surfaced in UI include issuer mismatch, audience mismatch, nonce replay/mismatch, and JWKS reachability/signature problems.

#### 6) AD-021 stale-key/JWKS drill visibility in Dev UI
- After running `python3 scripts/local-keycloak-rotate-keys.py`, trigger one callback with stale key cache to generate an expected callback failure window.
- Open Dev UI Activity Explorer and filter:
  - `Outcome = failure`
  - `Since Minutes = 15`
- Confirm failed events show JWKS-related troubleshooting context (`jwks_unreachable` / signature-related failure reason), then refresh/retry flow and confirm success events appear in the same filtered window.
- This gives a no-DB-query diagnosis path for key rotation regressions during local drills.


### Dev UI-first user provisioning and activity diagnosis (AD-027)

Use this path when you want to manage local AD users and debug failed logins without direct DB queries.

1. **Start local stack + Keycloak mode**
   ```bash
   scripts/local-ad-sso-up.sh
   scripts/run_dev.sh --no-clean
   ```
2. **Open Dev UI and switch to root actor**
   - In UI, set **Acting Role** = `root`.
   - Open **Dev Directory (Local AD/Keycloak)** panel.
3. **Load directory data**
   - Click **Load Directory Data**.
   - Confirm seeded users/groups/activity counts appear.
4. **Create or update a local AD user in UI**
   - Fill `Dev Username`, `Dev Email`, `Dev Password`.
   - Set `Initial Groups` (for example `group-admins` or `group-ops`).
   - Click **Create / Sync User**.
5. **Assign or remove groups in UI**
   - Select user in **Selected Dev User** dropdown.
   - Use quick actions:
     - **Add group-admins**
     - **Add group-ops**
     - **remove <group>** on the user row
6. **Control account status**
   - Use **Enable User** / **Disable User** to verify allowed vs blocked login behavior.
7. **Diagnose auth outcomes in Activity Explorer**
   - Set filters (`Actor Email`, `Provider ID`, `Outcome`, `Since Minutes`).
   - Click **Apply Activity Filters**.
   - Select an event to inspect `failure_reason`, `troubleshooting_category`, and `troubleshooting_hint`.

### Decision guide: use Dev UI actions vs scripts/API

| Task | Prefer Dev UI | Prefer script/API |
|---|---|---|
| Quick local user creation + group assignment | ✅ Yes | |
| Verify enabled/disabled behavior for one user | ✅ Yes | |
| Inspect callback failures and mapping outcomes | ✅ Yes (Activity Explorer) | |
| Bootstrap realm/client/users/groups from scratch | | ✅ `scripts/local-ad-sso-up.sh` / `scripts/local-keycloak-init.py` |
| Rebuild provider payload from discovery metadata | | ✅ `python3 scripts/local-ad-sso-provider-config.py` |
| Repeatable CI/nightly regression runs | | ✅ pytest profiles + scripts |
| Stale-key/JWKS rotation drill | UI for diagnosis, script for setup | ✅ `python3 scripts/local-keycloak-rotate-keys.py` |

### Quick-reference: local AD login failures → remediation

| Symptom in Dev UI Activity Explorer | Likely cause | Immediate remediation |
|---|---|---|
| `sso_callback_invalid_issuer` | Provider issuer mismatch | Re-generate provider payload; ensure issuer exactly matches discovery issuer. |
| `sso_callback_invalid_audience` | Client ID mismatch | Verify provider `client_id` matches seeded Keycloak client. |
| `sso_callback_invalid_nonce` | Stale/replayed auth attempt | Restart flow from `/start`; do not reuse callback URL. |
| `sso_callback_jwks_unreachable` or signature failure | Stale key/JWKS connectivity issue | Validate JWKS endpoint, then retry after refresh/rotation drill recovery. |
| `sso_role_mapping_denied` | User has no mapped AD group | Assign `group-admins` or `group-ops` in Dev UI and retry login. |
| User appears in UI as `disabled` | Account intentionally disabled | Click **Enable User** in Dev UI, then retry login. |
| Activity feed not updating after role switch | Stale root/non-root UI session context | Set Acting Role = `root`, reload directory data, then re-apply filters. |

### AD-020 local-real-IdP integration profile

Run this profile after Keycloak host mode is up:

```bash
RUN_LOCAL_KEYCLOAK_INTEGRATION=1 \
  PYTHONPATH=deployment_initializer/backend \
  pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_integration.py
```

Suggested nightly target (same profile command) should execute on an environment where:
- `scripts/local-ad-sso-up.sh` has been run (or equivalent host-mode Keycloak setup),
- discovery endpoint and JWKS are reachable,
- seeded user `admin@example.com` / `DevAdmin123!` exists.

### AD-021 key-rotation drill

Run the local key-rotation helper:

```bash
python3 scripts/local-keycloak-rotate-keys.py
```

Run the rotation regression profile:

```bash
RUN_LOCAL_KEYCLOAK_ROTATION=1 \
  PYTHONPATH=deployment_initializer/backend \
  pytest deployment_initializer/backend/tests/test_admin_sso_keycloak_rotation.py
```

Checklist/runbook: `docs/ad-admin-sso-key-rotation-drill.md`


## 1) Boot local infrastructure

Preferred (automatic bootstrap path):

```bash
scripts/run_dev.sh
```

Manual fallback / troubleshooting path:

```bash
scripts/local-stack-up.sh
python3 scripts/local-ddb-init.py
python3 scripts/local-ddb-seed.py   # optional
python3 scripts/local-s3-init.py
# optional: run manually if you want to re-generate Cognito ids
python3 scripts/local-cognito-init.py
```

`local-stack-up.sh` supports **Docker mode** (when Docker is installed) and **host mode** (no Docker). In host mode it starts moto (AWS mock including S3/Cognito/SES), DynamoDB Local, and stripe-mock as local processes and stores logs under `.local/logs/`.

If `.env.local` does not exist, copy from `.env.local.example` and adjust as needed.

`local-stack-up.sh` now automatically runs `scripts/local-cognito-init.py`, which writes Cognito settings to both backend `.env.local` and frontend `frontend/.env.local` (`VITE_COGNITO_*`). It also runs `scripts/local-ses-init.py` to pre-verify `SES_FROM_EMAIL` for local email testing in both Docker (LocalStack) and host mode (moto) by reading values from `.env.local` when shell env vars are not exported.

## 2) Start app

```bash
uvicorn app.main:app --reload
```

## 3) Provider mock defaults (recommended local)

Use these in `.env.local`:

- `CCBILL_MOCK_ENABLED=1`
- `CCBILL_BASE_URL=http://localhost:8000/mock/ccbill`
- `CCBILL_WEBHOOK_VERIFY_MODE=local`
- `CCBILL_WEBHOOK_SIGNATURE_SECRET=local-ccbill-webhook-secret`
- `UPS_BASE_URL=http://localhost:8000/mock/ups`
- `UPS_AUTH_URL=http://localhost:8000/mock/ups/oauth/token`
- `UPS_CLIENT_ID=local_ups_client`
- `UPS_CLIENT_SECRET=local_ups_secret`
- `UPS_WEBHOOK_SECRET=local-ups-webhook-secret`
- `SES_FROM_EMAIL=dev-no-reply@example.com`

## 4) run_dev bootstrap validation checklist

Use this after changing bootstrap logic:

1. **Fresh run (no marker)**
   ```bash
   rm -f .local/run/ddb-bootstrap.done
   scripts/run_dev.sh
   ```
   Expected: logs include DynamoDB table initialization and marker creation.

2. **Warm run (marker present)**
   ```bash
   scripts/run_dev.sh
   ```
   Expected: logs show bootstrap skipped because marker exists.

3. **Forced rerun**
   ```bash
   DEV_FORCE_DDB_BOOTSTRAP=1 scripts/run_dev.sh
   ```
   Expected: logs show forced bootstrap and table init rerun.

4. **Bootstrap disabled**
   ```bash
   DEV_DDB_BOOTSTRAP=0 scripts/run_dev.sh
   ```
   Expected: logs show bootstrap skipped by env flag.

5. **Optional seed enabled**
   ```bash
   DEV_DDB_SEED=1 DEV_FORCE_DDB_BOOTSTRAP=1 scripts/run_dev.sh
   ```
   Expected: logs show `scripts/local-ddb-seed.py` executed after table init.

## 5) QA checklist

Before manual validation, run:

```bash
scripts/test_mock_mode.sh
```

### Core stack
- [ ] UI loads at `/`
- [ ] DynamoDB tables exist and seeded records are queryable
- [ ] S3 buckets exist and upload endpoints work
- [ ] Cognito pool/client exist and `.env.local` has IDs + issuer/JWKS URLs

### Twilio (local validation)
- [ ] Set `TWILIO_*` vars (or keep disabled)
- [ ] Run SMS MFA enroll/verify flow from UI
- [ ] Confirm audit trail/log entries for send + verify

### CCBill
- [ ] `POST /api/billing/ccbill/frontend-oauth` returns token
- [ ] Save tokenized payment method via UI
- [ ] Run `/api/billing/charge-once` and `/api/billing/subscribe-monthly`
- [ ] Emit webhook: `POST /emit/ccbill-webhook` and verify `/api/ccbill/webhook` reconciliation updates payments/subscriptions

### PayPal
- [ ] `/api/billing/config` shows PayPal config
- [ ] Create PayPal setup/payment flow
- [ ] Trigger/forward PayPal webhook locally and verify billing state transition

### UPS (local mock simulation)
- [ ] `POST /api/ups/quote` succeeds against local UPS mock
- [ ] `POST /api/ups/label` returns a mock tracking number + label URL
- [ ] `POST /emit/ups-tracking-webhook` delivers signed webhook to `/api/ups/tracking/webhook`
- [ ] Confirm webhook event persisted under `UPS_TRACKING` records in billing table

## 6) Example UPS local simulation

1. Quote:
```bash
curl -s -X POST http://localhost:8000/api/ups/quote \
  -H 'content-type: application/json' \
  -H 'cookie: ui_session=<session-cookie>' \
  -d '{"service":"ground","package":{"weight":2.5}}'
```

2. Label:
```bash
curl -s -X POST http://localhost:8000/api/ups/label \
  -H 'content-type: application/json' \
  -H 'cookie: ui_session=<session-cookie>' \
  -d '{"service":"ground","package":{"weight":2.5},"to":{"postal":"10001"}}'
```

3. Tracking webhook emit:
```bash
curl -s -X POST http://localhost:8000/emit/ups-tracking-webhook \
  -H 'content-type: application/json' \
  -d '{"payload":{"tracking_number":"1ZMOCK123","status":"DELIVERED"}}'
```
