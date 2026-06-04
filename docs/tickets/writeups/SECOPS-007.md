# SECOPS-007: Dev/Prod Environment Parity & AWS Abstraction — Investigation & Implementation Write-up

> ~5 pages. Read the real code before writing; cite `file:line`. Be concrete, not generic.

## 1. Summary & Classification

SECOPS-007 is a cross-cutting governance document and standing engineering requirement, not a single deliverable. Every SEC-NNN and SECOPS-NNN ticket must satisfy one criterion: the feature runs fully in a dev environment with no AWS services and no outbound network access, **and** runs in production using real AWS services, through the **same code path** with only the injected backend differing. The selection is made by `S.dev_mode` and per-feature `*_MOCK_ENABLED` / `*_ENABLED` flags — never by scattered `if dev:` branches inside business logic.

This document codifies the requirement, catalogues every existing mock pattern in the repo, specifies the canonical provider-interface + factory pattern that new security capabilities must follow, and provides the definitive reference table mapping each SECOPS capability to its dev and prod implementation.

- **Type**: infra / governance (cross-cutting)
- **Priority/Severity**: High — blocks all SECOPS implementation tickets
- **Status**: Open (the pattern is established in the existing codebase; the formal documentation and checklist are missing)
- **Owning area**: Platform Engineering / Security Operations
- **Who is affected**: every engineer implementing a SEC-NNN or SECOPS-NNN ticket; every CI run that must pass with zero AWS credentials
- **Cross-references**: all SEC-NNN and SECOPS-NNN tickets; directly depended on by [[SECOPS-005]], [[SECOPS-006]]

---

## 2. Current-State Investigation (what exists today)

### 2.1 The master `dev_mode` flag

`app/core/settings.py:273`:

```python
dev_mode: bool = os.environ.get("DEV_MODE", "1") not in ("0", "false", "False")
```

`DEV_MODE` defaults to `"1"` (enabled), so a fresh checkout with no `.env.local` runs in dev mode. All dev-mode overrides in the codebase key off this boolean. It is the root switch; per-capability `*_MOCK_ENABLED` flags allow production deployments to selectively re-enable mock behaviour for individual subsystems (e.g., staging environments that share a real DynamoDB but use a mock KMS).

### 2.2 DynamoDB — DynamoDB Local on :8001

All boto3 DynamoDB access goes through `app/core/aws_clients.py:ddb_resource` (line 104). The endpoint is resolved by `_ddb_endpoint_url()` (line 74):

```python
def _ddb_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.ddb_endpoint_url, _aws_endpoint_url())
```

In dev, `.env.local` sets `DDB_ENDPOINT_URL=http://localhost:8001` (DynamoDB Local, started by `scripts/local-stack-up.sh`). In prod, `DDB_ENDPOINT_URL` is empty and the client connects to `dynamodb.us-east-1.amazonaws.com`. No business logic needs to know which endpoint is in use; the table handle in `app/core/tables.py` is identical in both environments.

When both `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` env vars are unset **and** the endpoint resolves to localhost or a private address, `_local_credentials_kwargs` (`app/core/aws_clients.py:62`) injects synthetic `test/test` credentials so the client can authenticate to DynamoDB Local without real AWS credentials. This means `just test` and `just e2e` pass with `--no-aws-creds` equivalent.

### 2.3 S3 — in-process moto (`app/core/dev_s3.py`)

`app/core/dev_s3.py:start_s3_mock` (line 20) calls `moto.mock_aws().start()` which patches botocore's HTTP layer at the process level. After this call, any `boto3.client("s3")` call anywhere in the process — regardless of endpoint URL — is intercepted by moto's in-memory store. This is the most elegant mock pattern in the codebase: zero configuration, zero external process, fully in-memory, and completely transparent to business logic.

The key design decision in `app/core/aws_clients.py:s3_client` (lines 78–83) is:

```python
def _s3_endpoint_url() -> Optional[str]:
    # In dev mode, moto intercepts boto3 S3 calls in-process; no endpoint URL
    # should be set (a custom endpoint would bypass moto's botocore patching).
    if S.dev_mode:
        return None
    return _resolve_endpoint_url(S.s3_endpoint_url, _aws_endpoint_url())
```

In dev, the endpoint URL is forced to `None` so moto's botocore patch takes effect. In prod, the endpoint resolves normally. Same code path; different infrastructure.

### 2.4 KMS — mock_kms server on :7999

`app/core/aws_clients.py:kms_client` (line 135) uses `_kms_endpoint_url()` (line 90):

```python
def _kms_endpoint_url() -> Optional[str]:
    return _resolve_endpoint_url(S.kms_endpoint_url, _aws_endpoint_url())
```

In dev, `.env.local` sets `KMS_ENDPOINT_URL=http://localhost:7999`. `scripts/mock_kms_server.py` runs on that port and implements a minimal KMS-compatible encrypt/decrypt API using a local AES key. Business logic calls `kms_encrypt` / `kms_decrypt` in `app/core/crypto.py:16–25` without any awareness of which backend serves the request. In prod, `KMS_ENDPOINT_URL` is empty and the AWS SDK routes to `kms.us-east-1.amazonaws.com`.

The LLM key service (`app/services/llm_provider_keys.py:107`) calls `kms_encrypt(api_key)` and later `kms_decrypt(item["encrypted_api_key"])` (line 170) — indistinguishable locally from production.

### 2.5 Cognito — moto in-process

`app/core/aws_clients.py:cognito_client` (line 125) resolves `_cognito_endpoint_url()` using `S.cognito_endpoint_url`. The local Cognito is bootstrapped by `scripts/local-cognito-init.py` which uses moto's HTTP server mode. In prod, this resolves to real AWS Cognito.

### 2.6 Stripe — external mock binary on :12111

`S.stripe_api_base` (`app/core/settings.py:338`) is set to `http://localhost:12111` in `.env.local.example`. The `stripe` Python SDK uses `stripe.api_base` as the request target, so pointing it at the stripe-mock binary redirects all Stripe API calls without changing any business logic. In prod, `STRIPE_API_BASE` is empty and the SDK defaults to `https://api.stripe.com`.

### 2.7 CCBill, PayPal, Jira, Google Calendar, Apple CalDAV — mock-enabled flags

Each of these integrations follows the same pattern: a boolean `*_mock_enabled` flag in `app/core/settings.py` that defaults to `True` in dev mode:

- `ccbill_mock_enabled: bool = os.environ.get("CCBILL_MOCK_ENABLED", os.environ.get("DEV_MODE", "1")) ...` (line 310)
- `jira_mock_enabled: bool = os.environ.get("JIRA_MOCK_ENABLED", "0") ...` (line 427) — note Jira defaults `False`; must be explicitly enabled
- `google_calendar_mock_enabled` (line 458), `apple_caldav_mock_enabled` (line 132)

Each service module checks the flag at call time and returns a canned response without making an outbound HTTP request.

### 2.8 DRM — mode string + factory (`app/services/drm_license_service.py`)

The most explicit factory pattern in the codebase. `S.drm_license_provider_mode` (`app/core/settings.py:386`, default `"mock"`) is a string enum:

```python
mode = (S.drm_license_provider_mode or "mock").strip().lower()
if mode == "mock":
    return issue_mock_license(...)
if mode != "production":
    raise ValueError(f"unsupported drm license provider mode: {mode}")
prod_provider = provider or default_production_drm_provider()
return prod_provider.issue_license(...)
```

This pattern — check the mode string, delegate to the appropriate implementation, raise on unknown mode — is the canonical model for SECOPS-005 and SECOPS-006.

### 2.9 GeoIP — database-path absence = fail-open

`app/services/geoip.py:60–68`: when `S.geo_maxmind_db_path` is empty (dev), `_lookup_country_uncached` returns `None` immediately. The `set_mock_country` / `get_mock_country` hooks (lines 95–109) enable deterministic E2E test scenarios by populating an in-process dict. Rule 3 in SECOPS-007: *graceful degradation* — missing provider → feature no-ops with a log warning, never breaks request handling.

### 2.10 EC2 and Kubernetes mock flags

`S.ec2_mock_enabled` (`app/core/settings.py:2043`) and `S.k8s_mock_enabled` (line 2117) both default to `True` when `DEV_MODE=1`, preventing any real AWS EC2 or Kubernetes API calls during local development and CI. The agent worker provisioner (`app/services/agent_worker_provisioner.py`) branches on these flags before making EC2 `run_instances` or K8s `create_pod` calls.

### 2.11 What is missing

There is no single canonical document enumerating the full capability matrix, the provider-interface contract, or the startup validation rules for SECOPS capabilities. The existing patterns are consistent but undocumented beyond inline comments. This ticket formalises those patterns and extends them to the new security capabilities.

---

## 3. Gap / Threat Analysis

### 3.1 CI/E2E breakage risk from AWS-dependent new code

The highest practical risk is that a developer implementing SECOPS-005 or SECOPS-006 writes business logic that calls `httpx.post("https://api.anthropic.com/...")` or `httpx.post("https://api.abuseipdb.com/...")` directly in the service, without a provider abstraction layer. The first `just e2e` run in a CI environment with no network access fails with a `ConnectError` inside a test that should pass offline. This is harder to fix retroactively once the service is deployed.

### 3.2 Scattered `if S.dev_mode:` branches

A simpler anti-pattern is embedding `if S.dev_mode: return fake_data` directly in the service function rather than in a provider class. This makes the service untestable with the prod implementation in isolation, and adds a hidden branch that is never covered by prod integration tests.

### 3.3 Missing required-secret startup validation

`UI_ACCESS_TOKEN_SECRET` and `API_KEY_PEPPER` are validated non-empty at startup (the app refuses to start without them). New secrets (`ABUSEIPDB_API_KEY`, LLM API keys stored in KMS) must follow the same discipline: if `ABUSEIPDB_ENABLED=1` but no encrypted key record exists in DynamoDB, the enricher should fail with a clear startup error rather than a silent `None` key that produces 401s at runtime.

### 3.4 Prod-only testing gaps

Some behaviours (AbuseIPDB category mapping, Anthropic structured output parsing, KMS key rotation) can only be exercised against real services. The parity framework must include a prod-readiness checklist and a separate integration test suite tagged `@pytest.mark.integration` that is excluded from `just test` but runnable manually with real credentials.

### 3.5 Code sites that must be updated

| File | Required change |
|---|---|
| `app/core/settings.py` | Add all SECOPS capability flags per the capability table in Section 4 |
| `.env.local.example` | Document dev defaults for all new flags |
| `app/services/threat_intel/base.py` | **New** — canonical provider interface (shared by SECOPS-005 + SECOPS-006) |
| `app/services/threat_intel/mock_llm.py` | **New** — mock LLM analyst (SECOPS-005) |
| `app/services/threat_intel/mock_abuseipdb.py` | **New** — mock AbuseIPDB provider (SECOPS-006) |
| `docs/prod-readiness.md` | **New** — prod deployment checklist |

---

## 4. Proposed Design / Fix

### 4.1 The provider-interface + factory pattern — canonical form

Every new external dependency introduced by a SECOPS ticket must be wrapped in a three-layer structure:

**Layer 1 — Abstract base class** in `app/services/threat_intel/base.py`:

```python
from abc import ABC, abstractmethod
from typing import Any

class SecurityProvider(ABC):
    """Abstract base for security-relevant external integrations.

    Contract: implementations must be constructable with no arguments
    (dev mock) or with named keyword arguments only (prod). They must
    never make outbound network calls in __init__.
    """
    @abstractmethod
    def is_available(self) -> bool:
        """Return True if the provider is operational. Used for health checks."""
        ...
```

Individual provider interfaces (`LLMAnalystProvider`, `ThreatIntelProvider`) extend `SecurityProvider`.

**Layer 2 — Concrete implementations**: one in `app/services/threat_intel/<name>_mock.py` (deterministic, no I/O), one in `app/services/threat_intel/<name>_prod.py` (real HTTP, boto3, etc.).

**Layer 3 — Factory function** per capability, in the service module that owns the capability:

```python
def _get_<capability>_provider() -> <ProviderInterface>:
    if S.dev_mode or S.<capability>_mock_enabled:
        return Mock<Capability>Provider()
    return Prod<Capability>Provider(...)
```

The factory is the **only** place where `dev_mode` or mock flags are checked. Business logic calls the factory once per operation (or caches the provider at startup) and never inspects `S.dev_mode` itself.

### 4.2 Full capability → dev/prod table

| Capability (ticket) | Dev backend (no AWS, offline) | Prod backend (AWS/real) | Factory flag(s) |
|---|---|---|---|
| `security_events` / `security_blocklist` / canary stores (SECOPS-001/002/003) | DynamoDB Local (:8001) via `T.*` handles in `app/core/tables.py` | AWS DynamoDB | `DDB_ENDPOINT_URL` (existing) |
| Secrets at rest — AbuseIPDB key, LLM key (SECOPS-006/005, AGENT-001) | mock KMS (:7999) via `S.kms_endpoint_url` → `app/core/aws_clients.py:kms_client` | AWS KMS (`kms.us-east-1.amazonaws.com`) | `KMS_ENDPOINT_URL` (existing) |
| Object storage (logs, reports) | in-process moto via `dev_s3.py:start_s3_mock` | AWS S3 | `S.dev_mode` forces `_s3_endpoint_url()=None` so moto intercepts (`aws_clients.py:81`) |
| GeoIP country + ASN (SECOPS-002) | No-op (`None`) when `S.geo_maxmind_db_path` is empty; `set_mock_country` for E2E | MaxMind GeoLite2 Country+ASN database (vendored `.mmdb` file, offline reader) | `GEO_MAXMIND_DB_PATH` (existing, `app/core/settings.py:1763`) |
| Log sink (SECOPS-001) | stdout / local JSON file (`DEV_EMAIL_LOG` pattern, `app/core/settings.py:280`) | CloudWatch Logs / SIEM webhook (`S.siem_webhook_enabled`, `app/core/settings.py:234`) | `SIEM_WEBHOOK_ENABLED` (existing) |
| Metrics (SECOPS-004) | in-process counters + `/metrics` Prometheus endpoint | Prometheus / CloudWatch Metrics | `S.dev_mode` (metrics endpoint always enabled) |
| Alert delivery (SECOPS-004/005) | mock/log channel: `S.alerts_email_enabled=False`, `alerts_sms_enabled=False` by default; captured in `T.alerts` | SES (email), SNS, Twilio SMS, push, webhook — all enabled via `ALERTS_*_ENABLED=1` | `ALERTS_EMAIL_ENABLED`, `ALERTS_SMS_ENABLED`, `ALERTS_WEBHOOK_ENABLED` (existing) |
| LLM analyst (SECOPS-005) | `MockLLMAnalystProvider` — deterministic canned incidents, no spend, no egress, captures sanitised prompt for assertion | Real provider via stored key (Anthropic `claude-sonnet-4-20250514` / `claude-opus-4-20250514` from `PROVIDER_REGISTRY` in `llm_provider_keys.py:45–49`) | `SECURITY_LLM_MOCK_ENABLED` (new), `S.dev_mode` |
| AbuseIPDB report + enrich (SECOPS-006) | `MockAbuseIPDBProvider` — no outbound call, captures calls for test assertion, returns canned `abuseConfidenceScore` | `api.abuseipdb.com` v2 via `httpx` with `ABUSEIPDB_API_KEY` | `ABUSEIPDB_MOCK_ENABLED` (new), `S.dev_mode` |
| Schedulers (batch analyst, auto-ban decay, blacklist sync) | in-process asyncio background task (existing pattern: `BILLING_RECONCILE_INTERVAL_SECONDS` in `app/core/settings.py:365`) | Same in-process loop; optionally EventBridge Scheduler in prod for HA | `SECURITY_LLM_BATCH_INTERVAL_SECONDS` (new), existing scheduler pattern |
| EC2 / K8s worker provisioning (AGENT-002) | Mock flags: `S.ec2_mock_enabled` (`app/core/settings.py:2043`), `S.k8s_mock_enabled` (line 2117) | Real AWS EC2 / real K8s API | `EC2_MOCK_ENABLED`, `K8S_MOCK_ENABLED` (existing) |
| DRM licence (VWD-017) | `S.drm_license_provider_mode="mock"` → `issue_mock_license` (`app/services/drm_license_service.py:21`) | `S.drm_license_provider_mode="production"` → `ProductionDrmLicenseProvider` | `DRM_LICENSE_PROVIDER_MODE` (existing, `app/core/settings.py:386`) |

### 4.3 Naming convention for new mock flags

All new mock flags must follow the convention already established:

```
{SERVICE}_MOCK_ENABLED = os.environ.get("{SERVICE}_MOCK_ENABLED", os.environ.get("DEV_MODE", "1"))
```

This ensures `DEV_MODE=1` propagates to all mocks without requiring explicit per-service flag setting in `.env.local.example`, while still allowing staging environments to override individual mocks.

Exception: services where a mock is _never_ safe to auto-enable from `DEV_MODE` (e.g., a production KMS key that is shared between staging and dev) should default `"0"` and require explicit opt-in.

### 4.4 Rules for new SECOPS implementations

The following rules formalise the existing repo discipline:

1. **boto3 only via `app/core/aws.py` / `app/core/aws_clients.py`**: never construct boto3 clients with ad-hoc credentials. All endpoint resolution goes through `_resolve_endpoint_url` in `aws_clients.py:14`.

2. **Outbound HTTP only via provider classes**: never call `httpx.get("https://external-service.com/...")` directly in a service function. Always go through a provider interface that can be swapped for a mock.

3. **Every new external dependency ships a dev mock on day one**: the mock must be committed in the same PR as the production client. No partial implementations that are "TODO: add mock later" — the CI suite blocks immediately on missing offline coverage.

4. **Required secrets validated at startup**: if a feature is enabled (`FEATURE_ENABLED=1`) but its secret is missing or empty, raise a `ValueError` at startup with a clear message. Mirror the pattern from `UI_ACCESS_TOKEN_SECRET` validation. Never silently return `None` from a decryption call and propagate the `None` into downstream API calls.

5. **Fail-open vs. fail-closed**: enrichment paths (GeoIP country, AbuseIPDB confidence score, LLM triage) fail-open: if the enrichment provider is unavailable, the request proceeds without enrichment and a warning is logged. Enforcement paths (CSRF check, auth token validation, KMS decrypt) fail-closed: if the operation cannot be completed, return 401/403/500 rather than proceeding.

6. **CI / `just test` / `just e2e` must pass with zero AWS credentials and no internet**: verified by running the full suite inside a network-isolated container. Any test that fails in this environment without a `@pytest.mark.integration` skip tag is a CI regression.

7. **No scattered `if S.dev_mode:` in business logic**: the `dev_mode` check belongs exclusively in factory functions and startup initialisation. Business logic calls the abstraction; it does not know which environment it is in.

### 4.5 `.env.local.example` documentation

Every new settings field added for a SECOPS capability must be documented in `.env.local.example` with:

- The variable name and its default in dev
- A comment explaining what the prod value should be
- A note if the value must be a KMS-encrypted DDB record rather than a plain string

Example (to be added for SECOPS-005 + SECOPS-006):

```bash
# SECOPS-005: LLM Security Analyst
SECURITY_LLM_ENABLED=1
SECURITY_LLM_MOCK_ENABLED=1          # Set to 0 in prod; requires LLM key in llm_provider_keys table
SECURITY_LLM_BATCH_INTERVAL_SECONDS=900
SECURITY_LLM_AUTO_BLOCK_CONFIDENCE_THRESHOLD=0.95

# SECOPS-006: AbuseIPDB
ABUSEIPDB_ENABLED=0                  # Enable in prod after SEC-008 trusted IP is deployed
ABUSEIPDB_MOCK_ENABLED=1
ABUSEIPDB_DAILY_QUOTA=950
ABUSEIPDB_DEDUP_WINDOW_SECONDS=86400
# In prod: store ABUSEIPDB_API_KEY as KMS-encrypted record in DDB, never as plain env var
```

---

## 5. Testing, Verification & Rollout

### 5.1 pytest — offline parity test (`tests/test_secops007_parity.py`)

A dedicated test module that validates the parity contract for every SECOPS provider at the Python-import level. All tests run offline with no creds.

| Test case | Expected result |
|---|---|
| `test_llm_analyst_mock_selected_in_dev_mode` | `S.dev_mode=True` → factory returns instance of `MockLLMAnalystProvider` |
| `test_llm_analyst_prod_selected_when_mock_disabled` | `S.dev_mode=False, S.security_llm_mock_enabled=False` → factory returns `AnthropicLLMAnalystProvider` (class check only, no call) |
| `test_abuseipdb_mock_selected_in_dev_mode` | `S.dev_mode=True` → `MockAbuseIPDBProvider` |
| `test_abuseipdb_prod_selected_when_enabled` | `S.dev_mode=False, S.abuseipdb_mock_enabled=False` → `AbuseIPDBProvider` |
| `test_ddb_endpoint_uses_local_in_dev` | `S.ddb_endpoint_url="http://localhost:8001"` → `_ddb_endpoint_url()` returns local URL |
| `test_s3_endpoint_none_in_dev` | `S.dev_mode=True` → `_s3_endpoint_url()` returns `None` (moto intercept path) |
| `test_kms_endpoint_uses_local_in_dev` | `S.kms_endpoint_url="http://localhost:7999"` → `_kms_endpoint_url()` returns mock URL |
| `test_mock_provider_implements_full_interface` | `MockLLMAnalystProvider()` and `MockAbuseIPDBProvider()` have no unimplemented abstract methods |
| `test_no_scattered_dev_mode_in_service_files` | AST-walk `app/services/security_llm_analyst.py` and `app/services/abuseipdb_reporter.py`; assert no `S.dev_mode` reference outside factory functions |
| `test_full_e2e_with_no_aws_creds` | `os.environ` cleared of `AWS_ACCESS_KEY_ID`; run analyst batch on seeded events using moto DDB and `MockLLMAnalystProvider`; no `NoCredentialsError` raised |

### 5.2 Playwright E2E (`frontend/e2e/secops-parity-check.spec.ts`)

A single smoke-test spec that verifies the entire SECOPS stack runs with the dev mocks:

- Load SECOPS-004 dashboard (if implemented); assert page renders without console errors indicating missing providers.
- Call the internal `/internal/secops/health` endpoint; assert each provider reports `{available: true, mock: true}` in dev mode.
- Assert no request in the browser network log targets `api.anthropic.com`, `api.abuseipdb.com`, `kms.amazonaws.com`, or `dynamodb.amazonaws.com`.

### 5.3 Prod readiness checklist (`docs/prod-readiness.md`)

To be created as part of this ticket's deliverable:

- [ ] GeoLite2 Country+ASN `.mmdb` file present at `GEO_MAXMIND_DB_PATH`; updated monthly
- [ ] `KMS_KEY_ID` set; KMS key exists in the target AWS region; encryption test passes at startup
- [ ] `ABUSEIPDB_API_KEY` stored as KMS-encrypted DDB record; not in `.env`
- [ ] LLM provider key stored via AGENT-001 key management UI; `SECURITY_LLM_MOCK_ENABLED=0`
- [ ] `ABUSEIPDB_ENABLED=1, ABUSEIPDB_MOCK_ENABLED=0` after SEC-008 trusted IP deployed
- [ ] Alert delivery tested: `ALERTS_EMAIL_ENABLED=1` with valid `SES_FROM_EMAIL`, `ALERTS_FROM_EMAIL`
- [ ] SIEM webhook tested: `SIEM_WEBHOOK_ENABLED=1`, `SIEM_WEBHOOK_URL` points to real SIEM endpoint
- [ ] `DEV_MODE=0` in prod `.env`; confirmed by startup log line `"dev_mode": false`
- [ ] `just test` and `just e2e` pass in CI with `AWS_ACCESS_KEY_ID` unset (offline mode)
- [ ] Integration test suite (`pytest -m integration`) passes in staging with real credentials

### 5.4 Observability

Each provider implementation logs:

- On construction: `<provider>_provider_init mode=mock|prod` — so operators can confirm the right mode is active on startup.
- On first successful operation: `<provider>_provider_first_call` — confirms the provider is reachable in prod.
- On unavailability: `<provider>_provider_unavailable reason=...` — warning, not error (fail-open enrichment paths); error (fail-closed enforcement paths).

### 5.5 Rollback plan

SECOPS-007 is a governance document and pattern library; it has no runtime footprint itself. Rolling back a specific SECOPS capability is done by setting its `*_ENABLED=0` or `*_MOCK_ENABLED=1` flag, as described in the individual ticket's rollback plan. The parity tests provide a regression safety net; a CI failure on `test_no_scattered_dev_mode_in_service_files` immediately flags any violation of the pattern.

### 5.6 Effort estimate and suggested order

**This ticket itself: S (small)** — the patterns exist; the work is documenting them and writing the parity test suite.

**Suggested implementation sequence for dependent tickets**:

1. Write `tests/test_secops007_parity.py` with the AST-walk and provider-selection tests (both will be skipped/fail until SECOPS-005/006 providers exist — that is intentional, they serve as a TDD harness).
2. Implement `app/services/threat_intel/base.py` with `SecurityProvider` and the two provider interfaces.
3. Implement SECOPS-005 providers (mock + Anthropic real) and wire the factory.
4. Implement SECOPS-006 providers (mock + AbuseIPDB real) and wire the factory.
5. Add all new settings fields and `.env.local.example` documentation.
6. Run `just test` in a network-isolated environment to confirm the offline guarantee.
7. Create `docs/prod-readiness.md` checklist.
