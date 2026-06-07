# SECOPS-007: Dev/Prod Environment Parity & AWS Abstraction (governs all SEC/SECOPS tickets)

**Ticket**: SECOPS-007 · **Status**: Open · **Priority**: High (cross-cutting) · **Date**: 2026-06-04
**Scope**: A standing requirement for **every** SEC-0NN and SECOPS-0NN ticket: each must
run fully in the **dev env with NO AWS services and no outbound network**, and in a
**prod env that uses real AWS services**, via the same code path with only the injected
backend differing.

## Principle
Follow the patterns the repo already uses — `app/core/dev_s3.py` (in-process moto),
mock KMS (:7999), DynamoDB Local (:8001), stripe-mock, the GeoIP mock
(`geoip.py` `set_mock_country`), and the integration mock routers. New capabilities get
a **provider interface + factory** selected by `S.dev_mode` and per-feature
`*_ENABLED` / `*_MOCK_ENABLED` flags. No scattered `if dev:` branches in business logic —
centralize selection in the factory. **In dev_mode, real AWS/outbound calls are never
made** (fail-closed on egress); the full pytest + Playwright suite runs offline and
deterministically, with `seed`/`reset` hooks for E2E.

## Capability → Dev (no AWS) vs Prod (AWS)
| Capability (ticket) | Dev backend (no AWS, offline) | Prod backend (AWS) |
|---|---|---|
| `security_events` / `security_blocklist` / canary stores (SECOPS-001/002/003) | DynamoDB Local (:8001) via `app/core/tables.py` | DynamoDB |
| Secrets at rest — AbuseIPDB key, LLM key (SECOPS-006/005, SEC-022) | mock KMS (:7999), encrypted in DDB Local | AWS KMS / Secrets Manager |
| Object storage if used | in-process moto (`dev_s3.py`) | S3 |
| GeoIP **country + ASN** (SECOPS-002) | mock overrides / no-DB fallback → `None` | MaxMind GeoLite2 Country+ASN DB (vendored file or downloaded), offline reader |
| Log sink (SECOPS-001) | stdout / local JSON file | CloudWatch Logs (SIEM ship) |
| Metrics (SECOPS-004) | in-process counters + `/metrics` | Prometheus / CloudWatch |
| Alert delivery (SECOPS-004/005) | mock/log channel (capture for tests) | SES (email) / SNS / Slack webhook |
| LLM analyst (SECOPS-005) | **mock/stub client** — deterministic, no spend, no egress | real provider via stored key (latest Claude) |
| AbuseIPDB report+enrich (SECOPS-006) | **mock client** — no outbound, canned responses | `api.abuseipdb.com` v2 |
| Schedulers (batch analyst, auto-ban decay) | in-process loop (existing pattern) | same (optionally EventBridge) |

## Rules
1. boto3 only via `app/core/aws.py` with `endpoint_url`/creds from settings
   (`DDB_ENDPOINT_URL`, `AWS_*=test`) — never construct clients ad-hoc.
2. Every new external dependency ships a dev mock chosen by flag; `.env.local.example`
   documents the dev defaults; `.env` (prod) documents the real ones. Required secrets
   validated non-empty at startup (mirror `UI_ACCESS_TOKEN_SECRET`).
3. **Graceful degradation**: missing GeoIP/ASN DB or AbuseIPDB key ⇒ that feature
   no-ops with a logged warning and never breaks request handling. Enrichment fails
   *open*; enforcement decisions follow each ticket's stated fail policy
   (`geo_fail_open_dev` already exists).
4. SEC-0NN audit fixes are mostly pure code (auth checks, output escaping, IDOR scoping,
   iCal/CRLF escaping) and are **env-agnostic** — they must not introduce an AWS
   dependency. The AWS-touching ones (SEC-007 dev-gated mock routers, SEC-020 cloud-
   metadata denylist [prod-cloud relevant], SEC-022 KMS) already have dev equivalents.
5. CI / `just test` / `just e2e` must pass with **zero AWS credentials and no internet**.

## Testing
- pytest + Playwright run green with no AWS creds / network blocked.
- Per feature: a dev-mode test asserting no outbound/AWS call is made (mock client used)
  and a parity test asserting the prod provider implements the same interface.
- A `docs/` "prod readiness" checklist: GeoLite2 DB present, KMS key, AbuseIPDB key,
  alert channel configured, log/metric sinks wired.
