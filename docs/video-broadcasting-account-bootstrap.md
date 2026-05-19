# Video Broadcasting AWS Account Bootstrap Runbook (BRD-002)

- **Ticket:** BRD-002
- **Status:** Implemented
- **Date:** 2026-03-25
- **Owner:** Platform Engineering
- **Related ADR:** `docs/adr/ADR-0002-video-broadcasting-pipeline.md`

## Purpose

This runbook defines the pre-implementation cloud readiness work for the broadcasting pipeline:
- service quotas,
- cost model baseline,
- account bootstrap checklist (IAM, KMS, S3, tagging).

It is intended to be executable in a clean AWS account and region.

---

## 1) Target Regions and Environments

| Environment | Primary Region | Secondary Region | Notes |
|---|---|---|---|
| dev | us-east-1 | n/a | single-region for developer validation |
| staging | us-east-1 | us-west-2 | optional failover drills |
| prod | us-east-1 | us-west-2 | secondary reserved for DR roadmap |

---

## 2) Quota Request Matrix

> Fill in account-specific values before submission. These are the minimum planning targets for MVP.

| Service | Quota Area | Default Risk | MVP Target | Why |
|---|---|---|---|---|
| MediaLive | Inputs per region | may block provisioning | 25 | supports concurrent channels + test margin |
| MediaLive | Running channels per region | hard cap on live sessions | 20 | planned concurrency headroom |
| MediaPackage | Channels/endpoints | endpoint creation failures | 30 | profile growth and test environments |
| CloudFront | Distributions/origins | onboarding latency | 10 distributions (or shared pattern) | supports env split + rollback |
| KMS | Encrypt/decrypt TPS | secret/token burst risk | validate > expected peak | stream key + token operations |
| S3 | Request rate / bucket policy limits | archive write bottlenecks | verify with load test | sustained segment/object writes |

### Quota workflow
1. Validate current quotas in target region(s).
2. File increase requests for any field below target.
3. Record approval IDs and ETA in launch tracker.
4. Re-run preflight script before Phase 3 integration work.

### Quota readiness gate
- All quota requests are either:
  - **approved**, or
  - **mitigated** with documented lower concurrency limits and launch guardrails.

---

## 3) Cost Model Baseline (MVP)

## 3.1 Cost dimensions

For each live broadcast session, capture these cost dimensions:
- MediaLive channel runtime (per active channel hour by profile class).
- MediaPackage packaging/egress requests.
- CloudFront egress and request pricing.
- S3 archive storage growth + PUT/list requests.
- KMS + Secrets Manager usage for key material access.
- Observability (CloudWatch metrics/logs/alarms).

## 3.2 Scenario matrix

| Scenario | Concurrent Sessions | Avg Session Length | Monthly Session Hours | Notes |
|---|---:|---:|---:|---|
| low | 2 | 1.0 hr | 120 | internal pilot |
| baseline | 8 | 1.5 hr | 1,440 | initial launch assumption |
| burst | 20 | 2.0 hr | 4,800 | quota/cost stress case |

## 3.3 Estimation formula template

Use this template in pricing spreadsheet:

`TotalMonthly = (MediaLiveRate * SessionHours) + (MediaPackageRate * SessionHours) + (CloudFrontEgressGB * RateGB) + (S3StorageGB * RateGBMonth) + (S3Requests * RequestRate) + (KMSRequests * KMSRate) + (SecretsCalls * SecretsRate) + (ObservabilityFixed + ObservabilityVariable)`

## 3.4 Cost estimation sheet deliverable

- Baseline per-hour estimate sheet is committed at:
  - `docs/video-broadcasting-cost-estimation.csv`
- Sheet includes initial per-hour estimates for launch rendition profiles (`540p`, `720p`, `1080p`) and should be updated during pricing review.

## 3.5 Budget controls

- Set monthly budget alarms per environment.
- Alert at 50%, 80%, and 100% threshold.
- Define automatic launch guardrail: reject new session starts if projected monthly cost crosses policy threshold (except admin override).

---

## 4) Account Bootstrap Checklist (Clean Account)

## 4.1 IAM and roles

- [ ] Create `BroadcastOrchestratorRole` (application-assumed role).
- [ ] Grant least-privilege actions for MediaLive, MediaPackage, CloudFront, S3, KMS, CloudWatch.
- [ ] Add deny-by-default boundary policy.
- [ ] Restrict resource ARNs by environment prefix/tag.

## 4.2 KMS and secrets

- [ ] Create KMS CMK(s):
  - `alias/broadcast-stream-keys`
  - `alias/broadcast-drm-keys`
- [ ] Configure key policy for app role + security admin breakglass role.
- [ ] Create secret namespace:
  - `/broadcast/{env}/stream-keys/*`
  - `/broadcast/{env}/drm/*`
- [ ] Enable key rotation policy and audit logging.

## 4.3 S3 archive foundation

- [ ] Create archive bucket: `broadcast-archive-{env}-{account}-{region}`.
- [ ] Enable default encryption (KMS).
- [ ] Enable versioning.
- [ ] Configure lifecycle:
  - transition to infrequent access class,
  - transition to archival class,
  - expiration aligned to retention policy.
- [ ] Block public access at bucket/account level.

## 4.4 CloudFront baseline

- [ ] Create (or designate) distribution strategy:
  - shared distribution with path routing, or
  - per-environment distribution.
- [ ] Attach security headers policy.
- [ ] Configure signed URL/cookie validation integration point.
- [ ] Attach WAF ACL and geo-policy defaults if required by policy.

## 4.5 Observability baseline

- [ ] Create CloudWatch log groups with retention policy.
- [ ] Create dashboards for provision/start/stop success rates and latency.
- [ ] Create alarms for:
  - MediaLive input loss,
  - channel state errors,
  - orchestrator failure spikes,
  - budget threshold breaches.
- [ ] Configure alarm routing to incident channel/on-call.

## 4.6 Tagging and governance

- [ ] Enforce required tags on all resources:
  - `service=broadcasting`
  - `env={dev|staging|prod}`
  - `owner=platform`
  - `data_classification`
  - `cost_center`
- [ ] Add policy check in CI for missing/invalid tags.

---

## 5) Preflight Verification Commands (Operator Checklist)

Run this script prior to AWS integration development:

```bash
python3 scripts/check_broadcast_account_ready.py --account-id <aws-account-id> --env <dev|staging|prod> --region <region>
```

The script validates:
- quota targets (or flags explicit fallback requirement),
- required IAM role,
- required KMS aliases,
- archive S3 bucket.

Then run or verify the following additional controls:

1. Verify caller/account context.
2. Validate all required roles and policies exist.
3. Validate KMS keys + aliases exist and policy grants app role.
4. Validate S3 archive bucket policy + lifecycle.
5. Validate CloudWatch alarms/dashboard deployment state.
6. Validate service quotas satisfy MVP targets.

Fallback policy for missing quota approvals:
- Document temporary launch concurrency cap.
- Record quota increase request ID + ETA.
- Capture approval owner and risk acceptance in launch tracker.

---

## 6) Exit Criteria for BRD-002

BRD-002 is complete when:
- quota matrix is populated with real account values and approval states,
- cost spreadsheet is published with baseline + burst scenarios,
- clean-account bootstrap checklist is executed and signed off,
- readiness gate result is recorded for target launch region.
