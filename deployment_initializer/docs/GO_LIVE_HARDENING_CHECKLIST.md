# Deployment Initializer Go-Live Hardening Checklist (TKT-022)

Status: **SIGNED OFF**  
Ticket: **TKT-022 — Go-live hardening checklist**  
Last updated: **2026-03-01**

## 1) Threat Model Review
- [x] Architecture and data-flow review completed for frontend, backend API, artifact storage, auth, and secret handling.
- [x] Entry points reviewed: `/sessions/*`, `/config/schema`, `/ops/*`, artifact download tokens.
- [x] Abuse cases reviewed: privilege escalation, secret leakage, replay/idempotency bypass, forged deploy requests, audit tampering attempts.
- [x] Mitigations confirmed:
  - RBAC + SSO actor identity checks.
  - Secret redaction in API payloads/events.
  - Immutable audit and deploy event trails.
  - Approval gate for live deploy policy.
  - Idempotency + environment lock controls.
- [x] Security sign-off captured in sign-off table.

## 2) Load/Performance Smoke
- [x] Smoke scenario executed for core API flow:
  1. create session
  2. update config
  3. validate
  4. credential test
  5. generate artifacts
  6. deploy (`dry_run` and `mock`)
- [x] Baseline checks recorded:
  - Validation endpoint latency stable under repeated requests.
  - Deploy timeline/event retrieval remains responsive post-completion.
  - Metrics endpoints (`/ops/metrics`, `/ops/alerts`) return expected payloads.
- [x] Engineering sign-off captured in sign-off table.

## 3) Backup/Recovery Checks
- [x] SQLite DB backup procedure rehearsed.
- [x] Local artifact storage backup/restore rehearsal completed.
- [x] Recovery validation confirmed:
  - Session state is restorable.
  - Audit/event history remains queryable after restore.
  - Artifact metadata and download flow remain functional.
- [x] Ops sign-off captured in sign-off table.

## 4) On-Call + Runbook Handoff
- [x] Primary runbook reviewed with on-call engineers.
- [x] Escalation matrix verified (Eng + Security + Ops).
- [x] Alert-to-runbook mapping verified for repeated deploy failure alerts.
- [x] Rollback procedure walkthrough completed with responders.

## 5) Rehearsal Verification
- [x] Go-live rehearsal run completed using mock-safe deployment path.
- [x] Failure branch rehearsal completed (deterministic mock failure scenario).
- [x] Rollback rehearsal completed within accepted response window.
- [x] Rehearsal evidence linked from launch plan.

## 6) Stakeholder Sign-Off
| Function | Owner | Decision | Date | Notes |
|---|---|---|---|---|
| Engineering | Deployment Platform Lead | ✅ Approved | 2026-03-01 | Readiness and rollback rehearsal accepted. |
| Security | Product Security Lead | ✅ Approved | 2026-03-01 | Threat model review + redaction/audit controls accepted. |
| Operations | SRE/On-Call Manager | ✅ Approved | 2026-03-01 | Backup/restore + pager handoff complete. |

## 7) Exit Criteria
Go-live may proceed only while all of the following remain true:
- [x] No open P0 readiness blockers.
- [x] Launch plan rollback triggers are published and acknowledged.
- [x] On-call schedule and incident channels are staffed.
- [x] Stakeholder approvals remain valid for current release scope.
