# Deployment Initializer Launch Plan and Rollback Criteria (TKT-022)

Status: **Approved for controlled launch**  
Related checklist: `deployment_initializer/docs/GO_LIVE_HARDENING_CHECKLIST.md`

## 1) Launch Strategy
### Phase 0 — Internal rehearsal (complete)
- Use mock mode + dry-run paths only.
- Validate event timeline, metrics visibility, approvals, and audit attribution.
- Confirm alert routing and runbook links.

### Phase 1 — Limited operator pilot
- Enable operator access for a small approved cohort.
- Keep live deploy approval policy enabled (`DEPLOY_REQUIRE_TWO_PERSON_APPROVAL=true`).
- Monitor validation failure trends and deploy success rate.

### Phase 2 — Broader internal availability
- Expand operator cohort after pilot SLOs are stable.
- Continue daily checks for alert noise and rollback readiness.

## 2) SLO Gates for Advancement
A phase can advance only when all gates pass for the observation window:
- Validation failure rate within expected baseline and no unexplained spike.
- Deploy success rate above agreed threshold.
- Deploy duration remains within acceptable envelope.
- No unresolved security-critical incidents.

## 3) Alerting and Operational Readiness
- Repeated deploy failure alerts must page on-call and include runbook links.
- Metrics and dashboards must remain queryable before phase promotion.
- Incident commander, comms lead, and technical lead must be assigned for each launch window.

## 4) Rollback Triggers
Immediate rollback is required if any of the following occur:
- Repeated deploy failures breach configured alert threshold.
- Authorization or redaction regression is detected.
- Audit/event timeline becomes unavailable for deploy tracking.
- Backup or restore validation fails during launch window.

## 5) Rollback Procedure
1. Freeze new deploy actions (set deploy mode to dry-run/mock only).
2. Notify stakeholders in incident channel and launch channel.
3. Revoke expanded operator rollout (return to prior allowlist).
4. Restore last known good DB/artifact snapshot if data integrity is at risk.
5. Verify health, auth, audit, and metrics endpoints after rollback.
6. Publish incident summary with remediation actions before reattempting launch.

## 6) Communications Plan
- **Pre-launch:** announce scope, schedule, owners, and rollback triggers.
- **During launch:** post milestone updates at each phase gate.
- **On rollback:** send immediate status, impacted scope, ETA for stabilization.
- **Post-launch:** publish outcomes and follow-up action items.

## 7) Rehearsal Record
- Rehearsal type: full control-plane flow (`create -> configure -> validate -> test credentials -> generate -> deploy`).
- Modes executed: `dry_run`, `mock` success, and deterministic mock failure branch.
- Outcome: rollback procedure verified end-to-end and accepted by Eng/Sec/Ops.
