# Messaging WebRTC Release Certification (WRTC-052)

Date: 2026-04-05  
Release candidate: `webrtc-direct-calls-v1`

## Readiness checklist

- [x] Feature flag and kill-switch controls validated.
- [x] Cross-browser QA matrix completed (Chromium/Firefox/Safari).
- [x] Reliability/security test suites green.
- [x] Dashboard and alert thresholds published.
- [x] On-call runbook references observability interpretation.
- [x] Deferred defects reviewed and approved.

Evidence references:
- QA matrix: `docs/qa/messaging-webrtc-cross-browser-qa-matrix.md`
- Metrics regression check: `pytest -q tests/test_messaging_call_metrics.py` (pass on 2026-04-05 UTC)

## Certification decision

**Decision:** ✅ Approved for staged rollout under WRTC-051 gates.

## Defect disposition

### Blocking defects
- None.

### Deferred defects with approval
- Firefox/Safari device switching UX parity gap (medium severity; non-blocking).
  - Approval: Product Owner + QA Lead
  - Follow-up: tracked under post-GA UX parity backlog item.

## Post-launch watch window

Window: first **72 hours** after initial stage enablement.

### Ownership

| Role | Owner | Responsibility |
|---|---|---|
| Primary on-call | Messaging backend on-call | API/signaling/lifecycle incidents |
| Secondary on-call | Web platform on-call | Client/browser regressions |
| SRE support | SRE on-call | Alert triage, scaling, infra health |
| Product escalation | Product owner | Rollout/go-no-go decisions |

### Watch metrics

- Setup success rate (warning/critical thresholds from dashboard)
- Setup latency p95
- TURN relay ratio
- Failure taxonomy by reason/stage and browser/platform
- TURN credential issuance failures

### Escalation policy

- Any critical alert sustained beyond threshold pauses rollout progression.
- Any Sev1/Sev2 attributable to calls triggers immediate kill-switch and incident command.

## Sign-off

| Function | Name | Status |
|---|---|---|
| QA Lead | _Approved_ | ✅ |
| Engineering Lead | _Approved_ | ✅ |
| Product Owner | _Approved_ | ✅ |
| SRE Reviewer | _Approved_ | ✅ |
