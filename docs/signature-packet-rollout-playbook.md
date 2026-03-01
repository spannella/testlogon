# Signature Packet Internal Dogfood + Staged Rollout Playbook (SFP-071)

## Objective
Roll out signature packets safely using progressive exposure gates, measurable success criteria, and explicit rollback triggers.

## Feature-flag strategy
- Primary gate: `SIGNATURE_PDF_ENABLED`
  - `false` by default in non-approved environments/users.
  - enable only for approved internal cohort during dogfood.
- Optional operational safety limits (already supported by config):
  - `SIGNATURE_PACKET_MAX_SIGNERS`
  - `SIGNATURE_PACKET_MAX_FIELDS`
  - `SIGNATURE_PACKET_RENDERER_TIMEOUT_SECONDS`
  - `SIGNATURE_PACKET_EXPIRATION_HOURS`

## Rollout phases

### Phase 0 — Preflight (staging)
**Goal:** confirm baseline reliability before user exposure.

Checklist:
- [ ] Signature packet API routes healthy in staging.
- [ ] Render worker running and processing completed packets.
- [ ] Dashboard imported: `docs/dashboards/signature-packet-ops-dashboard.json`.
- [ ] Alerts configured from `docs/signature-packet-observability.md`.
- [ ] Support team validated packet event timeline endpoint (`GET /v1/signature-packets/{id}/events`).

Exit criteria:
- No sustained render failure alert for 24h.
- p95 render latency below 30s.

---

### Phase 1 — Internal dogfood (employees only)
**Goal:** validate core sender/signer workflows with known internal users.

Cohort criteria:
- Internal users only (employees + QA + support).
- Include at least:
  - 10 active senders,
  - 20 signers,
  - 30 multi-signer packets,
  - both origin channels (`share`, `message`).

Success metrics:
- Funnel progression healthy:
  - `packet_created -> packet_sent -> signer_completed -> packet_completed` conversion within expected ranges.
- Render reliability:
  - render failure rate < 1% over 7-day window.
- Time-to-complete:
  - median packet completion under internal target (e.g., < 24h for dogfood set).
- No Sev-1/Sev-2 incidents attributable to signature packets.

Rollback triggers:
- Render failure rate >= 3% for 30 minutes.
- p95 render latency > 60s for 30 minutes.
- Stuck packet proxy trend exceeds threshold for 2 consecutive hours.
- Any data integrity/security issue (wrong participant access, artifact mismatch, audit-gap).

Rollback action:
1. Set `SIGNATURE_PDF_ENABLED=false` in target environment.
2. Keep read/download paths available for already completed packets.
3. Announce freeze in #team-signatures-oncall and incident channel.
4. Run incident triage with packet events + metrics dashboard.

---

### Phase 2 — Beta cohort (external limited)
**Goal:** validate product-market behavior with controlled customer exposure.

Beta cohort criteria:
- 1–5% of eligible tenants.
- Mix of single-signer and multi-signer usage.
- Exclude high-risk/compliance-sensitive tenants unless explicitly opted-in.

Operational guardrails:
- Daily review of dashboard and alert noise.
- Weekly support review of top incident themes.
- Maintain fast rollback (feature-flag) at all times.

Success metrics:
- Completion rate and failure rate remain within dogfood variance bands.
- No increase in unauthorized access/tamper events beyond baseline.
- Support ticket rate per 100 packets below defined threshold.

Rollback triggers:
- Two consecutive days of metric regression beyond thresholds.
- Any P1 security or access boundary incident.

---

### Phase 3 — General availability decision gate
**Goal:** explicit go/no-go decision for full rollout.

GA decision gate (must all pass):
- [ ] 14-day beta reliability window completed.
- [ ] Render success rate >= 99% and p95 render latency <= 30s.
- [ ] No unresolved P1/P2 incidents.
- [ ] Support runbook validated by support lead.
- [ ] Product + Engineering + Support sign-off recorded.

If passed:
- Increase rollout to 100% eligible tenants.
- Keep alerts and rollback runbook active for at least first 30 days.

If failed:
- Remain in beta or revert to internal-only until remediations ship and pass re-evaluation.

## Ownership and escalation
- Primary owner: Signatures backend team (`#team-signatures-oncall`).
- Secondary owner: Platform reliability (`#team-platform-reliability`).
- Escalation:
  1. Signatures on-call
  2. Platform reliability on-call
  3. Incident commander for customer-impacting events

## Rollout reporting template (daily during dogfood/beta)
- Exposure level (% tenants/users)
- Packets created/sent/completed
- Render success/failure + p95 latency
- Top 3 failure reasons
- Open incidents and mitigations
- Go/hold/rollback recommendation
