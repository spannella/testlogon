# DM Lottery Staging Rollout Checklist and Go/No-Go Gate (LOT-504)

## Status

- Ticket: `LOT-504`
- State: `approved-for-staging-rollout`
- Last updated: `2026-04-05`

---

## 1) Scope and prerequisites

This checklist is the required staging gate before any production cohort ramp for DM lottery messages.

Prerequisites:

- LOT-402 observability is deployed and queryable in staging.
- LOT-503 E2E scenario coverage is green in CI and staging smoke runs.
- `docs/dm-lottery-messages-feature-flags-runbook.md` is current and on-call has acknowledged rollback steps.

Linked references:

- `docs/dm-lottery-messages-feature-flags-runbook.md`
- `docs/messaging-lottery-observability.md`
- `docs/dashboards/messaging-lottery-unlock-reliability-dashboard.json`

---

## 2) Pre-flight checklist (must be complete before enablement)

- [ ] **Feature flag readiness**
  - [ ] Confirm `MESSAGING_DM_LOTTERY_ENABLED=false` in staging.
  - [ ] Confirm `MESSAGING_DM_LOTTERY_KILL_SWITCH=false` in staging.
  - [ ] Confirm API effective rule is understood: `enabled = MESSAGING_DM_LOTTERY_ENABLED && !MESSAGING_DM_LOTTERY_KILL_SWITCH`.

- [ ] **Dashboard and alert readiness**
  - [ ] Import/load `messaging-lottery-unlock-reliability-dashboard` in staging Grafana folder.
  - [ ] Validate dashboard variables `environment` and `client_version` resolve staging data.
  - [ ] Validate alerts route to staging on-call channel:
    - `MessagingLotteryUnlockErrorRateHigh`
    - `MessagingLotteryUnlockErrorRateWarn`
    - `MessagingLotteryUnlockLatencyP95High`

- [ ] **Test account and traffic readiness**
  - [ ] Prepare at least 3 test DM pairs across 2 client versions (current + previous).
  - [ ] Ensure one account pair can trigger controlled rate-limit path for validation.
  - [ ] Ensure synthetic traffic script or manual script exists for repeated unlock attempts.

---

## 3) Staging rollout sequence

1. **Enablement step**
   - Set `MESSAGING_DM_LOTTERY_ENABLED=true` in staging.
   - Keep `MESSAGING_DM_LOTTERY_KILL_SWITCH=false`.
   - Roll/reload app configuration.
   - Verify `/messaging/config` reports `messaging_dm_lottery_enabled=true`.

2. **Functional smoke (happy path)**
   - Sender creates a lottery DM with weighted mixed outcomes (text + media).
   - Recipient unlocks once and receives a revealed outcome.
   - Repeat unlock returns idempotent response and same revealed outcome.
   - Reload conversation and confirm revealed state persists.

3. **Negative-path smoke**
   - Attempt unlock on invalid message ID and confirm deterministic error handling.
   - Trigger rate-limited unlock and confirm `rate_limited` outcome increments.
   - Confirm non-lottery messaging flows are unaffected.

4. **Observation window**
   - Run controlled staging traffic for at least 30 minutes.
   - Review dashboard panels for:
     - unlock attempts and successful/idempotent outcomes,
     - unlock error-rate trend,
     - unlock API p95 latency,
     - reveal p95 latency.

---

## 4) Rollback drill (required before go decision)

Execute the rollback drill in staging and capture evidence (screenshots or logs).

1. Set `MESSAGING_DM_LOTTERY_KILL_SWITCH=true`.
2. Roll/reload app configuration.
3. Verify `/messaging/config` reports `messaging_dm_lottery_enabled=false`.
4. Validate blocked behavior:
   - `POST /messaging/messages/lottery` returns `403` with `code=feature-disabled`.
   - `POST /messaging/messages/{message_id}/lottery/unlock` returns `403` with `code=feature-disabled`.
5. Verify no regressions for non-lottery message send/read paths.
6. Reset to staging test posture:
   - `MESSAGING_DM_LOTTERY_KILL_SWITCH=false`
   - keep `MESSAGING_DM_LOTTERY_ENABLED=true` for final gate window.

Rollback drill result: **[ ] pass  [ ] fail**

---

## 5) Objective go / no-go metric gates (LOT-402 aligned)

All gates below must pass simultaneously for one continuous 30-minute window in staging.

### Reliability gates

- **Unlock error-rate (critical gate):**
  - `unlock_error_rate = non_success_or_idempotent_unlock_results / unlock_attempts`
  - Required: **`< 5%`** (strictly below the LOT-402 warning threshold).
  - Immediate no-go if sustained **`>= 15%`** for 10 minutes (matches LOT-402 critical threshold).

### Performance gates

- **Unlock API p95 latency:**
  - Required: **`<= 2.0s`** (safety margin under LOT-402 2.5s warning threshold).
- **Reveal p95 latency:**
  - Required: **`<= 1.5s`** in staging synthetic + manual mix.

### Outcome quality / guardrail gates

- **Idempotency quality:**
  - Repeated unlock attempts for same recipient/message must return identical outcome ID in 100% of tested cases.
- **Rate-limit sanity:**
  - `rate_limited` outcomes should remain within expected test envelope and not exceed **20%** of total unlock results unless load test intentionally exceeds quota.

If any gate fails, decision is **NO-GO**, hold rollout, and execute remediation + repeat full checklist.

---

## 6) Stakeholder sign-off

Complete after checklist and gate evidence are attached.

| Stakeholder | Owner | Decision | Date | Notes |
|---|---|---|---|---|
| Engineering (Backend/Frontend) |  | [ ] Go [ ] No-Go |  |  |
| QA |  | [ ] Go [ ] No-Go |  |  |
| SRE / Operations |  | [ ] Go [ ] No-Go |  |  |
| Product |  | [ ] Go [ ] No-Go |  |  |

Final decision: **[ ] GO** / **[ ] NO-GO**

---

## 7) Production ramp recommendation (post sign-off)

If final decision is GO:

1. Start production at internal/canary cohort only.
2. Require at least one full healthy gate window in production canary before expansion.
3. Pause progression on any warning breach; rollback immediately on critical breach.

If final decision is NO-GO:

1. Keep production flags disabled.
2. File follow-up defects with metric evidence.
3. Re-run staging checklist after fixes are validated.
