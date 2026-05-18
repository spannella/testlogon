# Mass Messaging Deployment & Staged Rollout Plan (MSG-033)

## Objective
Safely deploy mass messaging with strict sequencing, canary validation, and explicit go/no-go gates.

---

## Deployment sequencing (required order)

### Phase 0 — Preflight
- Confirm on-call coverage and incident channel (`#team-messaging-oncall`).
- Confirm rollback operator access and migration permissions.
- Verify latest alert rules are loaded:
  - `MessagingMassCampaignHighFailureRate`
  - `MessagingMassCampaignWorkerLagP95High`

### Phase 1 — Schema rollout **before API/worker usage**
1. Apply table migrations:
   ```bash
   python scripts/migrations/20260405_mass_message_campaigns_schema.py
   python scripts/migrations/20260405_mass_message_campaign_destinations_schema.py
   ```
2. Verify tables/indexes exist and are ACTIVE.
3. Keep feature disabled during this phase:
   - `MESSAGING_MASS_SEND_ENABLED=false`
   - `MESSAGING_MASS_SEND_KILL_SWITCH=true`

> **Gate:** No API/worker traffic is allowed until schema rollout is complete and verified.
>
> **Staging validation command (must pass):**
> ```bash
> python scripts/check_mass_message_rollout_validation.py \
>   --api-base "$API_BASE" \
>   --token "$MASS_MESSAGE_VALIDATION_TOKEN" \
>   --run-regression-suite
> ```

### Phase 2 — API deploy (dark mode)
1. Deploy application containing API + worker code paths.
2. Keep mass send disabled:
   - `MESSAGING_MASS_SEND_ENABLED=false`
3. Smoke checks:
   ```bash
   curl -sS "$API_BASE/messaging/healthz"
   curl -sS -H "Authorization: Bearer $TOKEN" "$API_BASE/messaging/config" | jq
   ```

### Phase 3 — Controlled worker enablement
1. Enable feature with conservative limits:
   ```bash
   export MESSAGING_MASS_SEND_ENABLED=true
   export MESSAGING_MASS_SEND_KILL_SWITCH=false
   export MESSAGING_MASS_SEND_CAMPAIGNS_PER_USER_PER_HOUR=3
   export MESSAGING_MASS_SEND_CAMPAIGNS_PER_TENANT_PER_HOUR=30
   export MESSAGING_MASS_SEND_MAX_DESTINATIONS_PER_CAMPAIGN=20
   export MESSAGING_MASS_SEND_MAX_CONCURRENT_WORKERS=1
   ```
2. Validate metrics emit:
   - `messaging_mass_campaign_events_total`
   - `messaging_mass_destination_outcomes_total`
   - `messaging_mass_destination_retries_total`
   - `messaging_mass_worker_latency_seconds`
   - `messaging_mass_limit_events_total`

---

## Canary rollout phases

### Canary A (internal-only, 30 min)
- Scope: internal test users only.
- Traffic: ≤ 10 campaigns total.
- Success criteria:
  - failure ratio < 5%
  - p95 worker latency < 15s
  - no sustained retry growth (`transient_infra`)
- No-go conditions:
  - any paging alert firing > 10 min
  - repeated worker-capacity errors under low load

### Canary B (1% tenant slice, 60 min)
- Scope: selected low-risk tenants.
- Limits:
  - concurrent workers ≤ 2
  - destinations per campaign ≤ 25
- Success criteria:
  - failure ratio < 8%
  - no stuck campaigns (`pending/processing` > 15m without progress)
  - support tickets within expected baseline

### Canary C (10% tenant slice, 2–4 hours)
- Gradually raise:
  - worker concurrency to 3–4
  - per-user and per-tenant hourly quotas
- Success criteria:
  - stable failure ratio and worker latency
  - alert noise below incident threshold

### General availability
- Enable for all tenants after Canary C pass and approval from Messaging + SRE on-call.

---

## Go / No-Go gates

## Go gate checklist
- [ ] Schema migration complete and verified before feature enablement.
- [ ] Alerts and runbook links validated in monitoring stack.
- [ ] Canary success criteria met for latest phase.
- [ ] No active Sev-1/Sev-2 messaging incidents.
- [ ] Messaging + SRE on-call explicit approval.

## No-Go / rollback conditions
- [ ] Destination failure ratio >= 20% for 10m.
- [ ] Worker p95 latency >= 30s for 15m.
- [ ] Sustained retry storm (`transient_infra`) with user-visible impact.
- [ ] Stuck campaign backlog increasing for > 15m.
- [ ] Data consistency concerns (counter/destination divergence).

If any no-go condition is met:
1. Set kill switch immediately:
   ```bash
   export MESSAGING_MASS_SEND_KILL_SWITCH=true
   ```
2. Pause rollout and stabilize dependencies.
3. Follow incident flow in `docs/mass-message-operations-runbook.md`.

---

## Rollback execution summary

1. Disable traffic (`MESSAGING_MASS_SEND_KILL_SWITCH=true`).
2. Revert application to last known-good release.
3. Keep schema in place unless a destructive rollback is explicitly approved for non-prod.
4. Re-run canary from Phase 3 after remediation.
