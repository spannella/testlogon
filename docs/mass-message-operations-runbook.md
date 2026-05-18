# Mass Messaging Operations Runbook (MSG-032)

## Scope
Operational procedures for rollout, incident response, stuck campaigns, retry storms, and rollback of mass messaging campaigns.

**Service owner:** Messaging Platform Team  
**Primary on-call:** `#team-messaging-oncall`  
**Secondary escalation:** Site Reliability Engineering (`#sre-oncall`)  
**Executive escalation:** Engineering Manager, Messaging

---

## 1) Rollout checklist

1. Confirm feature flags and guardrails:
   - `MESSAGING_MASS_SEND_ENABLED=true`
   - `MESSAGING_MASS_SEND_KILL_SWITCH=false`
   - `MESSAGING_MASS_SEND_CAMPAIGNS_PER_USER_PER_HOUR`
   - `MESSAGING_MASS_SEND_CAMPAIGNS_PER_TENANT_PER_HOUR`
   - `MESSAGING_MASS_SEND_MAX_DESTINATIONS_PER_CAMPAIGN`
   - `MESSAGING_MASS_SEND_MAX_CONCURRENT_WORKERS`
2. Apply migrations:
   ```bash
   python scripts/migrations/20260405_mass_message_campaigns_schema.py
   python scripts/migrations/20260405_mass_message_campaign_destinations_schema.py
   ```
3. Verify health + config:
   ```bash
   curl -sS "$API_BASE/messaging/healthz"
   curl -sS -H "Authorization: Bearer $TOKEN" "$API_BASE/messaging/config" | jq
   ```
4. Validate control metrics are ingesting:
   - `messaging_mass_campaign_events_total`
   - `messaging_mass_destination_outcomes_total`
   - `messaging_mass_destination_retries_total`
   - `messaging_mass_worker_latency_seconds`
   - `messaging_mass_limit_events_total`

---

## 2) Diagnostics playbook

### A. Campaign creation failures / rate limiting
1. Inspect API response for stable codes:
   - `mass_send_user_rate_limited`
   - `mass_send_tenant_rate_limited`
   - `mass_send_destinations_limit_exceeded`
   - `mass_send_worker_capacity_exceeded`
2. Confirm enforcement metrics:
   ```promql
   sum by (scope,limit_name,outcome) (increase(messaging_mass_limit_events_total[15m]))
   ```
3. Validate current throttles from runtime env/settings.

### B. Stuck campaign (pending/scheduled/processing not progressing)
1. Fetch campaign status:
   ```bash
   curl -sS -H "Authorization: Bearer $TOKEN" \
     "$API_BASE/messaging/mass-messages/$CAMPAIGN_ID?limit=200" | jq
   ```
2. Check destination states and counters mismatch.
3. Review worker logs for:
   - `messaging_mass_campaign_completed`
   - repeated destination errors / retries
4. Manually trigger scheduled dispatcher (if safe in environment) from admin shell:
   ```python
   from app.routers.messaging import dispatch_due_scheduled_mass_campaigns
   print(dispatch_due_scheduled_mass_campaigns(limit=100))
   ```

### C. Retry storm
1. Check retry error concentration:
   ```promql
   sum by (mode,error_code) (increase(messaging_mass_destination_retries_total[10m]))
   ```
2. Check failure ratio:
   ```promql
   (
     sum(rate(messaging_mass_destination_outcomes_total{outcome="failed"}[5m]))
     /
     clamp_min(sum(rate(messaging_mass_destination_outcomes_total[5m])), 1e-9)
   )
   ```
3. If dominated by `transient_infra`, inspect dependent services (DDB, event fanout, queue/network).

---

## 3) Remediation commands

### A. Immediate safety stop (incident mitigation)
```bash
export MESSAGING_MASS_SEND_KILL_SWITCH=true
```

### B. Reduce blast radius without full stop
```bash
export MESSAGING_MASS_SEND_CAMPAIGNS_PER_USER_PER_HOUR=5
export MESSAGING_MASS_SEND_CAMPAIGNS_PER_TENANT_PER_HOUR=100
export MESSAGING_MASS_SEND_MAX_DESTINATIONS_PER_CAMPAIGN=25
export MESSAGING_MASS_SEND_MAX_CONCURRENT_WORKERS=2
```

### C. Drain and recover
1. Re-enable only after dependency health is green.
2. Increase limits gradually (25% steps every 15–30 minutes) while watching:
   - failure ratio alert
   - worker-latency alert
   - limit blocks (`messaging_mass_limit_events_total{outcome="blocked"}`)

---

## 4) Rollback procedure

> Use only when schema/code rollback is necessary (not for transient traffic incidents).

1. Enable kill switch.
2. Roll back app deploy to previous stable release.
3. If destructive schema rollback is explicitly approved in non-prod:
   ```bash
   APP_ENV=staging python scripts/migrations/20260405_mass_message_campaign_destinations_schema.py --rollback --allow-destructive
   APP_ENV=staging python scripts/migrations/20260405_mass_message_campaigns_schema.py --rollback --allow-destructive
   ```
4. Validate:
   - API error responses are controlled
   - no worker threads continue processing
   - alert volume returns to baseline

---

## 5) Escalation path

1. **On-call Messaging engineer** acknowledges within 5 minutes for page alerts.
2. If unresolved in 15 minutes, page **SRE on-call**.
3. If customer-impacting for >30 minutes, engage **Engineering Manager (Messaging)** and incident commander.
4. Record incident timeline, impacted campaign IDs, and mitigation actions in postmortem ticket.
