# iCloud Mount On-Call Quick Reference

## Fast Classification

- **Auth storm:** auth failures rising, verify failures, lockouts.
- **Provider outage:** 5xx/throttled + latency spike + degraded transitions.
- **Credential compromise:** suspicious secret access or leaked credentials.

## First 10 Minutes

1. Acknowledge alert and open incident channel.
2. Confirm blast radius (`provider`, `mount_id`, tenants).
3. Apply guardrail:
   - auth storm -> tighten verify/onboarding pressure,
   - outage -> keep/read-only degraded mode,
   - compromise -> revoke + rotate + invalidate sessions.
4. Send initial customer advisory (use template doc below).

## Must-Check Dashboards

- Filemanager Provider Health dashboard:
  - p50/p95 latency by provider,
  - error rate / 5xx rate,
  - auth failures by mount.
- Mount secret access dashboard for suspicious reads/rotations.

## Escalation and paging

- Use `docs/runbooks/icloud-mount-incident-response-playbook.md` pager threshold matrix as source of truth.
- If no acknowledgment within 5 minutes for P1, escalate immediately to secondary on-call.
- For security indicators, page Security On-Call immediately.

## Customer comms templates

- `docs/runbooks/icloud-mount-customer-comms-templates.md`

## Closure Criteria

- Error and auth failure signals below thresholds for 30+ minutes.
- No active security anomalies.
- Customer update posted.
- Follow-up action items logged.
