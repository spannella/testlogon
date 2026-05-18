# Payment Incident Rollout + Backfill Runbook (PDM-019)

This runbook defines staged rollout, shadow validation, reconciliation/backfill execution, and rollback for Payment Incident GA.

## 1) Feature flags (staged rollout)

Use the following environment flags:

- `PAYMENT_INCIDENTS_ROLLOUT_ENABLED` (`0|1`): global gate for payment-incident ingestion.
- `PAYMENT_INCIDENTS_ROLLOUT_PROVIDERS`: CSV allowlist (`stripe,paypal,ccbill`).
- `PAYMENT_INCIDENTS_SHADOW_MODE` (`0|1`): global shadow validation mode.
- `PAYMENT_INCIDENTS_SHADOW_PROVIDERS`: provider-level shadow override.
- `PAYMENT_INCIDENTS_BACKFILL_APPLY_ENABLED` (`0|1`): required to run backfill in apply mode.

### Rollout phases

1. **Shadow phase**
   - Set `PAYMENT_INCIDENTS_ROLLOUT_ENABLED=1`
   - Set `PAYMENT_INCIDENTS_SHADOW_MODE=1` or shadow selected providers via `PAYMENT_INCIDENTS_SHADOW_PROVIDERS`.
   - Validate webhook verification/parsing without writes.
   - Confirm `payment_incident_rollout_shadow_validated` audit events and compare event counts to provider logs.

2. **Provider canary**
   - Keep shadow for two providers.
   - Set live provider in `PAYMENT_INCIDENTS_ROLLOUT_PROVIDERS` and remove that provider from shadow.
   - Monitor dashboards/alerts for 24h.

3. **Full live rollout**
   - Set all providers live (`stripe,paypal,ccbill`), disable shadow mode.
   - Verify incident lifecycle metrics and ticketing SLAs are stable.

## 2) Reconciliation + backfill

Script: `scripts/payment_incident_backfill_reconcile.py`

### Dry-run

```bash
python scripts/payment_incident_backfill_reconcile.py --scan-limit 250 --out .artifacts/pdm019_backfill_dryrun.json
```

Expected:
- deterministic report payload (`report_version=1`, sorted `missing` list),
- explicit `missing_count` and gap rows.

### Apply

```bash
export PAYMENT_INCIDENTS_BACKFILL_APPLY_ENABLED=1
python scripts/payment_incident_backfill_reconcile.py --apply --scan-limit 250 --out .artifacts/pdm019_backfill_apply.json
```

Expected:
- `applied_count` equals intended backfill subset,
- deterministic `applied_incident_ids`.

## 3) Launch checklist

Use `docs/payment-incident-launch-checklist.json` for go/no-go signoff:
- Eng, Ops, and Support approvals,
- shadow parity evidence attached,
- backfill report attached,
- rollback owner and execution window confirmed.

## 4) Rollback steps

1. Set `PAYMENT_INCIDENTS_ROLLOUT_ENABLED=0` (immediate kill switch).
2. If partial provider rollback required, remove provider from `PAYMENT_INCIDENTS_ROLLOUT_PROVIDERS`.
3. Re-enable shadow-only mode (`PAYMENT_INCIDENTS_SHADOW_MODE=1`) for diagnostics.
4. Pause backfill apply runs (`PAYMENT_INCIDENTS_BACKFILL_APPLY_ENABLED=0`).
5. Open incident ticket and include:
   - dashboard snapshots,
   - failing provider/event IDs,
   - latest shadow-validation audit evidence.

## 5) On-call/support readiness sign-off

Minimum required:

- [ ] Support reviewed customer/admin retry escalation paths.
- [ ] On-call simulated alert triage for webhook failure spike + retry terminal failure spike.
- [ ] Backfill dry-run and apply run output reviewed by Billing + Ops.
- [ ] Escalation contacts verified in incident rotation.
