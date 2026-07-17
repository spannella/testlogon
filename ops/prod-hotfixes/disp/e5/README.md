# DISP E5 — notifications + reconciliation audit + webhook deconfliction + rollout hardening

Tickets: **DISP-050** (notifications), **DISP-051** (reconciliation audit), **DISP-052**
(deconflict the two Stripe webhook seams), **DISP-053** (rollout/shadow hardening +
go-live checklist), **DISP-054** (scope decisions).

## What this fold does

- **`dispute_notify.py`** (NEW) — the single notification seam for BOTH tracks. Every
  dispute state change persists an Alerts row (`write_alert`) with an explicit relative
  deep-link AND fires a tappable PUSH (`send_push_for_alert`). Gated by
  `S.dispute_notifications_enabled` (default ON). Deep-links: payer →
  `/billing/disputes/{id}`, creator/seller → `/creator/disputes/{id}`.
    - USER track: `notify_opened` (payer + creator on file), `notify_needs_response`
      (creator on window open), `notify_creator_responded` (payer on rebuttal),
      `notify_resolved` (both parties per refunded/partial/denied).
    - PROCESSOR track: `notify_chargeback_opened` + `notify_evidence_due` (creator on
      `charge.dispute.created`), `notify_chargeback_terminal` (creator on LOST/WON).
- **`alerts.py`** — dispute events added to `ALERT_EVENT_TYPES` (valid registry) AND
  `DEFAULT_PUSH_EVENT_TYPES` (default-ON transactional push, opt-out not opt-in).
- **`settings.py`** — `dispute_notifications_enabled` master flag.
- **`billing_disputes.py`** — `file_dispute` + `resolve_dispute` route through `dispute_notify`.
- **`dispute_lifecycle.py`** — `open_response_window` + `record_creator_response` route
  through `dispute_notify`.
- **`dispute_chargeback.py`** — `on_incident_transition` fires chargeback opened/evidence-
  due/terminal notifications.
- **`subscription_server.py`** (DISP-052) — the subs `billing_webhook` now explicitly
  ignores `charge.dispute.*` / `charge.refund.*` (returns `ignored=dispute_event_owned_by_
  payment_incidents`). `charge.dispute.*` is owned SOLELY by the PaymentIncident endpoint
  `POST /api/billing/webhooks/stripe` (secret `STRIPE_WEBHOOK_SECRET`), distinct from the
  subs secret `SUBSCRIPTION_WEBHOOK_SECRET`. One dispute event → exactly one ledger path.

## DISP-051 reconciliation audit
The E5 verify harness proves the reconciliation invariant live: after a refunded dispute,
NO `type=="credit"` row with `state!="reversed"` remains for the charge (nothing inflates
`get_available_balance`). Combined with the per-transition `audit_event` trail already
emitted by the lifecycle/chargeback services, every terminal dispute is auditable and
net-reconciles T.billing. The honesty invariant is enforced structurally by the shared
reversal rails (E0): every reversal writes a NON-credit type + flips the original credit
`state=reversed`, and `get_available_balance` counts only live credits.

## DISP-053 rollout / go-live (unchanged from E3, re-confirmed)
- User track master: `S.billing_disputes_enabled` (default ON).
- Processor track: `payment_incidents_rollout_enabled` + `payment_incidents_rollout_providers`
  + `payment_incidents_shadow_mode`/`payment_incidents_shadow_providers` — ship **shadow**
  (parse+validate+audit, zero ledger writes) → promote **live** per provider after a clean
  shadow window (`billing.py` `_payment_incident_rollout_mode`).
- Real-when-keyed: `stripe_webhook_secret` present + `stripe` SDK installed → signature-
  verify + `Dispute.retrieve/modify(evidence=)` + real fee amount go live; absent →
  recorded-not-sent (mock-that-records).
- `S.dispute_chargeback_reconcile_enabled`, `S.dispute_chargeback_fee_policy`
  (creator_eats|platform_eats), `S.dispute_auto_refund_threshold_cents`,
  `S.dispute_dual_approval_threshold_cents`.

## DISP-054 scope decisions (locked)
(i) pay-to-message access revoke on refund = YES (rides the tip rail, reversal flips the
credit); (ii) partial-tip disallowed in v1 (partial override only ecom/sub — enforced by
`dispute_lifecycle`); (iii) chargeback-fee = `creator_eats` default (flag
`dispute_chargeback_fee_policy`); (iv) auto-refund threshold + 7d response window
(`dispute_auto_refund_threshold_cents`, `dispute_response_window_days`); (v) chargeback on
a sub charge claws the sub credit + revokes via the clawback-only rail (does not by itself
cancel the sub subscription record — access follows the credit/entitlement, sub lifecycle
is separate).

## Apply on PROD
```
set -a; . .env.local; set +a
python3 ops/prod-hotfixes/disp/e5/apply_e5_prod.py     # idempotent, anchor-based
# restart backend (kill root uvicorn first), openapi 200
python3 ops/prod-hotfixes/disp/e5/verify_e5.py          # LIVE 18/18
```
Idempotent: re-running SKIPs every already-present patch. Backups → `disp_bak_e5_<ts>/`.

## LIVE verify (dev prod-mock): 18/18 PASS, 0 residue
Both tracks + all charge types; payer/creator deep-links correct; chargeback opened/
evidence-due/lost notifications; subs-webhook dispute ignore; default-on push allowlist;
reconciliation spot-check clean. Regression: E1 20/20, E2 21/21, E3 25/25, E4 31/31.
