# Payment Webhook Reconciliation (CCE-012)

`app/services/payment_reconciliation.py` normalizes provider webhook events and applies deterministic payment-state transitions to entitlement actions.

## Provider event normalization
- Stripe maps events such as:
  - success: `payment_intent.succeeded`, `charge.succeeded`, `checkout.session.completed`
  - failure: `payment_intent.payment_failed`, `charge.failed`
  - refunded: `charge.refunded`
  - chargeback: `charge.dispute.*`
- PayPal maps events such as:
  - success: `PAYMENT.CAPTURE.COMPLETED`, `CHECKOUT.ORDER.APPROVED`, `BILLING.SUBSCRIPTION.ACTIVATED`
  - refunded/cancelled: `PAYMENT.CAPTURE.REFUNDED`, `BILLING.SUBSCRIPTION.CANCELLED`
  - chargeback: `CUSTOMER.DISPUTE.CREATED`

All normalized events include: `provider`, `provider_event_id`, `order_id`, `status`, `occurred_at`, and raw payload.

## Deterministic entitlement actions
- Terminal success (`succeeded`) => `grant_entitlement(order_id)`.
- Terminal failure (`failed`, `refunded`, `chargeback`) => revoke active/pending entitlements for the order user.
- Non-terminal (`pending`) => no entitlement mutation.

## Idempotency behavior
- Duplicate webhook delivery is deduped on `(provider, provider_event_id)`.
- Duplicate processing returns deterministic `{"status": "duplicate"}` response.
- Previously dead-lettered events are eligible for replay processing.

## Dead-letter and replay
- Reconciliation exceptions enqueue dead-letter records with raw payload and reason.
- `replay_dead_letters()` reprocesses each payload through the same deterministic path.
- Replay reports `{replayed, processed, failed}` for operations visibility.

## Audit trail linkage
- On grant/revoke reconciliation, service emits `payment_webhook_entitlement_link` audit events.
- Audit fields include `provider_event_id`, `order_id`, `payment_status`, and `entitlement_id`.
