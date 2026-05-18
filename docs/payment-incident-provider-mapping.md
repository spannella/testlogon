# Payment Incident Provider Mapping (Canonical)

This document defines shared mapping guidance between provider-native events and the canonical payment incident model in `app/services/payment_incidents_domain.py`.

## Canonical Types

- `incident_type`
  - `dispute`
  - `chargeback`
  - `payment_failure`

- Dispute statuses
  - `opened`
  - `evidence_required`
  - `response_submitted`
  - `under_review`
  - `won`
  - `lost`
  - `accepted`
  - `canceled`

- Payment-failure statuses
  - `failed_initial`
  - `customer_action_required`
  - `ready_to_retry`
  - `retry_pending`
  - `retry_succeeded`
  - `retry_failed_terminal`

- Customer action requirements
  - `confirm`
  - `update_method`
  - `retry`

## Provider Event Mapping Rules

### Stripe
- `charge.dispute.created` => `incident_type=dispute`, `status=opened`
- `charge.dispute.updated` => maintain `dispute` type; map reason/state to:
  - `evidence_required` when Stripe indicates evidence needed
  - `under_review` after submission/review start
- `charge.dispute.closed` => map to terminal status (`won|lost`) based on provider outcome
- `invoice.payment_failed` / `payment_intent.payment_failed` => `incident_type=payment_failure`, `status=failed_initial`

### PayPal
- Dispute/claim opened events => `dispute`, `opened`
- Evidence/response-required signals => `evidence_required`
- Provider review state => `under_review`
- Provider final resolution => `won|lost|accepted`
- Payment denial/failure events => `payment_failure`, `failed_initial`

### CCBill
- Chargeback/dispute notifications => `chargeback` or `dispute` + `opened`
- Rebill decline/failure notifications => `payment_failure`, `failed_initial`
- Provider closure notifications => terminal statuses (`won|lost|accepted|canceled`) where supported

## Canonical Entity Field Coverage Checklist

The canonical `PaymentIncident` model includes:
- identity: `incident_id`, `provider`, `provider_incident_id`
- references: `payment_reference`, `account_id`, `customer_id`, `subscription_id`, `order_id`
- financials: `amount`, `currency`
- lifecycle: `incident_type`, `status`
- actionability: `requires_customer_action`, `customer_action_type`
- deadlines: `response_due_at`
- payload refs: `raw_payload_ref`, `provider_metadata`
- auditing timestamps: `created_at`, `updated_at`

## Adapter Contract Alignment

Adapters should produce canonical transitions via:
1. Parse provider event -> canonical `(incident_type, target_status)`.
2. Validate transition with `validate_incident_status_transition(...)`.
3. Persist transition + immutable event record.
4. Emit downstream actions (tickets, alerts, retry orchestration) based on canonical status.
