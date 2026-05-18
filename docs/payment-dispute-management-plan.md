# Payment Dispute & Failure Recovery Implementation Plan (Stripe / PayPal / CCBill)

## 1) Goals

Build a unified payment incident management flow so that:

1. **Disputes/chargebacks** from Stripe, PayPal, and CCBill are normalized into one internal model.
2. **Admins can respond** from an internal UI (upload evidence, add notes, submit response, track deadlines).
3. **Support tickets are created automatically** for each dispute event and lifecycle transition.
4. **Immediate payment failures** that only require customer action are surfaced with clear retry/confirmation UX.
5. **Automatic payment failures** trigger customer alerts and a one-click “Retry automatic payment” path once payment details are fixed.
6. Full **auditability and observability** are available for compliance and operations.

---

## 2) Scope

### In scope
- Provider webhook ingestion and signature verification for dispute/payment-failure events.
- Unified domain entities for disputes, evidence, deadlines, outcomes, and retry requirements.
- Admin dispute operations UI/API.
- Ticket creation + ticket status sync from dispute lifecycle events.
- Customer notification and retry UX for failed immediate/auto charges.
- Metrics, alerting, runbooks, and backfill/reconciliation jobs.

### Out of scope (v1)
- ML-based dispute win-probability scoring.
- Fully automated evidence generation from external systems.
- Multi-currency hedging and FX optimizations.

---

## 3) Canonical event model (provider-agnostic)

Define a canonical event envelope and state model:

### `payment_incident` (new aggregate)
- `incident_id` (internal UUID)
- `provider` (`stripe|paypal|ccbill`)
- `provider_incident_id`
- `incident_type` (`dispute|chargeback|payment_failure`)
- `payment_reference` (invoice/charge/subscription/payment-intent mapping)
- `account_id`, `customer_id`, `subscription_id?`, `order_id?`
- `amount`, `currency`
- `status` (see state machines below)
- `requires_customer_action` (bool)
- `customer_action_type` (`confirm|update_method|retry`)
- `response_due_at` (for disputes)
- `raw_payload_ref` (pointer to immutable payload storage)
- `created_at`, `updated_at`

### Dispute state machine (canonical)
- `opened`
- `evidence_required`
- `response_submitted`
- `under_review`
- `won|lost|accepted|canceled`

### Payment failure state machine (canonical)
- `failed_initial`
- `customer_action_required`
- `ready_to_retry`
- `retry_pending`
- `retry_succeeded|retry_failed_terminal`

Store provider-specific details under a JSON metadata blob but keep core processing canonical.

---

## 4) Provider mapping design

Create provider adapters implementing a shared interface:

```text
interface PaymentIncidentProvider {
  verifyWebhook(signature, body): VerificationResult
  parseEvents(body): CanonicalIncidentEvent[]
  fetchDisputeDetails(providerIncidentId): ProviderDisputeDetails
  submitDisputeEvidence(providerIncidentId, evidence): ProviderSubmissionResult
  retryPayment(reference): ProviderRetryResult
}
```

### Stripe mappings
- Webhooks: `charge.dispute.created`, `charge.dispute.updated`, `charge.dispute.closed`,
  `invoice.payment_failed`, `payment_intent.payment_failed`, `invoice.payment_succeeded`.
- Retry path:
  - Immediate one-off failures: retry charge/payment intent.
  - Autopay failures: update default payment method -> retry latest invoice.

### PayPal mappings
- Webhooks: disputes lifecycle events + payment sale/authorization denial/failure events.
- Retry path:
  - One-time payment failure: customer confirm/retry from checkout/payment method selection.
  - Subscription/automatic failure: billing agreement/payment source fix -> retry capture/next billing action.

### CCBill mappings
- Webhooks: chargeback/dispute notifications, recurring rebill failures, transaction declines.
- Retry path:
  - Tokenized method confirmation/update where required.
  - Retry rebill via CCBill transaction API or scheduled retry trigger.

---

## 5) Data model & storage changes

Add tables/collections (or prefixed entities in existing billing store):

1. `payment_incidents`
   - canonical record + status + deadline + references.
2. `payment_incident_events`
   - immutable event log for each provider webhook and internal transition.
3. `payment_dispute_evidence`
   - file refs, structured fields, submitter, versioning.
4. `payment_retry_attempts`
   - retry initiator (`customer|system|admin`), request/response, outcome.
5. `payment_incident_ticket_links`
   - mapping between incident and support ticket IDs.

Also ensure existing ledger supports dispute/chargeback reversal entries consistently.

---

## 6) API plan

### Admin APIs
- `GET /api/admin/payment-incidents`
  - filters: provider, type, status, due date window, customer, amount range.
- `GET /api/admin/payment-incidents/{id}`
- `POST /api/admin/payment-incidents/{id}/evidence`
  - metadata + file references.
- `POST /api/admin/payment-incidents/{id}/submit-response`
- `POST /api/admin/payment-incidents/{id}/escalate`
- `POST /api/admin/payment-incidents/{id}/link-ticket`

### Customer APIs
- `GET /api/billing/payment-issues`
  - open actionable failures/disputes affecting account.
- `POST /api/billing/payment-issues/{id}/confirm-and-retry`
- `POST /api/billing/payment-issues/{id}/retry-automatic-payment`
- `POST /api/billing/payment-methods/{id}/set-default-and-retry`

### Webhooks
- `POST /api/billing/webhooks/stripe`
- `POST /api/billing/webhooks/paypal`
- `POST /api/billing/webhooks/ccbill`

All webhook handlers must be idempotent on provider event IDs.

---

## 7) Admin UI plan

Create “Payment Incidents” module in admin area:

1. **Queue view**
   - tabs: `Disputes`, `Payment failures`, `Needs response soon`.
   - columns: provider, customer, amount, status, due date SLA, ticket link.
2. **Incident detail**
   - timeline of webhook/internal events.
   - evidence panel (upload docs, add notes, preview evidence package).
   - response actions (`Submit to provider`, `Escalate`, `Mark internal note`).
3. **SLA indicators**
   - countdown badges and breach warnings.
4. **Ticket integration panel**
   - create/open linked ticket, sync status, assign owner.

RBAC: limit to admins with billing support scope.

---

## 8) Customer UX plan (failure recovery)

### A) Immediate payment failures requiring confirmation
- Show banner/modal on billing page and checkout result screen:
  - Explain failure reason in user-safe text.
  - CTA: `Confirm and Retry Charge`.
- Flow:
  1. Customer confirms current/default method or picks updated method.
  2. System triggers retry endpoint.
  3. Show success/failure with next-step guidance.

### B) Automatic payment failures
- Trigger alert channels: in-app + email (+ optional SMS/push later).
- Message includes: failed invoice/subscription, amount, and due date.
- CTA sequence:
  1. `Fix payment method`.
  2. `Retry automatic payment` button enabled after method update/confirmation.
- If retry succeeds: clear alert + close issue.
- If retry fails: keep issue open and show escalation path (contact support).

---

## 9) Ticket automation workflow

### Ticket creation triggers
- New dispute/chargeback opened.
- Dispute nearing response deadline (e.g., <48h).
- Payment failure stuck without customer action beyond threshold.
- Retry failed terminally.

### Ticket schema additions
- `ticket_type = payment_incident`
- `incident_id`, `provider`, `provider_incident_id`
- `incident_status`, `next_action`, `deadline`
- `customer_contacted_at`, `assigned_admin_id`

### Sync rules
- Incident status updates post ticket comments/events.
- Ticket closure requires incident terminal state or explicit override.

---

## 10) Reliability, security, and compliance

1. **Webhook security**: strict signature verification, timestamp tolerance, replay protection.
2. **Idempotency**: dedupe key = provider event ID.
3. **Audit logging**: log every admin action (evidence upload, submit, retry trigger).
4. **PII minimization**: redact sensitive provider payload fields in logs.
5. **Evidence retention policy**: retention/expiry controls by compliance requirements.
6. **Rate limiting & backoff**: protect retry and provider submission endpoints.

---

## 11) Observability and KPIs

Track:
- Disputes opened/won/lost by provider.
- Avg response latency and SLA breach rate.
- Payment failure recovery rate (% recovered within 24h/72h).
- Retry success rate by provider and by failure reason.
- Ticket MTTA/MTTR for payment incidents.

Add dashboards and alerts for:
- Webhook failure spikes.
- Dispute backlog growth.
- Retry terminal failure spikes.

---

## 12) Rollout phases & execution tickets

### Phase 0: Discovery/spec (1 week)
- Confirm exact webhook event catalogs per provider account configuration.
- Finalize canonical status mappings and failure-reason taxonomy.
- Align support operations on ticket lifecycle.

### Phase 1: Backend foundation (2 weeks)
1. Add schema/migrations for incident entities.
2. Implement provider adapter interface + Stripe adapter first.
3. Add webhook endpoint idempotency/security middleware.
4. Implement incident orchestration service (state transitions).

### Phase 2: Ticket integration + alerts (1 week)
1. Automatic ticket creation/linking.
2. Customer alert pipeline for payment failures.
3. Retry orchestration service and audit trails.

### Phase 3: Admin UI + customer retry UX (2 weeks)
1. Admin incident queue/detail pages.
2. Evidence upload and response submit flows.
3. Customer payment issue center and retry buttons.

### Phase 4: PayPal + CCBill adapters (1–2 weeks)
1. Implement provider-specific parsing/submission/retry logic.
2. End-to-end parity checks against Stripe behavior.

### Phase 5: Hardening & launch (1 week)
1. Runbook + on-call alerts.
2. Backfill/reconciliation job for missing incidents.
3. Shadow mode validation, then production rollout behind flags.

---

## 13) Acceptance criteria

1. Every dispute/chargeback from Stripe/PayPal/CCBill creates one canonical incident and one linked ticket.
2. Admin can view timeline, add evidence, and submit dispute response from UI.
3. Immediate customer-action failures show a retry confirmation flow that can recover payment.
4. Automatic payment failures notify customers and provide fix+retry path.
5. Incident and ticket status remain synchronized.
6. Audit logs and metrics cover full lifecycle from webhook to resolution.

---

## 14) Testing strategy

- Unit tests:
  - provider event parsers/mappers
  - state transitions and idempotency guards
  - retry orchestration decision logic
- Integration tests:
  - webhook ingestion -> incident creation -> ticket creation
  - admin evidence submission -> provider submission stub
  - customer update payment method -> retry automatic payment
- E2E tests:
  - admin dispute queue/detail flows
  - customer alert + retry flows
- Chaos/failure tests:
  - duplicate webhooks
  - provider timeout on response submit
  - retry storms and backoff behavior

---

## 15) Open decisions

1. Whether to expose provider-native dispute IDs directly in customer-visible pages.
2. Which channels are required for v1 alerts (email + in-app minimum).
3. Whether retry button should trigger immediate attempt or enqueue worker job for uniformity.
4. Required SLA targets per provider and dispute type.
5. Evidence template standardization per dispute reason code.
