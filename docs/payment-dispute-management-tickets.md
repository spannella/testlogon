# Payment Dispute & Failure Recovery — Implementation Tickets

This ticket set converts `docs/payment-dispute-management-plan.md` into executable engineering work for Stripe, PayPal, and CCBill.

## Epic PDM-1: Canonical Incident Platform

### PDM-001 — Define canonical payment incident domain model
**Type:** Feature  
**Priority:** P0  
**Dependencies:** None

**Scope**
- Add canonical enums/entities for:
  - `incident_type` (`dispute|chargeback|payment_failure`)
  - dispute lifecycle statuses
  - payment-failure lifecycle statuses
  - customer action requirements (`confirm|update_method|retry`)
- Define shared service contracts for incident orchestration.

**Deliverables**
- Typed domain model in backend.
- Shared mapping docs for provider adapters.

**Acceptance Criteria**
- Canonical model supports all fields listed in plan.
- Domain validation rejects invalid status transitions.

---

### PDM-002 — Add persistence schema for incidents/events/evidence/retries
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-001

**Scope**
- Add migrations/schema for:
  - `payment_incidents`
  - `payment_incident_events`
  - `payment_dispute_evidence`
  - `payment_retry_attempts`
  - `payment_incident_ticket_links`
- Add indexes for lookup by provider incident ID, customer ID, and SLA deadlines.

**Deliverables**
- Migration scripts.
- Repository/store interfaces + implementations.

**Acceptance Criteria**
- Migrations apply/rollback cleanly.
- Event log is immutable (append-only).
- Read paths support provider/case/deadline filtering.

---

### PDM-003 — Implement incident state transition service
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-001, PDM-002

**Scope**
- Build orchestration service that applies transitions from webhook and internal actions.
- Enforce idempotency keys and dedup logic.
- Emit domain events for ticketing/notifications/metrics.

**Deliverables**
- Transition engine + guardrails.
- Idempotency utility + tests.

**Acceptance Criteria**
- Duplicate provider events do not duplicate incidents/transitions.
- Invalid transitions are rejected with stable error codes.

---

## Epic PDM-2: Provider Webhooks & Adapter Integrations

### PDM-004 — Build provider adapter interface and registry
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-001

**Scope**
- Implement provider abstraction interface:
  - signature verification
  - webhook parsing
  - dispute details fetch
  - dispute response submission
  - payment retry
- Add adapter registry/resolver by provider key.

**Deliverables**
- Shared adapter interface package.
- Registry with safe fallback behavior.

**Acceptance Criteria**
- Unsupported provider yields structured non-500 response.
- Adapter contract tests pass for mock adapters.

---

### PDM-005 — Stripe adapter + webhook ingestion
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-004, PDM-003

**Scope**
- Implement Stripe mapping for dispute and payment-failure events.
- Add `POST /api/billing/webhooks/stripe` with signature verification and idempotency.
- Map immediate and autopay retry capabilities.

**Deliverables**
- Stripe adapter.
- Stripe webhook endpoint.

**Acceptance Criteria**
- Supported Stripe events create/update canonical incidents correctly.
- Invalid signature requests are rejected.
- Duplicate webhook delivery is safely ignored.

---

### PDM-006 — PayPal adapter + webhook ingestion
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-004, PDM-003

**Scope**
- Implement PayPal dispute/failure parsing and verification.
- Add `POST /api/billing/webhooks/paypal`.
- Implement PayPal retry hooks for one-time and subscription failures.

**Deliverables**
- PayPal adapter.
- PayPal webhook endpoint.

**Acceptance Criteria**
- PayPal lifecycle events map to canonical statuses.
- Signature/auth verification and dedup are enforced.

---

### PDM-007 — CCBill adapter + webhook ingestion
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-004, PDM-003

**Scope**
- Implement CCBill dispute/chargeback/rebill-failure parser.
- Add `POST /api/billing/webhooks/ccbill`.
- Implement CCBill retry hook behavior.

**Deliverables**
- CCBill adapter.
- CCBill webhook endpoint.

**Acceptance Criteria**
- CCBill event types are normalized to canonical incident model.
- Verification/idempotency behavior matches Stripe/PayPal standards.

---

## Epic PDM-3: Admin Dispute Operations

### PDM-008 — Admin payment incidents listing/detail APIs
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-003

**Scope**
- Implement:
  - `GET /api/admin/payment-incidents`
  - `GET /api/admin/payment-incidents/{id}`
- Add filters by provider/type/status/deadline/customer/amount.
- Enforce billing-admin RBAC.

**Deliverables**
- Admin incident query endpoints.
- RBAC policy checks.

**Acceptance Criteria**
- Authorized billing-support admins can query incident queues.
- Unauthorized admins/users receive 403.

---

### PDM-009 — Admin evidence upload and dispute response submit APIs
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-008, PDM-005

**Scope**
- Implement:
  - `POST /api/admin/payment-incidents/{id}/evidence`
  - `POST /api/admin/payment-incidents/{id}/submit-response`
- Support evidence metadata + file references.
- Add audit logs for submitter identity and submission payload summaries.

**Deliverables**
- Evidence persistence + provider submit workflow.
- Auditing hooks.

**Acceptance Criteria**
- Evidence versions are tracked and retrievable.
- Response submission updates incident status and stores provider response.

---

### PDM-010 — Admin incident queue/detail UI
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-008, PDM-009

**Scope**
- Build admin pages:
  - queue tabs (`Disputes`, `Payment failures`, `Needs response soon`)
  - incident detail timeline
  - evidence and response actions
  - ticket link panel
- Add SLA countdown badges and overdue warnings.

**Deliverables**
- New admin UI screens and API integrations.
- Unit/E2E coverage for key flows.

**Acceptance Criteria**
- Admin can find incidents, inspect timeline, upload evidence, and submit response.
- SLA indicators render correctly based on due dates.

---

## Epic PDM-4: Customer Recovery Flows

### PDM-011 — Payment issues customer APIs
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-003

**Scope**
- Implement:
  - `GET /api/billing/payment-issues`
  - `POST /api/billing/payment-issues/{id}/confirm-and-retry`
  - `POST /api/billing/payment-issues/{id}/retry-automatic-payment`
  - `POST /api/billing/payment-methods/{id}/set-default-and-retry`
- Enforce account ownership and scope checks.

**Deliverables**
- Customer payment issue endpoints.
- Retry orchestration integration.

**Acceptance Criteria**
- Customer can only operate on their own issues.
- Retry attempts and outcomes are persisted in `payment_retry_attempts`.

---

### PDM-012 — Customer billing UI for immediate failure confirmation/retry
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-011

**Scope**
- Add in-app UX for immediate failures:
  - banner/modal with failure explanation
  - `Confirm and Retry Charge` CTA
  - result states and guidance

**Deliverables**
- Billing page UI changes.
- Component tests for success/failure branches.

**Acceptance Criteria**
- Immediate actionable failures are clearly surfaced.
- CTA invokes retry API and shows deterministic outcome messaging.

---

### PDM-013 — Customer auto-payment failure fix-and-retry flow
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-011

**Scope**
- Add UI for automatic payment failures:
  - “Fix payment method” action
  - “Retry automatic payment” enabled after method update/confirmation
  - escalation guidance on repeated failure

**Deliverables**
- Billing issue center updates.
- Frontend tests for button state transitions.

**Acceptance Criteria**
- Retry button remains disabled until prerequisites are met.
- Successful retry clears issue from active queue.

---

## Epic PDM-5: Ticketing, Alerts, and Operational Controls

### PDM-014 — Automatic ticket creation + incident-ticket sync
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-003

**Scope**
- Create tickets for:
  - dispute/chargeback opened
  - nearing dispute deadline
  - stalled payment failures
  - terminal retry failures
- Keep ticket and incident statuses synchronized.

**Deliverables**
- Ticket automation workers/handlers.
- Incident-ticket link persistence.

**Acceptance Criteria**
- Every qualifying incident trigger creates exactly one linked ticket.
- Status changes synchronize both directions with conflict-safe rules.

---

### PDM-015 — Customer alerts for failed automatic payments
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-011

**Scope**
- Send in-app + email alerts on automatic payment failure.
- Include amount, due date, and recovery CTA deep-links.
- Clear notifications on successful recovery.

**Deliverables**
- Alert templates and dispatch logic.
- Notification lifecycle state tracking.

**Acceptance Criteria**
- Alerts emit once per failure incident state transition.
- Recovery success closes/archives relevant alerts.

---

### PDM-016 — Security hardening for webhooks and admin actions
**Type:** Feature  
**Priority:** P0  
**Dependencies:** PDM-005, PDM-006, PDM-007, PDM-009

**Scope**
- Enforce strict signature verification and replay windows.
- Add redaction for sensitive payload fields in logs.
- Add admin action audit trails for evidence upload/submit/retry actions.

**Deliverables**
- Security middleware updates.
- Audit log event schema + writers.

**Acceptance Criteria**
- Security tests cover invalid signatures and replay attempts.
- Audit logs capture actor, action, target, and timestamp.

---

## Epic PDM-6: Observability, QA, and Rollout

### PDM-017 — Metrics + dashboards + alerts for incident lifecycle
**Type:** Feature  
**Priority:** P1  
**Dependencies:** PDM-003

**Scope**
- Add metrics:
  - dispute volumes and outcomes by provider
  - response latency + SLA breaches
  - payment recovery rate and retry success
  - ticket MTTA/MTTR for payment incidents
- Add dashboards and on-call alerts.

**Deliverables**
- Metrics instrumentation.
- Dashboard panels + alert rules.

**Acceptance Criteria**
- All KPIs defined in plan are queryable.
- Alert thresholds validated in staging.

---

### PDM-018 — E2E/integration test matrix for providers and retry flows
**Type:** Test  
**Priority:** P0  
**Dependencies:** PDM-005 through PDM-015

**Scope**
- Add integration suites:
  - webhook -> incident -> ticket
  - admin evidence/submit flows
  - customer fix + retry flows
- Add E2E suites for admin and customer UX.
- Add failure-mode tests (duplicates, provider timeouts, retry storms).

**Deliverables**
- Test suites and fixtures/mocks per provider.
- CI jobs for critical paths.

**Acceptance Criteria**
- Test matrix covers Stripe, PayPal, and CCBill happy/error paths.
- Critical suites are required checks in CI.

---

### PDM-019 — Rollout, backfill, and runbook execution
**Type:** Ops  
**Priority:** P1  
**Dependencies:** PDM-017, PDM-018

**Scope**
- Implement feature flags for staged rollout.
- Create reconciliation/backfill job for missing incident records.
- Publish runbook for support/on-call response.

**Deliverables**
- Launch checklist and rollback steps.
- Backfill tooling.
- Operational runbook docs.

**Acceptance Criteria**
- Shadow mode validates parity before full launch.
- Backfill reports any data gaps with deterministic output.
- On-call/support sign off runbook readiness.

---

## Suggested Delivery Order

1. **Foundation:** PDM-001, PDM-002, PDM-003, PDM-004
2. **Provider-first production path:** PDM-005, PDM-008, PDM-009, PDM-011, PDM-014, PDM-015, PDM-016
3. **UX completion:** PDM-010, PDM-012, PDM-013
4. **Provider parity:** PDM-006, PDM-007
5. **Hardening + launch:** PDM-017, PDM-018, PDM-019

## Milestone Exit Gates

- **M1 (Stripe MVP):** PDM-001 to PDM-005, PDM-008, PDM-009, PDM-011, PDM-014, PDM-016 complete.
- **M2 (Customer Recovery):** PDM-012, PDM-013, PDM-015 complete.
- **M3 (Provider Parity):** PDM-006, PDM-007 complete with test matrix updates.
- **M4 (GA):** PDM-017 to PDM-019 complete with runbook sign-off.
