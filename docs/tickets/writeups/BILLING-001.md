# BILLING-001: Refunds & Dispute Resolution — Investigation & Implementation Write-up

> Type: feature | Priority: High | Status: Implemented | Area: billing

## 1. Summary & Classification

BILLING-001 builds a customer-facing self-service refund request queue and an admin processing interface so that users can request reversal of specific billing ledger entries (tips, unlocks, subscription charges, shop items), and admin users can approve or deny those requests with full audit trail. The ticket also addresses the operational gap around payment provider disputes (chargebacks).

The implementation is classified as a **feature** (not a bug fix) because the core payment and Stripe-refund infrastructure already existed before this ticket. The real scope is: a structured `refund_requests` DynamoDB table, new customer-facing and admin-facing HTTP endpoints, and the frontend pages that expose those flows.

**Who is affected**: Regular users (customers requesting refunds), admins with `billing_support` scope processing the queue, and Finance needing audit-trail reconciliation.

**Cross-references**: The ticket description contained several factual errors that were corrected inline. Most notably: `StripeRefundReq` is not dead code (used at `app/routers/billing.py:1145`), `refund_payment()` is a fully functional endpoint (`billing.py:1144-1202`), and comprehensive chargeback/dispute handling already exists at `billing.py:1464-1543` plus a full `PaymentIncident` system across `app/services/payment_incidents_store.py`, `payment_incident_transitions.py`, and provider adapters. See SEC-004 for related billing authorization issues. See SECOPS-007 for dev/prod parity requirements.

---

## 2. Current-State Investigation (what exists today)

### 2.1 What already existed before BILLING-001

**`refund_payment()` at `app/routers/billing.py:1144-1202`** is a working admin-only refund endpoint. It accepts a `StripeRefundReq` body (`app/models.py:1492-1495`: `payment_intent_id`, `amount_cents`, `reason`), calls `stripe.Refund.create()` against stripe-mock on port 12111 in dev, writes a reverse `adjustment` ledger entry via `new_ledger_entry()` (`app/services/billing_shared.py:224`), applies a balance delta via `apply_balance_delta()` (`billing_shared.py:76-98`), and marks the payment record as `"refunded"`. This is guarded by `_billing_write_user_context()` which calls `_require_billing_support_actor()` — so only ROOT or ADMIN+billing_support scope can call it.

**Stripe dispute webhook at `billing.py:1464-1543`**: The existing webhook receiver at `POST /api/billing/webhooks/stripe` handles `charge.dispute.funds_withdrawn` and `charge.dispute.funds_reinstated` events. For a funds-withdrawn event it writes an `adjustment` ledger entry, applies a balance delta increasing `owed_settled_cents`, reverses the original payment ledger entry, calls `mark_reverted()` for purchase transactions, and writes an `audit_event("billing_dispute_funds_withdrawn", ...)`.

**PaymentIncident system**: A multi-file system handles structured dispute tracking across providers. Admin endpoints exist at `billing.py:2095-2199`: `GET /api/admin/payment-incidents/{id}` returns the incident with events and evidence versions; `POST /api/admin/payment-incidents/{id}/evidence` stores structured evidence; `POST /api/admin/payment-incidents/{id}/submit-response` calls the provider adapter to submit a dispute response. Provider adapters cover Stripe, PayPal, and CCBill (`app/services/payment_incident_stripe_adapter.py`, `payment_incident_paypal_adapter.py`, `payment_incident_ccbill_adapter.py`).

**Billing shared utilities** (`app/services/billing_shared.py`): `new_ledger_entry()` at line 224, `ensure_balance_row()` at line 62, `apply_balance_delta()` at line 76, `settle_or_reverse_ledger()` at line 248.

**Auth dependency**: There is no `require_admin_session` in the codebase. Billing-admin endpoints use `require_billing_support_admin` (defined at `billing.py:105` as `require_admin_scope("billing_support")`) or `require_billing_admin_operator` (line 423). The `_require_billing_support_actor()` function at line 437 enforces the scope check.

### 2.2 What BILLING-001 added (implemented state)

The `RefundRequests` DynamoDB table is now defined in `scripts/local-ddb-init.py:1307` using `_resolve_table_name(S.refund_requests_table_name, "RefundRequests")`. The table handle is wired at `app/core/tables.py:434` as `T.refund_requests`. Settings in `app/core/settings.py` at lines 1814-1817 add `refund_requests_table_name`, `refund_requests_enabled`, and `max_refund_requests_per_month` (default 3).

**`app/services/refund_requests.py`** provides `create_refund_request()` at line 50.

**`app/routers/refund_requests.py`** exposes six endpoints (registered in `app/main.py:214,640`):
- `POST /ui/billing/refund-requests` (line 68) — customer submits a request
- `GET /ui/billing/refund-requests` (line 84) — customer lists their own requests
- `GET /ui/billing/refund-requests/{request_id}` (line 94) — customer gets one request
- `GET /ui/admin/refund-requests` (line 114) — admin sees pending queue
- `POST /ui/admin/refund-requests/{request_id}/approve` (line 124) — admin approves
- `POST /ui/admin/refund-requests/{request_id}/reject` (line 146) — admin rejects

The Pydantic models `RefundRequestIn` (`app/models.py:1500-1503`: `transaction_entry_id`, `reason` min_length=10/max_length=2000, optional `amount_cents`) and `RefundRequestOut` (`models.py:1506+`) are defined.

**Dev/Prod parity**: The `stripe.Refund.create()` call in `refund_payment()` (called from the approve endpoint) uses `S.stripe_api_base` at `billing.py:519`. In dev, `STRIPE_API_BASE=http://localhost:12111` routes all Stripe API calls to stripe-mock. In prod the variable is empty and the Stripe SDK uses its default base. This is the existing SECOPS-007-compliant pattern: same code path, mock vs. real via injected configuration, not scattered `if dev:` branches.

---

## 3. Gap / Threat Analysis

### 3.1 True scope after factual correction

The ticket premise contained three incorrect claims:
1. `StripeRefundReq` is dead code — **false**. Used at `billing.py:1145`.
2. No higher-level refund flow creates reverse ledger entries — **false**. `refund_payment()` does this at lines 1164-1179.
3. No chargeback handling exists — **false**. Full handling exists at `billing.py:1464-1543` plus the PaymentIncident system.

The genuine gap before this ticket was: no **customer-facing refund request flow**. Users had no way to initiate a refund request themselves. `refund_payment()` is admin-only (requires `billing_support` scope). A customer who accidentally tipped the wrong person had to contact support via external channels. The `refund_requests` table and endpoints added by this ticket fill exactly that gap.

### 3.2 Edge cases and failure modes

**Duplicate prevention**: The GSI3 index on `transaction_entry_id` allows a dedup check before creating a request. Without this, a user could submit multiple refund requests for the same transaction and potentially get refunded multiple times.

**Refund window enforcement**: The 30-day default window (`REFUND_WINDOW_DAYS` default not in settings — `max_refund_requests_per_month` is, but the window itself should be derived from the `created_at` on the original ledger entry). If window enforcement is missing from `create_refund_request()`, users could request refunds on year-old transactions.

**Partial refund amount validation**: `amount_cents` in the request must never exceed the `original_amount_cents` on the ledger entry. This is a service-layer validation, not a Pydantic validation (Pydantic only enforces `ge=1`).

**Stripe-mock refund behavior**: In dev, `stripe.Refund.create()` against stripe-mock on port 12111 returns a mock refund object with `status: "succeeded"` for refunds. Unlike off-session PaymentIntents (which always return `requires_payment_method`), refunds are supported by stripe-mock. This means the approve flow works end-to-end in the dev environment.

**`require_billing_support_admin` vs. `require_admin_session`**: The ticket spec used `require_admin_session` which does not exist. The actual implementation must use `require_billing_support_admin` (alias for `require_admin_scope("billing_support")` at `billing.py:105`) or the broader `require_billing_admin_operator` function.

**Marketplace double-entry**: The existing `refund_payment()` only adjusts the buyer's balance. For marketplace transactions (tips, unlocks) where the seller already received a credit, a complete refund should also debit the seller's ledger. The current implementation does not do this — only the buyer-side adjustment entry is written. This is noted in the ticket as the "paired buyer-CREDIT + seller-DEBIT pattern for marketplace refunds" gap.

---

## 4. Proposed Design / Fix

### 4.1 Data model — `RefundRequests` table

The table definition is already implemented at `scripts/local-ddb-init.py:1307`. The pattern matches the codebase convention using `_resolve_table_name()` and three GSIs:
- **GSI `ByStatusCreatedAt`**: PK=`status_scope` (`STATUS#pending`), SK=`created_at` (N) — admin queue by status
- **GSI `ByRequesterCreatedAt`**: PK=`requester_scope` (`USER#{user_id}`), SK=`created_at` (N) — user's own history
- **GSI `ByTransactionId`**: PK=`transaction_entry_id` — dedup check

The `attr_types={"created_at": "N"}` declaration is required for numeric GSI sort keys per the project-wide gotcha documented in CLAUDE.md. Omitting it causes DDB to store `created_at` as a String type, which causes `ValidationException` when queried with integer comparisons.

Settings are at `app/core/settings.py:1814-1817`:
```
refund_requests_table_name: str = os.environ.get("DDB_REFUND_REQUESTS", "RefundRequests")
refund_requests_enabled: bool = os.environ.get("REFUND_REQUESTS_ENABLED", "1") not in ("0", "false", "False")
max_refund_requests_per_month: int = int(os.environ.get("MAX_REFUND_REQUESTS_PER_MONTH", "3"))
```

### 4.2 Service layer (`app/services/refund_requests.py`)

`create_refund_request()` at line 50 is the primary entry point. It should:
1. Load the original ledger entry from `T.billing` (PK=`user_pk(user_id)`, SK containing the `transaction_entry_id`).
2. Validate the entry belongs to the requesting user, is a debit, and is within the refund window.
3. Query GSI `ByTransactionId` on `T.refund_requests` to check for an existing pending/approved request (409 if found).
4. Put a new item with `status=pending`, `status_scope=STATUS#pending`, `requester_scope=USER#{user_id}`, integer `created_at` from `now_ts()`.
5. Write `audit_event("refund_request_submitted", ...)` for audit trail.

The approve path (called from `admin_approve_refund` at router line 124) should:
1. Load the refund request item.
2. Call the existing `refund_payment()` logic directly (or call `stripe.Refund.create()` + `new_ledger_entry()` + `apply_balance_delta()` inline).
3. Update the request item to `status=completed`.
4. Write `write_alert()` to notify the customer.
5. Write `audit_event("refund_request_approved", ...)` with the admin's sub.

### 4.3 Auth pattern

Customer endpoints use `Depends(require_ui_session)` with the standard cookie+CSRF pattern. Admin endpoints use `Depends(require_billing_admin_operator)` + `_require_billing_support_actor(actor)` inline, matching the pattern at `billing.py:2098-2100`.

### 4.4 Dev/Prod parity (SECOPS-007)

No new AWS dependencies are introduced. The Stripe refund call in the approve path routes through `S.stripe_api_base` just like the existing `refund_payment()` endpoint: `STRIPE_API_BASE=http://localhost:12111` in dev, empty in prod. DynamoDB operations go to `DDB_ENDPOINT_URL=http://localhost:8001` in dev and real DynamoDB in prod. This is transparent to the refund service because `T.refund_requests` is initialized from `tables.py:434` using the standard `_safe_table()` factory. No `if S.dev_mode:` branches are needed in the refund service itself.

### 4.5 Dispute infrastructure (no new work required)

The ticket proposed `app/services/dispute_tracker.py` and `app/routers/dispute_webhooks.py`. Both are unnecessary because the PaymentIncident system (`payment_incidents_store.py`, `payment_incident_transitions.py`, and provider adapters) already implements the full dispute lifecycle. The existing webhook at `billing.py:1464-1543` handles `charge.dispute.funds_withdrawn` and `charge.dispute.funds_reinstated`. A separate disputes table would duplicate existing infrastructure. The admin dispute management UI, if needed, should be wired to `GET /api/admin/payment-incidents?type=dispute` rather than creating a parallel `Disputes` table.

---

## 5. Testing, Verification & Rollout

### 5.1 pytest unit tests (`tests/test_refunds_disputes.py`)

All tests use moto for DynamoDB and the existing test client from `tests/conftest.py`. No AWS credentials or network needed.

| Test | Coverage |
|------|----------|
| `test_submit_refund_request_creates_pending_row` | POST 201, DDB item `status=pending` |
| `test_duplicate_request_returns_409` | Second POST on same `transaction_entry_id` → 409 |
| `test_submit_requires_auth` | No session → 401 |
| `test_submit_for_other_users_transaction` | Wrong user → 404 (entry not found for that user) |
| `test_admin_approve_calls_stripe_refund` | Approve endpoint writes `completed` + `stripe_refund_id` |
| `test_admin_reject_writes_denied_status` | Reject endpoint writes `denied` + `admin_notes` |
| `test_admin_queue_filters_by_status` | GET admin queue returns only `STATUS#pending` items |
| `test_refund_window_rejects_old_transactions` | `created_at < now - window` → 400 |
| `test_partial_refund_amount_too_large` | `amount_cents > original` → 400 |

### 5.2 E2E tests (`frontend/e2e/refunds-disputes.spec.ts`)

Auth: `injectAuth(page, "alice")` for customer tests. `injectAuth(page, "root")` for admin tests. CSRF header (`x-csrf-token`) required for all POST mutations via session auth.

Key scenarios:
1. Alice submits a refund request referencing a seeded ledger entry in DDB.
2. Root navigates to `/admin/refunds`, sees Alice's request in the queue.
3. Root approves; Alice's request status updates to `completed`.
4. Duplicate submission returns 409.
5. Submission without auth returns 401.
6. Submission for a transaction belonging to another user returns 404.

### 5.3 Manual verification

Run `just restart` before the test suite to clear accumulated test data. Verify the `RefundRequests` DDB table appears in the DDB Local console at `http://localhost:8001` after restart. Confirm `T.refund_requests` is available at startup by checking backend logs for table initialization errors.

### 5.4 Rollout

The feature is gated by `S.refund_requests_enabled` (default `true` in dev, override via `REFUND_REQUESTS_ENABLED=0` to disable). Because the new router adds fresh endpoints with no overlap with existing billing endpoints, rollout is low-risk: there are no breaking changes to `POST /billing/refund`, `GET /billing/ledger`, or the webhook receiver.

### 5.5 Rate limiting and abuse prevention

The `max_refund_requests_per_month` setting at `settings.py:1817` (default 3) limits how many refund requests a single user can open in a rolling 30-day window. The service layer should enforce this by querying `GSI2 ByRequesterCreatedAt` for items with `created_at > (now_ts() - 30*86400)` and rejecting new requests when the count reaches the limit. This prevents abuse scenarios where users submit a flood of requests to tie up admin capacity.

The dedup check via `GSI3 ByTransactionId` prevents multiple concurrent requests for the same transaction entry. However, the check is a read-before-write pattern with no DDB condition expression — there is a race window where two concurrent submissions for the same `transaction_entry_id` could both pass the dedup check before either is written. Mitigation: use a DDB `ConditionExpression` (attribute_not_exists on the `transaction_entry_id` index key) or a distributed lock. For v1, the race window is acceptable given the low volume of refund submissions.

### 5.6 Notification flow

On refund request approval, `write_alert()` at `app/services/alerts.py:265-303` should be called with the requester's `user_sub` to push a notification. The `audit_event()` at `alerts.py:492` records every state transition. The combined ledger entry (credit in the buyer's account) plus the alert notification plus the audit log give Finance a complete reconciliation trail. The frontend should surface pending refund requests in the user's notification bell (if connected to the SSE alert stream) so users know their request is being processed.

**Effort estimate**: S/M (2-4 days — marketplace double-entry for seller-side debits on tip/unlock refunds is the most complex remaining piece; basic request/approve/deny flow plus E2E spec is 1-2 days).
