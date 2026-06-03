# BILLING-001: Refunds & Dispute Resolution

**Status**: Implemented
**Author**: Engineering
**Date**: 2026-05-27
**Priority**: High
**Estimated effort**: 8-10 days

---

## 1. Executive Summary

The platform processes payments across multiple channels -- tips, content unlocks, subscriptions, VOD purchases, pay-per-minute calls, and shop items -- but has no mechanism for reversing those payments. When a user accidentally tips the wrong person, gets billed for a subscription they thought they cancelled, or unlocks content that was not as described, their only recourse is to contact support through external channels. There is no in-app refund request flow, no admin refund processing tool, and no integration with Stripe/PayPal's refund APIs.

This ticket builds the complete refund and dispute lifecycle. Customers can submit refund requests referencing specific billing ledger entries. Admins see a queue of pending requests, can approve (triggering payment provider refund API calls and reverse ledger entries) or deny (with required notes). The system also tracks external disputes (chargebacks) received via Stripe and PayPal webhooks, providing admins with a resolution interface. All refund and dispute actions are audit-logged via `audit_event()`.

The implementation adds two new DynamoDB tables (`refund_requests` and `disputes`), a refund processing service that integrates with Stripe's Refund API (mocked via `stripe-mock` on port 12111 in dev), and frontend components for both customer-facing refund requests and admin-facing refund/dispute management.

---

## 2. Detailed Problem Analysis

### User Stories

| As a... | I want to... | So that... |
|---------|-------------|-----------|
| Customer | Request a refund for an accidental tip | I get my money back for a mistake |
| Customer | Request a refund for a subscription billing error | I am not charged for a period I did not use |
| Customer | See the status of my refund request | I know whether my money is coming back |
| Admin | See a queue of pending refund requests | I can process refunds efficiently |
| Admin | Approve a refund with full or partial amount | I can resolve the customer's issue fairly |
| Admin | Deny a refund with explanation notes | I can communicate the denial reason to the customer |
| Admin | See active disputes from payment providers | I can respond to chargebacks before the deadline |
| Admin | Submit evidence for a dispute | I can contest fraudulent chargebacks |
| Finance | See an audit trail of all refund/dispute actions | I can reconcile accounting records |

### Pain Points

1. **No self-service refund path**: Users must email support or open a helpdesk ticket. Response time is hours to days.
2. **No admin tooling**: Even when support agrees to a refund, they have no interface to process it. A developer must write DDB entries manually.
3. **Reverse ledger entries are not created**: `billing_shared.py` has `settle_or_reverse_ledger()` which can set a ledger entry to "reversed" state, but no higher-level flow creates the paired reverse debit/credit entries that keep the ledger balanced.
<!-- CORRECTED: refund_payment() at billing.py:1164-1174 DOES create reverse ledger entries via new_ledger_entry() and applies balance deltas via apply_balance_delta() at lines 1176-1179. The statement that no higher-level flow exists is incorrect -- refund_payment() is the higher-level flow. What IS missing is the paired buyer-CREDIT + seller-DEBIT pattern for marketplace refunds; current code only adjusts the buyer's balance. -->
4. **Stripe refund model exists but is dead code**: `StripeRefundReq` is defined in `app/models.py` but is not used by any endpoint.
<!-- CORRECTED: StripeRefundReq IS used by refund_payment() at billing.py:1145. It is NOT dead code. -->
5. **No chargeback handling**: When Stripe issues a `charge.dispute.created` event, the webhook receiver does not exist. The platform has no visibility into disputes.
<!-- CORRECTED: Stripe dispute handling ALREADY EXISTS at billing.py:1464-1543. The webhook receiver processes charge.dispute.funds_withdrawn and charge.dispute.funds_reinstated events, creates ledger entries, reverses payments, and logs audit events. Additionally, a full PaymentIncident system exists (billing.py:2095-2199+) with dispute evidence upload, dispute response submission, and provider adapters for Stripe/PayPal/CCBill. -->
6. **Legal exposure**: Without a clear refund policy enforced by the system, the platform risks regulatory issues in jurisdictions that mandate refund windows (e.g., EU 14-day cooling-off period).

### Competitive Analysis

| Platform | Self-serve refund | Admin refund | Dispute tracking | Refund window |
|----------|------------------|-------------|-----------------|---------------|
| Stripe Dashboard | N/A (merchant tool) | Full | Full | N/A |
| OnlyFans | No (email support) | Internal | Internal | 7 days |
| Patreon | No (email support) | Internal | Internal | None |
| Shopify | Partial (return request) | Full | Full | Configurable |
| This ticket | Yes (in-app request) | Yes (admin queue) | Yes (webhook + admin) | 30 days (configurable) |

---

## 3. Technical Architecture

### System Diagram

```
Customer                        Admin                         Backend
   |                              |                              |
   |-- POST /refund-request ---->|                              |
   |   {entry_id, reason}        |                              |
   |                              |                              |
   |                              |          +------ DDB -------+
   |                              |          | refund_requests   |
   |                              |          | (status=pending)  |
   |                              |          +-------------------+
   |                              |                              |
   |                              |<- GET /admin/refunds/queue --|
   |                              |   (status=pending, sorted)   |
   |                              |                              |
   |                              |-- POST /approve ----------->|
   |                              |                              |
   |                              |           +--- Stripe API --+
   |                              |           | POST /refunds   |
   |                              |           +-----------------+
   |                              |                              |
   |                              |           +--- DDB ---------+
   |                              |           | Reverse ledger  |
   |                              |           | entries:        |
   |                              |           | CREDIT to buyer |
   |                              |           | DEBIT fr seller |
   |                              |           +-----------------+
   |                              |                              |
   |                              |           +--- Alert -------+
   |<---- Refund notification ----|           | write_alert()   |
   |                              |           +-----------------+

Dispute Flow:
   Stripe                        Backend                     Admin
      |                              |                          |
      |-- webhook: dispute.created ->|                          |
      |                              |-- DDB: create dispute -->|
      |                              |                          |
      |                              |<- GET /admin/disputes ---|
      |                              |- dispute list ---------->|
      |                              |                          |
      |                              |<- POST /respond ---------|
      |                              |   {evidence}             |
      |                              |                          |
      |<-- API: submit evidence -----|                          |
```

### Data Flow: Refund Request Lifecycle

1. **Submit**: Customer views their billing history and clicks "Request Refund" on an eligible transaction. Frontend sends `POST /ui/refunds/request` with `transaction_entry_id` and `reason`.

2. **Validate**: Backend loads the original ledger entry from `T.billing`. Validates:
   - Entry exists and belongs to the requesting user.
   - Transaction is within the refund window (default 30 days).
   - No existing pending/approved refund for this entry (prevents duplicates).
   - Amount does not exceed the original transaction amount.

3. **Create**: Creates a `refund_requests` DDB row with `status=pending`. Writes an audit event.

4. **Admin review**: Admin navigates to `/admin/refunds`. Sees pending requests sorted by creation date. Can view the original transaction details.

5. **Approve**: Admin clicks "Approve". Backend:
   a. Calls Stripe Refund API (`POST /v1/refunds` with `charge` or `payment_intent` ID).
   b. Creates reverse ledger entries: CREDIT back to buyer, DEBIT from seller.
   c. Updates refund request status to `completed`.
   d. Writes alert to customer: "Your refund of $X.XX has been approved."
   e. Writes audit event.

6. **Deny**: Admin clicks "Deny" and provides notes. Backend:
   a. Updates refund request status to `denied`.
   b. Writes alert to customer: "Your refund request was denied. Reason: ..."
   c. Writes audit event.

### Component Interactions

- **`app/services/refund_requests.py`** (new): CRUD for refund requests. Status transitions: `pending -> approved/denied -> processing -> completed/failed`.
- **`app/services/refund_processor.py`** (new): Stripe/PayPal refund API integration. Uses existing Stripe client from `billing.py` (or `stripe-mock` in dev). Creates reverse ledger entries using patterns from `billing_shared.py` (`new_ledger_entry()`).
<!-- VERIFIED: new_ledger_entry() at billing_shared.py:217-245. ensure_balance_row() at :62-73. apply_balance_delta() at :76-98. -->
- **`app/services/dispute_tracker.py`** (new): Webhook event processing and dispute lifecycle management.
<!-- CORRECTED: A comprehensive dispute tracking system ALREADY EXISTS. See app/services/payment_incidents_store.py (DynamoPaymentIncidentRepository), app/services/payment_incident_transitions.py (PaymentIncidentTransitionService), app/services/payment_incident_stripe_adapter.py (StripePaymentIncidentAdapter), and similar adapters for PayPal and CCBill. The billing router at billing.py:2095-2199 provides admin endpoints for getting incidents, uploading evidence, and submitting dispute responses. A new dispute_tracker.py would duplicate existing infrastructure. -->
- **`app/routers/refunds.py`** (new): Customer and admin endpoints. Registered in `app/main.py`.
- **`app/routers/dispute_webhooks.py`** (new): Stripe/PayPal dispute webhook receivers.
<!-- CORRECTED: Stripe webhooks are ALREADY handled in billing.py at the /api/billing/webhooks/stripe endpoint (line 1559+). Dispute events (charge.dispute.funds_withdrawn, charge.dispute.funds_reinstated) are handled at lines 1464-1543. A separate dispute_webhooks.py router would conflict with the existing webhook handler. -->
- **Existing `billing_shared.py`**: Used for `new_ledger_entry()`, `ensure_balance_row()`, `apply_balance_delta()`. <!-- VERIFIED: billing_shared.py:217, :62, :76 -->
- **Existing `alerts.py`**: `write_alert()` for customer notifications. `audit_event()` for audit trail. <!-- VERIFIED: write_alert() at alerts.py:265-303; audit_event() at alerts.py:492-684 -->

---

## 4. Data Model Deep Dive

### DynamoDB Table: `refund_requests`

**Table definition for `scripts/local-ddb-init.py`:**
<!-- VERIFIED: TableDef pattern matches codebase convention at local-ddb-init.py:28-35. attr_types={"created_at": "N"} is correct for numeric GSI sort key (see CLAUDE.md "DynamoDB numeric GSI sort keys" gotcha). -->

```python
TableDef(
    os.environ.get("DDB_REFUND_REQUESTS", "RefundRequests"),
    "pk",
    "sk",
    gsi=[
        # GSI1: Admin queue -- all pending requests sorted by date
        {"index_name": "ByStatusCreatedAt", "partition_key": "status_scope", "sort_key": "created_at"},
        # GSI2: User's own refund history
        {"index_name": "ByRequesterCreatedAt", "partition_key": "requester_scope", "sort_key": "created_at"},
        # GSI3: Lookup by original transaction (dedup check)
        {"index_name": "ByTransactionId", "partition_key": "transaction_entry_id"},
    ],
    attr_types={"created_at": "N"},
)
```

**Settings entry for `app/core/settings.py`:**
<!-- NOTE: None of these settings exist yet. They must be added to the frozen Settings dataclass at app/core/settings.py (1197 lines). The existing disputes_table_name is NOT needed because the existing PaymentIncident system already has its own table and store (DynamoPaymentIncidentRepository). Also, disputes_table_name is not needed if extending the existing PaymentIncident infrastructure rather than creating a separate disputes table. -->

```python
refund_requests_table_name: str = os.environ.get("DDB_REFUND_REQUESTS", "RefundRequests")
disputes_table_name: str = os.environ.get("DDB_DISPUTES", "Disputes")
refund_window_days: int = int(os.environ.get("REFUND_WINDOW_DAYS", "30"))
refund_max_amount_cents: int = int(os.environ.get("REFUND_MAX_AMOUNT_CENTS", "100000"))  # $1000
refund_admin_auto_approve_threshold_cents: int = int(os.environ.get("REFUND_ADMIN_AUTO_APPROVE_THRESHOLD_CENTS", "0"))
```

### Example Items -- Refund Request

**Pending refund request:**

```json
{
  "pk": "REFUND#rr_1a2b3c4d",
  "sk": "META",
  "refund_request_id": "rr_1a2b3c4d",
  "requester_user_id": "alice-uuid",
  "requester_scope": "USER#alice-uuid",
  "transaction_entry_id": "le_xyz789",
  "transaction_type": "tip",
  "original_amount_cents": 500,
  "amount_cents": 500,
  "currency": "USD",
  "reason": "Accidentally tipped the wrong person. Meant to tip user Bob but tipped Charlie instead.",
  "status": "pending",
  "status_scope": "STATUS#pending",
  "admin_user_id": "",
  "admin_notes": "",
  "stripe_refund_id": "",
  "stripe_charge_id": "ch_mock_abc123",
  "created_at": 1748361600,
  "updated_at": 1748361600,
  "completed_at": 0
}
```

**Approved refund request:**

```json
{
  "pk": "REFUND#rr_1a2b3c4d",
  "sk": "META",
  "refund_request_id": "rr_1a2b3c4d",
  "status": "completed",
  "status_scope": "STATUS#completed",
  "admin_user_id": "root-admin-uuid",
  "admin_notes": "Verified with transaction logs. Approving full refund.",
  "stripe_refund_id": "re_mock_def456",
  "amount_cents": 500,
  "created_at": 1748361600,
  "updated_at": 1748365200,
  "completed_at": 1748365200
}
```

### DynamoDB Table: `disputes`

**Table definition:**

```python
TableDef(
    os.environ.get("DDB_DISPUTES", "Disputes"),
    "pk",
    "sk",
    gsi=[
        {"index_name": "ByStatusCreatedAt", "partition_key": "status_scope", "sort_key": "created_at"},
        {"index_name": "ByProviderCreatedAt", "partition_key": "provider_scope", "sort_key": "created_at"},
    ],
    attr_types={"created_at": "N"},
)
```

**Example dispute:**

```json
{
  "pk": "DISPUTE#dp_stripe_abc123",
  "sk": "META",
  "dispute_id": "dp_stripe_abc123",
  "provider": "stripe",
  "provider_dispute_id": "dp_abc123",
  "provider_scope": "PROVIDER#stripe",
  "user_id": "alice-uuid",
  "creator_id": "charlie-uuid",
  "amount_cents": 2500,
  "currency": "USD",
  "reason": "product_not_received",
  "status": "open",
  "status_scope": "STATUS#open",
  "evidence_submitted": false,
  "evidence_text": "",
  "created_at": 1748361600,
  "updated_at": 1748361600,
  "deadline_at": 1749571200
}
```

### Access Patterns

| Pattern | Key | Index | Notes |
|---------|-----|-------|-------|
| Get refund request by ID | PK=`REFUND#{id}`, SK=`META` | Table | Single get_item |
| Admin queue (pending) | GSI1PK=`STATUS#pending`, sorted by created_at | ByStatusCreatedAt | Paginated query |
| User's refund history | GSI2PK=`USER#{user_id}`, sorted by created_at | ByRequesterCreatedAt | Paginated query |
| Dedup check by transaction | GSI3PK=`{transaction_entry_id}` | ByTransactionId | Should return 0-1 items |
| Disputes by status | GSI1PK=`STATUS#{status}`, sorted by created_at | disputes ByStatusCreatedAt | Admin dispute list |
| Disputes by provider | GSI2PK=`PROVIDER#{provider}` | disputes ByProviderCreatedAt | Provider-specific view |

---

## 5. API Contract Design

### POST `/ui/refunds/request`

**Request body:**

```json
{
  "transaction_entry_id": "le_xyz789",
  "reason": "Accidentally tipped the wrong person.",
  "amount_cents": null
}
```

`amount_cents: null` means full refund. A positive integer requests a partial refund.

**Response 201:**

```json
{
  "refund_request_id": "rr_1a2b3c4d",
  "status": "pending",
  "amount_cents": 500,
  "currency": "USD",
  "reason": "Accidentally tipped the wrong person.",
  "transaction_type": "tip",
  "created_at": 1748361600
}
```

**Error responses:**

| Status | Body | Condition |
|--------|------|-----------|
| 400 | `{"detail": "Transaction is outside the refund window (30 days)"}` | created_at > 30 days ago |
| 400 | `{"detail": "Refund amount exceeds original transaction amount"}` | amount_cents > original |
| 400 | `{"detail": "Reason must be at least 10 characters"}` | Short reason |
| 404 | `{"detail": "Transaction not found"}` | entry_id not in billing table |
| 409 | `{"detail": "A refund request already exists for this transaction"}` | Duplicate |

### GET `/ui/refunds/requests`

**Query params:** `cursor` (optional), `limit` (default 20, max 100).

**Response 200:**

```json
{
  "items": [
    {
      "refund_request_id": "rr_1a2b3c4d",
      "status": "pending",
      "amount_cents": 500,
      "currency": "USD",
      "reason": "Accidentally tipped the wrong person.",
      "transaction_type": "tip",
      "created_at": 1748361600,
      "admin_notes": null,
      "completed_at": null
    }
  ],
  "next_cursor": null
}
```

### GET `/ui/refunds/requests/{id}`

**Response 200:** Single refund request object (same schema as list item, with additional `transaction_details` object).

### GET `/ui/admin/refunds/queue`

**Query params:** `status` (default: pending), `cursor`, `limit`.

**Response 200:**

```json
{
  "items": [
    {
      "refund_request_id": "rr_1a2b3c4d",
      "requester_user_id": "alice-uuid",
      "requester_email": "alice@example.com",
      "status": "pending",
      "amount_cents": 500,
      "currency": "USD",
      "reason": "Accidentally tipped the wrong person.",
      "transaction_type": "tip",
      "transaction_details": {
        "entry_id": "le_xyz789",
        "description": "Tip to charlie-uuid",
        "original_amount_cents": 500,
        "created_at": 1748350000
      },
      "created_at": 1748361600
    }
  ],
  "next_cursor": null,
  "total_pending": 3
}
```

### POST `/ui/admin/refunds/{id}/approve`

**Request body:**

```json
{
  "notes": "Verified with transaction logs. Approving full refund.",
  "amount_cents": null
}
```

`amount_cents: null` = approve full requested amount. A positive integer = partial approval.

**Response 200:**

```json
{
  "ok": true,
  "refund_request_id": "rr_1a2b3c4d",
  "status": "completed",
  "approved_amount_cents": 500,
  "stripe_refund_id": "re_mock_def456"
}
```

### POST `/ui/admin/refunds/{id}/deny`

**Request body:**

```json
{
  "notes": "Transaction was legitimate. The tip was intentional per conversation history."
}
```

`notes` is required (min_length=1).

**Response 200:**

```json
{
  "ok": true,
  "refund_request_id": "rr_1a2b3c4d",
  "status": "denied"
}
```

### POST `/webhooks/stripe/disputes`

**Request body:** Stripe webhook event JSON (verified via `stripe_webhook_secret`).
<!-- CORRECTED: A Stripe webhook endpoint ALREADY EXISTS at POST /api/billing/webhooks/stripe (billing.py:1559+). It processes charge.dispute.funds_withdrawn and charge.dispute.funds_reinstated events (billing.py:1464-1543). Creating a separate /webhooks/stripe/disputes endpoint would conflict. Instead, extend the existing webhook handler to store dispute records in the new refund_requests or disputes table, or leverage the existing PaymentIncident system. -->

**Response 200:** `{"received": true}`

### GET `/ui/admin/disputes`

**Response 200:**

```json
{
  "items": [
    {
      "dispute_id": "dp_stripe_abc123",
      "provider": "stripe",
      "amount_cents": 2500,
      "currency": "USD",
      "reason": "product_not_received",
      "status": "open",
      "deadline_at": 1749571200,
      "evidence_submitted": false,
      "created_at": 1748361600
    }
  ],
  "next_cursor": null
}
```

### POST `/ui/admin/disputes/{id}/respond`

**Request body:**

```json
{
  "evidence_text": "Customer received the content. Here is proof: ...",
  "evidence_files": ["s3://evidence/receipt_screenshot.png"]
}
```

**Response 200:**

```json
{
  "ok": true,
  "dispute_id": "dp_stripe_abc123",
  "evidence_submitted": true
}
```

---

## 6. Frontend Component Design

### Component Tree

```
{/* Customer: Billing History */}
<BillingHistoryPage>
  <TransactionRow transaction={tx}>
    {tx.eligible_for_refund && (
      <Button onClick={() => setRefundTransaction(tx)}>Request Refund</Button>
    )}
  </TransactionRow>
  <RefundRequestDialog
    transaction={refundTransaction}
    onSubmit={submitRefundMutation.mutate}
    onClose={() => setRefundTransaction(null)}
  />
</BillingHistoryPage>

{/* Customer: Refund History */}
<RefundHistoryPage>
  {refundRequests.map(r => (
    <RefundRequestCard key={r.refund_request_id} request={r} />
  ))}
</RefundHistoryPage>

{/* Admin: Refund Queue */}
<AdminRefundQueuePage>
  <DataTable data={pendingRefunds}>
    <Column header="User" />
    <Column header="Type" />
    <Column header="Amount" />
    <Column header="Reason" />
    <Column header="Date" />
    <Column header="Actions">
      <ApproveButton onClick={() => approveMutation.mutate(id)} />
      <DenyButton onClick={() => setDenyDialog(id)} />
    </Column>
  </DataTable>
  <DenyDialog
    onSubmit={(notes) => denyMutation.mutate({ id, notes })}
  />
</AdminRefundQueuePage>

{/* Admin: Disputes */}
<AdminDisputeListPage>
  <DataTable data={disputes}>
    <Column header="Provider" />
    <Column header="Amount" />
    <Column header="Reason" />
    <Column header="Deadline" />
    <Column header="Status" />
    <Column header="Actions">
      <RespondButton onClick={() => setRespondDialog(id)} />
    </Column>
  </DataTable>
</AdminDisputeListPage>
```

### State Management

- **React Query keys**:
  - `["refunds", "my-requests"]`: Customer's refund request history.
  - `["refunds", "admin-queue", { status }]`: Admin refund queue.
  - `["disputes", "list", { status }]`: Admin dispute list.
- **Mutations**:
  - `useSubmitRefundRequest`: POST /ui/refunds/request. Invalidates `["refunds", "my-requests"]`.
  - `useApproveRefund`: POST /ui/admin/refunds/{id}/approve. Invalidates `["refunds", "admin-queue"]`.
  - `useDenyRefund`: POST /ui/admin/refunds/{id}/deny. Invalidates `["refunds", "admin-queue"]`.
  - `useRespondToDispute`: POST /ui/admin/disputes/{id}/respond. Invalidates `["disputes", "list"]`.

### Navigation Integration

- **Customer routes**: `/billing/refunds` -- refund request history page. Added to `App.tsx`. Link in Billing sidebar section.
- **Admin routes**: `/admin/refunds` -- refund queue page. `/admin/disputes` -- dispute list page. Added to `App.tsx`. Links in Admin sidebar section.
- **BillingHistory modification**: Add "Request Refund" button to each eligible transaction row. A transaction is eligible if: (a) it is a debit (customer paid), (b) it is within the refund window, (c) no existing refund request exists for it.

### UI Mockup Descriptions

1. **RefundRequestDialog**: A shadcn/ui `Dialog` with: transaction summary (type, amount, date), a `Textarea` for reason (min 10 chars), an optional amount input (pre-filled with full amount, editable for partial), and "Submit Request" / "Cancel" buttons.

2. **RefundRequestCard**: A `Card` showing: status badge (pending=yellow, approved=green, denied=red, completed=blue), amount, reason (truncated), date, and admin notes (if present).

3. **Admin Refund Queue**: A `DataTable` with sortable columns. Each row has the requester's email, transaction type, amount, reason (expandable), and action buttons (Approve/Deny). Approve opens a confirmation dialog; Deny opens a notes dialog.

4. **Admin Dispute List**: A `DataTable` with: provider badge (Stripe/PayPal), amount, reason code, deadline (with countdown if < 7 days), evidence status, and "Respond" button.

---

## 7. Security & Privacy Considerations

### Authentication & Authorization

- Customer endpoints: `require_ui_session`. Users can only submit requests for their own transactions and view their own request history.
<!-- VERIFIED: require_ui_session is at app/services/sessions.py:283 -->
- Admin endpoints: `require_admin_session` (role >= ADMIN). The refund queue and dispute list are admin-only.
<!-- CORRECTED: There is no require_admin_session dependency. The codebase uses require_admin_or_root (app/auth/policy.py:67) for general admin checks, require_admin_scope("billing_support") (policy.py:84) for billing-specific admin scope, or require_billing_support_admin (billing.py:105). For the refund admin endpoints, use require_billing_support_admin or require_admin_or_root — NOT require_admin_session which does not exist. -->
- Webhook endpoints: Verified via Stripe webhook signature (`stripe_webhook_secret`) or PayPal webhook ID verification.
<!-- VERIFIED: stripe_webhook_secret at settings.py:301. Existing webhook handler at billing.py:1559+ already verifies Stripe signatures. -->

### Input Validation

- `reason`: min_length=10, max_length=2000. Prevents empty reasons while allowing detailed explanations.
- `amount_cents`: Must be > 0 and <= original transaction amount. Validated server-side.
- `transaction_entry_id`: Must exist in `T.billing` and belong to the requesting user.
- Admin `notes`: Required for deny (min_length=1). Optional for approve.

### Data Protection

- Refund request data includes the reason text, which may contain PII or sensitive information. This data is only accessible to the requester and admins.
- Stripe refund IDs are stored for reconciliation but not exposed to the customer.
- Dispute evidence files are stored in S3 with restricted access (admin-only presigned URLs).

### Abuse Prevention

- **Duplicate prevention**: One refund request per transaction (409 on duplicate via GSI3 check).
- **Rate limit**: Max 5 refund requests per user per hour.
- **Refund window**: Default 30 days. Transactions older than this are ineligible.
- **Amount validation**: Refund amount can never exceed the original transaction amount.
- **Admin audit trail**: Every approve/deny action is recorded via `audit_event()` with the admin's `user_sub` and the decision notes.
- **Auto-fraud detection** (future): Flag users who submit > 10 refund requests in 30 days. Out of scope for v1.

---

## 8. Performance & Scalability

### Query Cost Analysis

| Operation | DDB Operations | Estimated Cost |
|-----------|---------------|----------------|
| Submit refund request | 1 GetItem (billing entry) + 1 Query (GSI3 dedup) + 1 PutItem | 2 WCU + 2 RCU |
| List user's requests | 1 Query (GSI2) | ~1 RCU |
| Admin queue (pending) | 1 Query (GSI1) | ~1 RCU |
| Approve refund | 1 GetItem + 1 UpdateItem + 2 PutItem (reverse ledger) | 4 WCU + 1 RCU |
| Deny refund | 1 GetItem + 1 UpdateItem | 2 WCU + 1 RCU |
| Dispute webhook | 1 PutItem | 1 WCU |

### Caching Strategy

- No backend caching for refund requests (must reflect current status immediately).
- Admin queue: React Query with `staleTime: 30 * 1000` (30 seconds). Auto-refetch on window focus.
- Customer refund history: React Query with `staleTime: 60 * 1000` (1 minute).

### Stripe Mock Compatibility

The `stripe-mock` server on port 12111 supports the `POST /v1/refunds` endpoint. Key behaviors:
<!-- VERIFIED: stripe-mock runs on port 12111. The existing refund_payment() at billing.py:1158 already calls stripe.Refund.create() successfully against stripe-mock. -->
- Returns a mock refund object with `id: re_mock_...` and `status: succeeded`.
- Does NOT actually reverse charges (mock limitation).
- Off-session refunds always succeed (unlike PaymentIntents which return `requires_payment_method`).

### Known Bottlenecks

1. **Admin queue scan on large datasets**: If thousands of refund requests accumulate, the GSI1 query for `STATUS#pending` returns many items. Mitigation: Paginate with Limit=20; add a sort key on `created_at` for chronological ordering.
2. **Stripe API latency**: Real Stripe refund calls take 200-500ms. Mitigation: Process asynchronously; update status from `processing` to `completed` in a background task.

---

## 9. Migration & Rollback Plan

### Deployment Phases

1. **Phase 1 -- Tables + settings**: Add `RefundRequests` and `Disputes` tables to `local-ddb-init.py`. Add settings. No behavioral change.
2. **Phase 2 -- Backend services + router**: Deploy behind `REFUND_SYSTEM_ENABLED` flag. When disabled, all endpoints return 404.
3. **Phase 3 -- Webhook receiver**: Deploy dispute webhook endpoint. This is safe even without the full admin UI -- it just stores dispute records.
4. **Phase 4 -- Frontend customer flow**: Add "Request Refund" button to BillingHistory, RefundRequestDialog, and RefundHistoryPage.
5. **Phase 5 -- Frontend admin flow**: Add AdminRefundQueuePage and AdminDisputeListPage. Admin routes.
6. **Phase 6 -- Enable in production**: Set `REFUND_SYSTEM_ENABLED=true`.

### Feature Flags

| Flag | Default | Purpose |
|------|---------|---------|
| `REFUND_SYSTEM_ENABLED` | `true` (dev), `false` (prod) | Master enable/disable |
| `REFUND_WINDOW_DAYS` | `30` | How many days after transaction a refund can be requested |
| `REFUND_MAX_AMOUNT_CENTS` | `100000` | Max refund amount per request ($1000) |
| `REFUND_AUTO_APPROVE_THRESHOLD_CENTS` | `0` | Auto-approve refunds below this amount (0 = no auto-approve) |
| `DISPUTE_WEBHOOK_ENABLED` | `true` | Process dispute webhooks |

### Rollback Steps

1. Set `REFUND_SYSTEM_ENABLED=false`. All endpoints return 404. UI hides refund buttons.
2. Pending refund requests remain in DDB but are not actionable.
3. Completed refunds (already processed via Stripe) CANNOT be rolled back through the app -- they must be handled via Stripe Dashboard.
4. Dispute records remain for audit purposes.

---

## Testing Strategy

### Unit Tests (pytest)

**Test file**: `tests/test_refunds_disputes.py`

**Mock setup**: moto mock for DynamoDB (billing tables). stripe-mock on port 12111 for payment provider calls.

| Test Function | Description |
|---|---|
| `test_create_resource` | Create primary resource; verify stored correctly |
| `test_get_resource_by_id` | Get resource; verify all fields returned |
| `test_list_resources` | List with pagination; verify count and order |
| `test_update_resource` | Update fields; verify changes persisted |
| `test_delete_or_cancel_resource` | Delete/cancel; verify status change |
| `test_validation_rejects_invalid` | Missing/invalid fields return 400/422 |
| `test_authorization_enforced` | Non-owner/non-admin returns 403 |

### Integration Tests

Cross-service tests with real DynamoDB Local:

1. Full lifecycle through real DDB
2. Cross-service with billing ledger validation
3. Concurrent requests handled correctly

### E2E Tests (Playwright)

**Test file**: `frontend/e2e/refunds-disputes.spec.ts`

**Auth pattern**: `injectAuth(page, "alice")` for customer; `injectAuth(page, "root")` for admin; CSRF header for mutations

| # | Test Name | Assertion |
|---|---|---|
| 1 | API creates resource | POST returns 200/201 with ID |
| 2 | API returns resource by ID | GET returns full resource |
| 3 | API lists with pagination | GET list returns array |
| 4 | API updates resource | PATCH returns updated resource |
| 5 | UI page loads with heading | Navigate to page; heading visible |
| 6 | UI form submits successfully | Fill form; submit; success toast |
| 7 | UI shows validation errors | Submit invalid; error messages visible |
| 8 | Unauthenticated returns 401 | No session -> 401 |
| 9 | Non-owner returns 403 | Wrong user -> 403 |
| 10 | Not found returns 404 | Invalid ID -> 404 |
| 11 | Duplicate returns 409 | Create twice -> 409 |

**Negative tests**: 401 unauthenticated, 403 non-owner/non-admin, 404 not found, 409 conflict, 422 validation

**Edge cases**: Zero balance payout attempt, refund exceeding original amount, concurrent refund requests

### Test Data Requirements

Seed billing data via DDB `put_item` in `beforeAll`. Use unique IDs per test run.

**Test users**: Alice (USER, customer), Charlie (ADMIN, queue management), Root (ROOT, admin operations)

### CI/Pipeline

Serial execution. `stripe-mock` on port 12111. Retry-safe.

---

## Dependencies & Merge Safety

### Depends On

| Ticket | What's Needed | Status | Can Overlap? |
|---|---|---|---|
| MON-002 | Billing ledger for refund amount validation | Implemented | Yes |

### Depended On By

No downstream dependents identified.

### Merge Strategy

Independent. New DDB tables (`refund_requests`, `disputes`), new service + router. Feature-flag-gated.

### Merge Checklist

- [ ] DDB tables `refund_requests` and `disputes` added to `local-ddb-init.py`
- [ ] Refund service integrates with Stripe mock refund API
- [ ] Admin refund queue endpoint registered in `main.py`
- [ ] Frontend refund request form and admin queue page created
- [ ] E2E tests pass in CI
- [ ] No breaking changes to existing billing endpoints

---

## Codebase References

> **KEY FINDING**: The ticket's premise contains significant factual errors. It claims `StripeRefundReq` is dead code and that no chargeback handling exists. In reality: (1) `refund_payment()` at billing.py:1144-1202 is a fully functional refund endpoint that uses `StripeRefundReq`, creates Stripe refunds, writes reverse ledger entries, applies balance deltas, and logs audit events; (2) Dispute/chargeback handling already exists at billing.py:1464-1543 for `charge.dispute.funds_withdrawn` and `charge.dispute.funds_reinstated` events; (3) A comprehensive **PaymentIncident system** exists across multiple service files with admin endpoints for viewing incidents, uploading dispute evidence, and submitting dispute responses to Stripe/PayPal/CCBill (billing.py:2095-2199). The ticket's true remaining scope is: **a customer-facing self-service refund REQUEST queue** (the existing refund endpoint is admin-only) and **extending the existing dispute infrastructure** with a customer-visible status page.

| Claim / Reference | Status | Actual Location | Notes |
|---|---|---|---|
| `StripeRefundReq` model in models.py | VERIFIED | `app/models.py:1392-1395` | Has `payment_intent_id`, `amount_cents`, `reason` |
| `StripeRefundReq` is "dead code" | **INCORRECT** | `app/routers/billing.py:1145` | `refund_payment()` uses it as the request body |
| `RefundIn` model | VERIFIED | `app/models.py:1347-1350` | Has `transaction_id`, `amount_cents`, `reason` |
| `billing_shared.py` `new_ledger_entry()` | VERIFIED | `app/services/billing_shared.py:217-245` | Used by refund_payment() at billing.py:1164 |
| `billing_shared.py` `settle_or_reverse_ledger()` | VERIFIED | `app/services/billing_shared.py:248-260` | Used by refund_payment() at billing.py:1182 |
| `billing_shared.py` `ensure_balance_row()` | VERIFIED | `app/services/billing_shared.py:62-73` | Used by dispute handler at billing.py:1488 |
| `billing_shared.py` `apply_balance_delta()` | VERIFIED | `app/services/billing_shared.py:76-98` | Used at billing.py:1177-1179 and :1503 |
| No chargeback/dispute webhook | **INCORRECT** | `app/routers/billing.py:1464-1543` | Handles `charge.dispute.funds_withdrawn` and `charge.dispute.funds_reinstated` |
| No dispute evidence/response system | **INCORRECT** | `app/routers/billing.py:2113-2199` | Admin endpoints for evidence upload and dispute response submission |
| PaymentIncident infrastructure | EXISTS | `app/services/payment_incidents_store.py`, `payment_incident_transitions.py`, `payment_incident_stripe_adapter.py`, `payment_incident_paypal_adapter.py`, `payment_incident_ccbill_adapter.py` | Full provider adapter pattern with transition state machine |
| Stripe webhook endpoint | EXISTS | `app/routers/billing.py:1559+` | `POST /api/billing/webhooks/stripe` |
| `require_admin_session` dependency | **DOES NOT EXIST** | N/A | Use `require_admin_or_root` (auth/policy.py:67), `require_admin_scope("billing_support")` (policy.py:84), or `require_billing_support_admin` (billing.py:105) |
| `require_ui_session` | VERIFIED | `app/services/sessions.py:283` | Cookie+CSRF auth dependency |
| `stripe_webhook_secret` setting | VERIFIED | `app/core/settings.py:301` | `os.environ.get("STRIPE_WEBHOOK_SECRET", "")` |
| `write_alert()` | VERIFIED | `app/services/alerts.py:265-303` | Creates alert DDB row + SSE push |
| `audit_event()` | VERIFIED | `app/services/alerts.py:492-684` | Master notification dispatch function |
| TableDef pattern | VERIFIED | `scripts/local-ddb-init.py:28-35` | `TableDef(name, partition_key, sort_key, gsi, attr_types)` |
| stripe-mock on port 12111 | VERIFIED | CLAUDE.md / dev stack | Supports `POST /v1/refunds` |
| Proposed settings (refund_requests_table_name, etc.) | **NOW EXIST** | `app/core/settings.py:1384-1387` | `refund_requests_table_name`, `refund_requests_enabled`, `max_refund_requests_per_month` |
| Proposed table handles | **NOW EXIST** | `app/core/tables.py:107,231` | `T.refund_requests` handle + wiring |
| RefundRequests DDB table | **NOW EXISTS** | `scripts/local-ddb-init.py:948` | TableDef with `_resolve_table_name` |
| `refund_payment()` existing endpoint | EXISTS | `app/routers/billing.py:1144-1202` | Full refund flow: Stripe API call, ledger entry, balance delta, audit event |
| `refund_requests_router` | **NOW EXISTS** | `app/main.py:158,449` | Import + registration |
| `app/routers/refund_requests.py` | **NOW EXISTS** | — | Refund requests router |
| `app/services/refund_requests.py` | **NOW EXISTS** | — | Refund requests service |
