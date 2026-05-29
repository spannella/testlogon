# FIN-011: Collaboration Revenue Splitting

**Ticket**: FIN-011
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-29
**Priority**: High
**Estimated effort**: 10-12 days

---

## 1. Overview & Motivation

### 1.1 Purpose

FIN-011 extends the existing collaboration agreement system with full revenue splitting automation, content assignment, split history with audit trail, and a dispute resolution mechanism. The backend already has `app/services/collaborations.py` (399 lines) for agreement lifecycle (create, accept, reject, counter-propose, terminate) and `app/services/collaboration_splits.py` (129 lines) for writing split ledger entries. However, there is no way to assign content items to a collaboration, no automatic trigger for splits when content earns revenue, no split history view, and no dispute mechanism if a collaborator disagrees with a split. This ticket fills those gaps.

### 1.2 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator | As a creator, I want to assign a video/post to a collaboration so revenue is split. | POST assigns content_id to collaboration; future revenue triggers automatic split. |
| Creator | As a creator, I want to see all content assigned to a collaboration. | GET returns list of content items with their revenue totals. |
| Creator | As a creator, I want automatic revenue splits when collaboration content earns money. | When a tip/unlock/purchase hits content assigned to a collaboration, split is calculated and ledger entries written automatically. |
| Creator | As a creator, I want to see a history of all splits for a collaboration. | Split history page shows each split event with amounts, dates, and percentages. |
| Creator | As a creator, I want to dispute a split if I think it is wrong. | Dispute button on a split entry; creates dispute record; other party is notified. |
| Creator | As a creator, I want to resolve a dispute by accepting or counter-proposing. | Accept dispute resolution or propose new split terms. |
| Admin | As an admin, I want to view and arbitrate unresolved disputes. | Admin dispute queue shows pending disputes with context. |
| System | Revenue splits must maintain full audit trail. | Every split writes immutable ledger entries with collaboration_id in meta. |

### 1.3 Why This Is Needed

The collaboration system today supports agreement negotiation (split percentages, terms, counter-proposals) and can write split ledger entries via `write_collaboration_split_ledger`. But this function must be called manually -- there is no integration with the billing pipeline to automatically split revenue when collaboration content earns money. Additionally, there is no way to assign specific content to a collaboration, no split history view, and no mechanism for handling disputes. Without these features, collaboration revenue splitting is effectively non-functional.

---

## 2. Current State Analysis

### 2.1 Existing Infrastructure

| Component | Location | Relevance |
|-----------|----------|-----------|
| Collaborations service | `app/services/collaborations.py` (399 lines) | Full agreement lifecycle: create, accept, reject, counter-propose, terminate |
| Collaboration splits | `app/services/collaboration_splits.py` (129 lines) | `write_collaboration_split_ledger` writes per-collaborator ledger credits |
| Collaboration agreements table | DDB `collaboration_agreements` | PK=collaboration_id, SK=CURRENT; GSIs: ByInitiator, ByRecipient, ByStatus |
| Billing shared | `app/services/billing_shared.py` | `new_ledger_entry` for financial records |
| Tip ledger | `app/services/tip_ledger.py` | Content tips with `meta.content_id` |
| Settings | `app/core/settings.py` | `collaboration_agreements_table_name` |

### 2.2 Collaboration Agreement Schema

From `app/services/collaborations.py:93-145`:

```python
item = {
    "collaboration_id": collab_id,
    "sk": "CURRENT",
    "initiator_id": initiator_id,
    "recipient_id": recipient_id,
    "status": "pending",            # pending, accepted, rejected, terminated, counter
    "content_types": content_types, # ["vod", "post", "broadcast"]
    "split": {initiator_id: 60, recipient_id: 40},
    "title": title,
    "description": description,
    "terms_text": terms_text,
    "valid_from": valid_from,
    "valid_until": valid_until,
    "max_content_items": max_content_items,
    "content_count": 0,
    "total_revenue_cents": 0,
    ...
}
```

### 2.3 Existing Split Logic

From `app/services/collaboration_splits.py:16-113`:

```python
def write_collaboration_split_ledger(
    *,
    collaboration_id: str,
    payer_user_id: str,
    amount_cents: int,
    currency: str = "USD",
    content_type: str = "collaboration",
    content_id: str = "",
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Write split ledger entries for a collaboration.
    For each collaborator compute: floor(amount * pct / 100).
    Remainder goes to initiator.
    """
```

This function works but must be called explicitly. It is not hooked into any billing flow.

### 2.4 Gaps

1. **No content assignment** -- no way to link a content_id to a collaboration_id.
2. **No automatic split triggers** -- billing flows do not check if content belongs to a collaboration.
3. **No split history view** -- individual split events are not queryable.
4. **No dispute mechanism** -- no way for a collaborator to challenge a split.
5. **No admin arbitration** -- no admin tools for dispute resolution.
6. **No content revenue tracking per collaboration** -- `total_revenue_cents` exists but is not reliably updated.
7. **No frontend for collaboration revenue** -- agreement management may exist but revenue tab is missing.

---

## 3. Technical Design

### 3.1 Data Model Extensions

#### 3.1.1 Content Assignment (Collaboration Agreements Table)

**PK**: `collaboration_id`, **SK**: `CONTENT#{content_id}`

| Field | Type | Description |
|-------|------|-------------|
| `content_id` | S | Video/post/broadcast ID |
| `content_type` | S | `"vod"`, `"post"`, `"broadcast"` |
| `title` | S | Cached content title |
| `assigned_by` | S | User who assigned the content |
| `assigned_at` | N | Assignment timestamp |
| `total_revenue_cents` | N | Running revenue total for this content in this collaboration |
| `split_count` | N | Number of splits executed for this content |

#### 3.1.2 Content-to-Collaboration Lookup (Collaboration Agreements Table)

To quickly look up whether a content item belongs to any collaboration:

**GSI**: `ByContentId`
**PK**: `COLLAB_CONTENT#{content_id}`, **SK**: `collaboration_id`

This allows the billing pipeline to check `does content X belong to any active collaboration?` with a single GSI query.

#### 3.1.3 Split Execution Record (Collaboration Agreements Table)

**PK**: `collaboration_id`, **SK**: `SPLIT#{timestamp}#{split_id}`

| Field | Type | Description |
|-------|------|-------------|
| `split_id` | S | `csplit_<uuid4_hex>` |
| `content_id` | S | Content that earned the revenue |
| `content_type` | S | Type of content |
| `gross_amount_cents` | N | Gross revenue amount |
| `source` | S | `"tip"`, `"unlock"`, `"vod_purchase"`, `"subscription"` |
| `distributions` | L | List of `{user_id, amount_cents, percentage}` |
| `ledger_entry_ids` | M | Map of `{user_id: ledger_entry_id}` |
| `created_at` | N | Split execution timestamp |
| `dispute_status` | S | `null`, `"disputed"`, `"resolved"` |

#### 3.1.4 Dispute Record (Collaboration Agreements Table)

**PK**: `collaboration_id`, **SK**: `DISPUTE#{timestamp}#{dispute_id}`

| Field | Type | Description |
|-------|------|-------------|
| `dispute_id` | S | `disp_<uuid4_hex>` |
| `split_id` | S | The split being disputed |
| `filed_by` | S | User who filed the dispute |
| `reason` | S | Dispute reason text |
| `proposed_split` | M | Optional proposed alternative split percentages |
| `status` | S | `"open"`, `"accepted"`, `"counter"`, `"admin_review"`, `"resolved"` |
| `resolution` | S | Resolution text (when resolved) |
| `resolved_by` | S | Who resolved (collaborator or admin) |
| `resolved_at` | N | Resolution timestamp |
| `created_at` | N | Filing timestamp |

### 3.2 Backend Service Extension

**Extend**: `app/services/collaboration_splits.py` (~300 additional lines)

```python
# -- Collaboration Revenue Splitting (FIN-011) --

def assign_content(
    collaboration_id: str,
    content_id: str,
    content_type: str,
    assigned_by: str,
    title: str = "",
) -> Dict[str, Any]:
    """Assign a content item to a collaboration for automatic revenue splitting.

    Validates:
    - Collaboration exists and is accepted.
    - content_type is in the collaboration's allowed content_types.
    - Content is not already assigned to another active collaboration.
    - max_content_items limit not exceeded.
    - Assigner is a participant in the collaboration.
    """
    ...


def unassign_content(
    collaboration_id: str,
    content_id: str,
    user_id: str,
) -> bool:
    """Remove a content item from a collaboration."""
    ...


def list_collaboration_content(
    collaboration_id: str,
) -> List[Dict[str, Any]]:
    """List all content items assigned to a collaboration."""
    ...


def find_collaboration_for_content(content_id: str) -> Optional[Dict[str, Any]]:
    """Look up the active collaboration for a content item.

    Uses ByContentId GSI. Returns the collaboration record if found
    and status=accepted, else None.
    """
    ...


def execute_content_split(
    content_id: str,
    amount_cents: int,
    source: str,
    payer_user_id: str,
) -> Optional[Dict[str, Any]]:
    """Check if content belongs to a collaboration and execute split if so.

    Called by billing hooks (tip, unlock, purchase).
    Returns split record if split was executed, None if content has no collaboration.
    """
    ...


def get_split_history(
    collaboration_id: str,
    user_id: str,
    limit: int = 50,
    cursor: Optional[str] = None,
) -> Dict[str, Any]:
    """Get split execution history for a collaboration.

    Only accessible to collaboration participants.
    """
    ...


def file_dispute(
    collaboration_id: str,
    split_id: str,
    filed_by: str,
    reason: str,
    proposed_split: Optional[Dict[str, int]] = None,
) -> Dict[str, Any]:
    """File a dispute on a specific split.

    Validates filed_by is a participant.
    Sets dispute_status on the split record.
    """
    ...


def resolve_dispute(
    dispute_id: str,
    collaboration_id: str,
    resolved_by: str,
    resolution: str,
    accept: bool = True,
) -> Dict[str, Any]:
    """Resolve a dispute (accept or counter).

    If accepted, the dispute is closed.
    If admin resolves, this is final arbitration.
    """
    ...


def list_disputes(
    collaboration_id: Optional[str] = None,
    status: str = "open",
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """List disputes. If collaboration_id is None, list all (admin)."""
    ...
```

### 3.3 Backend Router

**New file**: `app/routers/collaboration_splits.py` (~200 lines)

### 3.4 Router Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/ui/collaborations/{id}/content` | `require_ui_session` | Assign content to collaboration |
| `DELETE` | `/ui/collaborations/{id}/content/{content_id}` | `require_ui_session` | Unassign content |
| `GET` | `/ui/collaborations/{id}/content` | `require_ui_session` | List assigned content |
| `GET` | `/ui/collaborations/{id}/splits` | `require_ui_session` | Get split history |
| `POST` | `/ui/collaborations/{id}/splits/{split_id}/dispute` | `require_ui_session` | File a dispute |
| `GET` | `/ui/collaborations/{id}/disputes` | `require_ui_session` | List disputes for collaboration |
| `POST` | `/ui/collaborations/{id}/disputes/{dispute_id}/resolve` | `require_ui_session` | Resolve a dispute |
| `GET` | `/ui/admin/collaboration-disputes` | `require_admin_session` | Admin: list all open disputes |
| `POST` | `/ui/admin/collaboration-disputes/{dispute_id}/arbitrate` | `require_admin_session` | Admin: arbitrate a dispute |

### 3.5 Request/Response Models

**Add to `app/models.py`**:

```python
# -- Collaboration Revenue Splitting (FIN-011) --

class CollabContentAssignIn(BaseModel):
    content_id: str = Field(min_length=1)
    content_type: str = Field(pattern="^(vod|post|broadcast)$")
    title: str = Field(default="", max_length=200)

class CollabContentItem(BaseModel):
    content_id: str
    content_type: str
    title: str = ""
    assigned_by: str = ""
    assigned_at: int = 0
    total_revenue_cents: int = 0
    split_count: int = 0

class CollabContentListOut(BaseModel):
    items: List[CollabContentItem] = Field(default_factory=list)
    collaboration_id: str = ""

class CollabSplitDistribution(BaseModel):
    user_id: str
    amount_cents: int = 0
    percentage: float = 0

class CollabSplitRecord(BaseModel):
    split_id: str
    content_id: str
    content_type: str = ""
    gross_amount_cents: int = 0
    source: str = ""
    distributions: List[CollabSplitDistribution] = Field(default_factory=list)
    created_at: int = 0
    dispute_status: Optional[str] = None

class CollabSplitHistoryOut(BaseModel):
    items: List[CollabSplitRecord] = Field(default_factory=list)
    next_cursor: Optional[str] = None

class CollabDisputeIn(BaseModel):
    reason: str = Field(min_length=10, max_length=2000)
    proposed_split: Optional[Dict[str, int]] = None

class CollabDisputeResolveIn(BaseModel):
    resolution: str = Field(min_length=5, max_length=2000)
    accept: bool = True

class CollabDisputeOut(BaseModel):
    dispute_id: str
    split_id: str
    collaboration_id: str = ""
    filed_by: str
    reason: str
    proposed_split: Optional[Dict[str, int]] = None
    status: str
    resolution: str = ""
    resolved_by: str = ""
    resolved_at: int = 0
    created_at: int = 0

class CollabDisputeListOut(BaseModel):
    items: List[CollabDisputeOut] = Field(default_factory=list)
```

### 3.6 Integration with Billing Pipeline

The key integration is hooking `execute_content_split` into revenue events. When a billing event occurs with a `content_id`:

1. Call `find_collaboration_for_content(content_id)`.
2. If a collaboration is found, call `execute_content_split(content_id, amount_cents, source, payer_user_id)`.
3. The split replaces the single-creator credit with per-collaborator credits.

Integration points:

| Flow | File | Change |
|------|------|--------|
| Tip on content | `app/services/tip_ledger.py` | Before writing single credit, check for collaboration; if found, use `execute_content_split` instead |
| Unlock content | `app/routers/messaging.py` (unlock path) | Check for collaboration; split if found |
| VOD purchase | `app/services/vod_purchases.py` | Check for collaboration; split if found |

**Important**: The split replaces the normal single-creator credit. If content is in a collaboration with a 60/40 split on a $10 tip, Alice gets $6 credit and Bob gets $4 credit (before platform commission). The payer still pays $10.

### 3.7 Frontend Components

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `frontend/src/pages/collaborations/CollabRevenuePage.tsx` | Revenue tab on collaboration detail | ~350 |
| `frontend/src/pages/collaborations/DisputeDialog.tsx` | Dispute filing dialog | ~120 |
| `frontend/src/api/endpoints/collaboration-splits.ts` | API wrappers | ~60 |

**Component tree for CollabRevenuePage**:

```
CollabRevenuePage (tab within collaboration detail)
├── Card: "Revenue Summary"
│   ├── Total Revenue (from collaboration.total_revenue_cents)
│   ├── Your Share amount
│   ├── Content Items count
│   └── Split Count
├── Card: "Assigned Content"
│   ├── AssignContentButton → dialog to pick content
│   ├── ContentTable
│   │   ├── Column: Title
│   │   ├── Column: Type (badge)
│   │   ├── Column: Revenue
│   │   ├── Column: Splits
│   │   └── Column: Actions (Unassign)
│   └── Empty state: "No content assigned"
├── Card: "Split History"
│   ├── SplitTable
│   │   ├── Column: Date
│   │   ├── Column: Content
│   │   ├── Column: Source (tip/unlock/purchase)
│   │   ├── Column: Gross Amount
│   │   ├── Column: Your Share
│   │   ├── Column: Dispute Status
│   │   └── Column: Actions (Dispute button)
│   └── Pagination
└── DisputeDialog (modal)
    ├── Split details display
    ├── Reason textarea
    ├── Proposed split inputs (optional)
    └── Button: "File Dispute"
```

### 3.8 Files to Create

| File | Purpose | Estimated Lines |
|------|---------|-----------------|
| `app/routers/collaboration_splits.py` | Collaboration split API endpoints | ~200 |
| `frontend/src/pages/collaborations/CollabRevenuePage.tsx` | Revenue tab UI | ~350 |
| `frontend/src/pages/collaborations/DisputeDialog.tsx` | Dispute dialog | ~120 |
| `frontend/src/api/endpoints/collaboration-splits.ts` | API wrappers | ~60 |
| `frontend/e2e/fin-collab-splits.spec.ts` | E2E tests | ~420 |

### 3.9 Files to Modify

| File | Change |
|------|--------|
| `app/main.py` | Register `collaboration_splits` router |
| `app/models.py` | Add collaboration split models |
| `app/services/collaboration_splits.py` | Extend with content assignment, split execution, disputes |
| `app/services/tip_ledger.py` | Hook into collaboration split for content tips |
| `scripts/local-ddb-init.py` | Add ByContentId GSI to collaboration_agreements table |
| `frontend/src/api/types.ts` | Add TypeScript interfaces |

---

## 4. Rounding and Split Mechanics

### 4.1 Split Calculation

Reuses the existing pattern from `collaboration_splits.py`:

```python
for user_id, pct in sorted(split.items()):
    share = amount_cents * int(pct) // 100
```

Remainder goes to the initiator (first collaborator alphabetically if no initiator).

### 4.2 Invariant

`sum(distributions.amount_cents) == gross_amount_cents` -- enforced by giving remainder to one party.

### 4.3 Multi-Party Splits

The split map supports more than 2 collaborators (e.g., `{alice: 40, bob: 35, charlie: 25}`). Percentages must sum to exactly 100.

### 4.4 Content Exclusivity

A content item can only be assigned to one active collaboration at a time. The `find_collaboration_for_content` GSI lookup enforces this. If a collaboration is terminated, the content is freed for reassignment.

---

## 5. E2E Test Plan

**File**: `frontend/e2e/fin-collab-splits.spec.ts`

### Section 579: Content Assignment API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 579.1 | Assign content to accepted collaboration | Create collab (accepted); POST content assignment; 200; content appears in list |
| 579.2 | Cannot assign content to pending collaboration | POST content to pending collab; 400; error mentions "not active" |
| 579.3 | Cannot assign content already in another collaboration | Assign content to collab A; assign same content to collab B; 409; error mentions "already assigned" |
| 579.4 | Unassign content from collaboration | DELETE content from collab; 200; content no longer in list |

### Section 580: Automatic Revenue Split API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 580.1 | Tip on collaboration content triggers split | Assign content; send tip to content; both collaborators get ledger credits proportional to split |
| 580.2 | Split amounts match collaboration percentages | 60/40 split on $10; initiator gets $6 credit; recipient gets $4 credit |
| 580.3 | Split writes immutable execution record | After split; GET split history; record has gross, distributions, ledger_entry_ids |
| 580.4 | Content without collaboration gets normal single credit | Tip on non-collab content; only content owner gets credit (no split) |

### Section 581: Split History and Disputes API (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 581.1 | Split history lists past splits | GET splits; items ordered newest first; each has split_id and amounts |
| 581.2 | File dispute on a split | POST dispute with reason; 200; dispute_status on split = "disputed" |
| 581.3 | Resolve dispute marks it resolved | POST resolve with accept=true; status = "resolved" |
| 581.4 | Non-participant cannot file dispute | Third party POST dispute; 403 |

### Section 582: Collaboration Revenue UI (4 tests)

| # | Test Title | Assertion |
|---|-----------|-----------|
| 582.1 | Revenue tab visible on collaboration detail | Navigate to collaboration; "Revenue" tab visible |
| 582.2 | Assigned content table shows content items | Content table has at least one row with title and revenue |
| 582.3 | Split history shows split records | Split history table has rows with date, amount, and source |
| 582.4 | Dispute button opens dispute dialog | Click "Dispute" on a split row; dialog with reason textarea appears |

**Total E2E tests: 16**

---

## 6. Security Considerations

### 6.1 Auth Requirements

| Endpoint | Auth | Authorization |
|----------|------|---------------|
| Content assignment | `require_ui_session` | Only collaboration participants |
| Split history | `require_ui_session` | Only collaboration participants |
| File dispute | `require_ui_session` | Only collaboration participants |
| Resolve dispute | `require_ui_session` | Participants or admin |
| Admin disputes | `require_admin_session` | Admin role required |

### 6.2 Content Ownership Validation

When assigning content, the service validates that the assigning user is:
1. A participant in the collaboration (initiator or recipient).
2. The owner of the content item (checked via content metadata).

### 6.3 Financial Integrity

- Split calculations use integer arithmetic only.
- Split execution records are immutable (no update/delete).
- Each split writes standard billing ledger entries that integrate with existing earnings/payout systems.
- Disputes do not reverse or modify ledger entries; they create a record for human resolution.

### 6.4 Dispute Safety

- Disputes are informational records; they do not block future splits.
- Admin arbitration is the final resolution mechanism.
- Dispute reason and resolution are stored for audit purposes.

---

## 7. Dependencies

| Dependency | Status | Required For |
|------------|--------|-------------|
| `app/services/collaborations.py` | Exists | Agreement lifecycle, participant validation |
| `app/services/collaboration_splits.py` | Exists | `write_collaboration_split_ledger` pattern |
| `collaboration_agreements` DDB table | Exists | Storage for content assignments, splits, disputes |
| `app/services/billing_shared.py` | Exists | Ledger entries for split credits |
| `app/services/tip_ledger.py` | Exists | First integration point for automatic splits |

---

## 8. Acceptance Criteria

1. Creator can assign content items to an accepted collaboration.
2. Content items can only be assigned to one active collaboration at a time.
3. Revenue on collaboration content is automatically split according to agreement percentages.
4. Split amounts sum exactly to the gross amount (no rounding loss).
5. Split execution records are queryable with full distribution details.
6. Collaborator can file a dispute on any split with a reason.
7. Disputes can be resolved by the other collaborator or by admin arbitration.
8. Non-participants cannot access collaboration revenue data.
9. All 16 E2E tests pass.
