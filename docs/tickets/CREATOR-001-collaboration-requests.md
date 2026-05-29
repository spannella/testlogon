# CREATOR-001: Creator-to-Creator Collaboration Requests

**Ticket**: CREATOR-001
**Author**: Engineering
**Status**: Design
**Date**: 2026-05-28

---

## 1. Overview & Motivation

### 1.1 Problem Statement

The platform currently supports individual creator activities -- broadcasting, posting, selling products, and earning tips -- but provides no mechanism for two or more creators to formally collaborate. Informal collaborations (one creator hosts a broadcast while another joins as a guest via BCAST-016 multi-input) exist, but there is no system for:

- Proposing collaborations with agreed-upon revenue splits
- Tracking which content was co-created
- Attributing shared content to multiple creators
- Automatically distributing revenue from co-created content

Creators who want to collaborate must negotiate splits off-platform and manually transfer funds, leading to disputes, delayed payments, and lost collaboration opportunities.

### 1.2 Goals

1. **Collaboration Invite System**: A creator can propose a collaboration to another creator, specifying the content type, revenue split, and terms. The recipient can accept, reject, or counter-propose.
2. **Revenue Split Configuration**: Percentage-based splits that are enforced at the billing ledger level. When revenue is earned on co-created content, the platform automatically distributes the agreed percentages.
3. **Shared Content Attribution**: Co-created posts, broadcasts, and VOD content display both creators' profiles, driving cross-audience discovery.
4. **Joint Broadcast/Post Creation**: Once a collaboration is accepted, either party can create content tagged to the collaboration, which inherits the agreed revenue split.

### 1.3 User Stories

| Actor | Story | Acceptance Criteria |
|-------|-------|---------------------|
| Creator A | I want to propose a collaboration with Creator B with a 60/40 revenue split. | POST creates a collab request with `status=pending`. Creator B receives a notification. |
| Creator B | I want to review and accept/reject/counter a collaboration proposal. | PATCH updates status to `accepted`/`rejected`/`counter`. Counter proposals create a new revision. |
| Creator A | I want to cancel a pending collaboration request I sent. | DELETE/PATCH sets `status=cancelled`. Only the sender can cancel pending requests. |
| Creator A | I want to create a joint post attributed to our collaboration. | POST to newsfeed with `collaboration_id` tag. Post shows both creators' profiles. |
| Creator A | I want to start a joint broadcast using an accepted collaboration. | POST to broadcast sessions with `collaboration_id`. Revenue split applies to tips, locked messages, and product sales. |
| Creator B | I want to see my earnings from collaborative content on my earnings dashboard. | GET `/ui/earnings/summary` includes `collaborations` category in the breakdown. |
| Either | I want to end an active collaboration. | PATCH sets `status=terminated`. Future content is no longer linked. Existing content keeps its split. |
| Admin | I want to audit collaboration agreements and revenue distributions. | GET admin endpoint returns collaboration history with financial summary. |
| Creator A | I want to see a history of all revisions for a counter-proposal negotiation. | GET `/ui/collaborations/{collab_id}/revisions` returns an ordered list of all prior versions. |
| Creator A | I want to search for creators I can collaborate with. | GET `/ui/collaborations/discover` returns a list of creators who have opted into collaboration discovery. |
| Creator B | I want to opt out of receiving collaboration requests. | PATCH `/ui/collaborations/settings` sets `accepting_requests=false`. Requests to this creator return 403. |

---

## 2. Current State Analysis

### 2.1 Revenue & Billing Ledger Architecture

The platform already has a robust paired-entry billing ledger via `app/services/tip_ledger.py`. The `TipLedgerEntry` class (line 20-61) writes paired debit/credit entries to `T.billing`:
<!-- CORRECTED: was "line 22-60", actually class starts at line 20, ends ~line 61 -->

```python
class TipLedgerEntry:
    def __init__(
        self,
        *,
        tipper_user_id: str,
        recipient_user_id: str,
        amount_cents: int,
        currency: str = "USD",
        content_type: str,
        content_id: str,
        payment_method_id: Optional[str] = None,
        tip_payment_id: Optional[str] = None,
        extra_meta: Optional[Dict[str, Any]] = None,
    ):
        if content_type not in ("message", "post", "comment", "broadcast"):
            raise ValueError(f"Invalid content_type: {content_type}")
```

The `write_tip_ledger` function (line 88-150) writes two items to `T.billing`: a DEBIT under `USER#{tipper_user_id}` and a CREDIT under `USER#{recipient_user_id}`.
<!-- VERIFIED: app/services/tip_ledger.py:88 write_tip_ledger --> This pattern will be extended for collaboration revenue splits -- instead of a single credit to one recipient, the system will write proportional credits to each collaborator.

The ledger write flow for tips is best-effort with individual try/except blocks around each write (lines 109-127 for debit, 129-148 for credit).
<!-- CORRECTED: was "130-148 for credit", actually credit try block starts at line 129 --> The collaboration split writes must maintain this same resilience: if one collaborator's credit fails, the other should still be written. A reconciliation job will detect and repair partial writes.

Key billing table schema (from `T.billing`):
- **PK**: `USER#{user_id}`
- **SK**: `LEDGER#{timestamp}#{entry_id}`
- **Fields**: `entry_id`, `ts`, `type` (debit/credit), `amount_cents`, `currency`, `state`, `reason`, `meta`

The `meta` dict is flexible and can store `collaboration_id`, `split_pct`, and `total_amount_cents` for audit purposes. This metadata is already read back by the earnings service (see section 2.4) and surfaced in transaction lists.

### 2.2 Broadcast Session Ownership Model

The broadcast store (`app/services/broadcast_store.py`, line 206-233) creates sessions tied to a single `created_by` user:
<!-- VERIFIED: app/services/broadcast_store.py:206 create_session -->

```python
def create_session(
    *,
    profile_id: str,
    created_by: str,
    ingest_url: str | None = None,
    stream_key_ref: str | None = None,
    ...
) -> BroadcastSessionModel:
    session = BroadcastSessionModel(
        id=str(uuid4()),
        profile_id=profile_id,
        status="draft",
        ...
        created_by=created_by,
        created_at=ts,
        updated_at=ts,
    )
    T.broadcast_sessions.put_item(
        Item=session_to_item(session),
        ConditionExpression="attribute_not_exists(session_id)",
    )
```

The `session_to_item` function (line 111-157) already includes multi-input/co-streaming fields from BCAST-016:
<!-- VERIFIED: app/services/broadcast_store.py:111 session_to_item -->

```python
# Multi-input / Co-streaming (BCAST-016)
"max_inputs": session.max_inputs,
"active_layout": session.active_layout,
"active_input_ids": session.active_input_ids,
"primary_input_id": session.primary_input_id,
"guest_invite_enabled": session.guest_invite_enabled,
```

The collaboration system will extend this by adding a `collaboration_id` field to sessions, allowing revenue from tips and product sales to be split according to the collaboration agreement.

The session model already supports a `name` and `description` field (used by schedule/reschedule endpoints), so no structural changes are needed for session metadata. The collaboration link is purely additive.

### 2.3 Broadcast Tipping and Revenue Flow

The broadcast router (`app/routers/broadcast.py`, lines 1629-1673) handles tip messages.
<!-- VERIFIED: app/routers/broadcast.py:1629 send_tip_message_route decorator, :1634 function def --> The `send_tip_message_route` endpoint resolves the session, validates tipping is enabled, and delegates to `broadcast_tip_store.send_tip_message`. Revenue is currently credited entirely to the `session.created_by` user (the broadcaster).

```python
result = send_tip_message(
    session_id=session_id,
    user_id=user_id,
    display_name=display_name,
    amount_cents=body.amount_cents,
    currency=body.currency,
    payment_method_id=body.payment_method_id,
    text=body.text,
    broadcaster_id=session.created_by,  # <-- single recipient
)
```

With collaboration splits, this will be modified to look up the collaboration agreement and distribute the credit proportionally. The modification is isolated to the tip flow -- the actual `TipLedgerEntry` class does not need to change; we simply call `write_tip_ledger` multiple times with adjusted amounts.

The full tip flow is:
1. User calls `POST /broadcast/sessions/{session_id}/tips`
2. Router validates session is live, tipping is enabled, payment method exists
3. `send_tip_message` writes the chat message (visual representation)
4. `write_tip_ledger` writes debit to tipper, credit to broadcaster
5. SSE event `tip:received` is published to the session stream

Step 4 changes: instead of one credit, write N credits (one per collaborator). Step 5 changes: SSE event includes `split_details` so the dashboard can show real-time splits.

### 2.4 Creator Earnings Dashboard

The existing earnings service (`app/services/creator_earnings.py`, lines 22-33) categorizes revenue by reason string:
<!-- CORRECTED: was "lines 23-34", actually _reason_to_category starts at line 22 -->

```python
def _reason_to_category(reason: str) -> str:
    reason_lower = reason.lower() if reason else ""
    if "subscription" in reason_lower:
        return "subscriptions"
    if reason_lower.startswith("tip"):
        return "tips"
    if "unlock" in reason_lower:
        return "unlocks"
    if "vod" in reason_lower:
        return "vod_purchases"
    return "other"
```

A new category `"collaborations"` will be added to the breakdown, or collaboration revenue will be tagged with metadata that links to the collaboration agreement. The implementation approach is to add a new reason prefix check:

```python
if "collaboration" in reason_lower or "collab" in reason_lower:
    return "collaborations"
```

The earnings summary aggregation loop (lines 92-107) uses `FilterExpression: Attr("type").eq("credit")` to find credit entries.
<!-- CORRECTED: was "lines 92-102", actually aggregation while loop is lines 92-107 --> Collaboration credits will be standard credit entries with `reason="Collaboration tip split"` or `reason="Collaboration unlock split"`, ensuring they are automatically included in the earnings total and individually categorized.

The `get_earnings_transactions` function (lines 117-207) returns paginated individual entries
<!-- VERIFIED: app/services/creator_earnings.py:117 get_earnings_transactions --> with `meta` dicts. Collaboration split entries will include `meta.collaboration_id`, `meta.split_pct`, and `meta.total_amount_cents`, enabling the frontend to display "You earned $6.00 (60%) from a $10.00 tip on your collaboration with Bob".

### 2.5 Newsfeed Post Authorship

Posts in the newsfeed (from `app/routers/newsfeed.py`) are single-author: each post has an `author_id` field. The `PostResponse` model (line 1330) includes `author_id: str`.
<!-- VERIFIED: app/routers/newsfeed.py:1330 PostResponse --> Collaborative posts will add a `co_authors` list field and populate `collaboration_id` for attribution.

The newsfeed post creation flow (`POST /posts`) writes to the app single table with PK `POST#{post_id}` and SK `META`. The item includes `author_id`, `body`, `image_urls`, `visibility`, and optional scheduling fields. Adding `collaboration_id` and `co_author_ids` to this item is straightforward.

For the feed query, posts appear in the author's feed via `GSI1PK = FEED#{author_id}`. Collaborative posts need to appear in both creators' feeds. The simplest approach is to write two feed index entries (one per co-author) pointing to the same post item. This is consistent with how the platform handles shared content (e.g., `share_node` in the file manager).

### 2.6 Notification System Integration

The platform uses `put_notification` from `app/routers/newsfeed.py` for in-app notifications. The function writes to the app single table with `pk=USER#{user_id}` and `sk=NOTIF#{timestamp}#{id}`. The notification item includes `type`, `title`, `body`, `action_url`, and `meta`.

Collaboration events that trigger notifications:
- `collaboration_request`: "Alice invited you to collaborate on 'Summer Series'"
- `collaboration_accepted`: "Bob accepted your collaboration request"
- `collaboration_rejected`: "Bob declined your collaboration request"
- `collaboration_counter`: "Bob counter-proposed: 50/50 split instead of 60/40"
- `collaboration_cancelled`: "Alice cancelled the collaboration request"
- `collaboration_terminated`: "Bob ended the collaboration 'Summer Series'"
- `collaboration_revenue`: "You earned $15.00 from your collaboration with Bob" (batched daily)

### 2.7 Profile Identity Resolution

The `get_profile_identity` function (used in `app/routers/subscription_server.py`, line 147) resolves display name and avatar for a user ID:
<!-- VERIFIED: app/routers/subscription_server.py:147 attach_creator_profile -->

```python
def attach_creator_profile(plan: Dict[str, Any]) -> Dict[str, Any]:
    enriched = plan.copy()
    enriched["creator_profile"] = get_profile_identity(plan["creator_id"])
    return enriched
```

Collaboration responses will use this same function to enrich `initiator_profile` and `recipient_profile` fields, providing display names and avatar URLs for the frontend without additional API calls.

---

## 3. Technical Design

### 3.1 Collaboration Agreement Data Model

Each collaboration is stored in a new DynamoDB table `collaboration_agreements`:

```python
# Table: collaboration_agreements
# PK: collaboration_id (UUID)
# GSI1: ByInitiator — GSI1PK=USER#{initiator_id}, GSI1SK=created_at
# GSI2: ByRecipient — GSI2PK=USER#{recipient_id}, GSI2SK=created_at
# GSI3: ByStatus — GSI3PK=STATUS#{status}, GSI3SK=created_at

{
    "collaboration_id": "collab_a1b2c3d4e5f6",
    "initiator_id": "user_alice",
    "recipient_id": "user_bob",
    "status": "pending",  # pending | accepted | rejected | counter | cancelled | terminated | expired
    "content_types": ["broadcast", "post"],  # which content types this collab covers
    "split": {
        "user_alice": 60,   # percentage (must sum to 100)
        "user_bob": 40,
    },
    "title": "Summer Collab Series",
    "description": "Joint broadcast series for summer campaign",
    "terms_text": "Each party contributes 2 broadcasts per week",
    "valid_from": 1748476800,   # Unix timestamp, optional
    "valid_until": 1751155200,  # Unix timestamp, optional (null = indefinite)
    "max_content_items": null,  # optional cap on co-created items
    "content_count": 0,         # current count of co-created items
    "total_revenue_cents": 0,   # running total for analytics
    "revision": 1,              # incremented on counter-proposals
    "previous_revision_id": null,
    "initiator_display_name": "Alice",
    "recipient_display_name": "Bob",
    "accepting_requests": true, # whether recipient accepts collab invitations
    "created_at": 1748390400,
    "updated_at": 1748390400,
    "accepted_at": null,
    "terminated_at": null,
    "terminated_by": null,
    "termination_reason": null,
    # GSI key attributes
    "GSI1PK": "USER#user_alice",
    "GSI1SK": 1748390400,
    "GSI2PK": "USER#user_bob",
    "GSI2SK": 1748390400,
    "GSI3PK": "STATUS#pending",
    "GSI3SK": 1748390400,
}
```

#### 3.1.1 Revision History Table

Counter-proposals create revision snapshots stored alongside the main agreement:

```python
# Stored in same table with different SK pattern
# PK: collaboration_id
# SK: "REV#{revision_number:04d}"
{
    "collaboration_id": "collab_a1b2c3d4e5f6",
    "sk": "REV#0001",
    "revision": 1,
    "split": {"user_alice": 60, "user_bob": 40},
    "terms_text": "Each party contributes 2 broadcasts per week",
    "proposed_by": "user_alice",
    "proposed_at": 1748390400,
    "status": "superseded",  # superseded | accepted | rejected
}
```

This approach reuses the same table (collaboration_agreements) with a composite key -- PK is `collaboration_id`, and the main record has SK `CURRENT` while revisions use `REV#NNNN`. This eliminates the need for a separate revisions table.

### 3.2 Revenue Split Execution

When revenue is earned on collaborative content, the split is applied at the ledger write:

```python
# app/services/collaboration_splits.py

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict, Optional

from app.core.tables import T
from app.core.time import now_ts
from app.services.tip_ledger import TipLedgerEntry, write_tip_ledger

logger = logging.getLogger(__name__)


def get_collaboration(collaboration_id: str) -> Optional[Dict[str, Any]]:
    """Fetch a collaboration agreement by ID."""
    resp = T.collaboration_agreements.get_item(
        Key={"collaboration_id": collaboration_id, "sk": "CURRENT"}
    )
    return resp.get("Item")


def write_collaboration_split_ledger(
    *,
    payer_user_id: str,
    collaboration_id: str,
    amount_cents: int,
    currency: str = "USD",
    content_type: str,
    content_id: str,
    payment_method_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Write split ledger entries for a collaboration.

    1. Fetch the collaboration agreement.
    2. For each collaborator, compute their share: floor(amount * pct / 100).
    3. Write DEBIT to payer, CREDIT to each collaborator proportionally.
    4. Any remainder (from rounding) goes to the initiator.

    Returns dict mapping user_id to their ledger write result.

    Raises:
        ValueError: If collaboration is not in 'accepted' status.
        KeyError: If collaboration_id does not exist.
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise KeyError(f"Collaboration {collaboration_id} not found")
    if collab["status"] != "accepted":
        raise ValueError("Collaboration is not active")

    # Check validity window
    now = now_ts()
    if collab.get("valid_from") and now < collab["valid_from"]:
        raise ValueError("Collaboration has not started yet")
    if collab.get("valid_until") and now > collab["valid_until"]:
        raise ValueError("Collaboration has expired")

    split = collab["split"]  # {"user_alice": 60, "user_bob": 40}
    entries = {}
    allocated = 0

    for user_id, pct in sorted(split.items()):
        share = amount_cents * pct // 100
        entries[user_id] = share
        allocated += share

    # Remainder to initiator
    remainder = amount_cents - allocated
    entries[collab["initiator_id"]] += remainder

    # Write paired ledger entries
    results = {}
    for user_id, share_cents in entries.items():
        if share_cents <= 0:
            continue
        entry = TipLedgerEntry(
            tipper_user_id=payer_user_id,
            recipient_user_id=user_id,
            amount_cents=share_cents,
            currency=currency,
            content_type=content_type,
            content_id=content_id,
            payment_method_id=payment_method_id,
            extra_meta={
                "collaboration_id": collaboration_id,
                "split_pct": split[user_id],
                "total_amount_cents": amount_cents,
                "reason_override": f"Collaboration {content_type} split",
            },
        )
        results[user_id] = write_tip_ledger(entry)

    # Update running total on the collaboration record
    _update_collab_revenue(collaboration_id, amount_cents)

    return results


def _update_collab_revenue(collaboration_id: str, amount_cents: int) -> None:
    """Atomically increment total_revenue_cents on the collaboration record."""
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
            UpdateExpression="SET total_revenue_cents = total_revenue_cents + :amt, updated_at = :now",
            ExpressionAttributeValues={
                ":amt": amount_cents,
                ":now": now_ts(),
            },
        )
    except Exception:
        logger.warning(
            "Failed to update collab revenue total",
            extra={"collaboration_id": collaboration_id, "amount_cents": amount_cents},
        )


def _increment_content_count(collaboration_id: str) -> None:
    """Atomically increment content_count on the collaboration record."""
    try:
        T.collaboration_agreements.update_item(
            Key={"collaboration_id": collaboration_id, "sk": "CURRENT"},
            UpdateExpression="SET content_count = content_count + :one, updated_at = :now",
            ExpressionAttributeValues={
                ":one": 1,
                ":now": now_ts(),
            },
        )
    except Exception:
        logger.warning(
            "Failed to increment collab content count",
            extra={"collaboration_id": collaboration_id},
        )
```

#### 3.2.1 Rounding Strategy

The rounding strategy for revenue splits is critical for financial correctness:

```
Example: $10.33 tip with 60/40 split
- Alice share: floor(1033 * 60 / 100) = floor(619.8) = 619 cents = $6.19
- Bob share:   floor(1033 * 40 / 100) = floor(413.2) = 413 cents = $4.13
- Allocated:   619 + 413 = 1032 cents
- Remainder:   1033 - 1032 = 1 cent → goes to initiator (Alice)
- Final: Alice = $6.20, Bob = $4.13, total = $10.33 ✓
```

The maximum rounding error is N-1 cents where N is the number of collaborators (always 2 in v1). This is a standard "largest remainder" allocation approach and is auditable via the `split_pct` and `total_amount_cents` metadata stored on each ledger entry.

### 3.3 Content Tagging

When creating content linked to a collaboration, the content record stores:

- `collaboration_id`: Links to the agreement
- `co_author_ids`: List of all collaborator user IDs (for display queries)

For broadcasts:
```python
# Extended BroadcastSessionModel fields:
collaboration_id: Optional[str] = None
co_author_ids: Optional[List[str]] = None
```

For newsfeed posts:
```python
# Extended PostCreateIn fields:
collaboration_id: Optional[str] = None
# PostResponse extended:
co_authors: Optional[List[Dict[str, str]]] = None  # [{user_id, display_name, avatar_url}]
```

#### 3.3.1 Content Tagging Validation

When a creator tags content with a `collaboration_id`, the backend validates:

```python
# app/services/collaboration_content.py

def validate_collab_content_tag(
    collaboration_id: str,
    creator_user_id: str,
    content_type: str,
) -> Dict[str, Any]:
    """Validate that a creator can tag content with a collaboration ID.

    Returns the collaboration record if valid.

    Raises HTTPException on validation failure.
    """
    collab = get_collaboration(collaboration_id)
    if not collab:
        raise HTTPException(status_code=404, detail="Collaboration not found")

    # Must be a participant
    if creator_user_id not in (collab["initiator_id"], collab["recipient_id"]):
        raise HTTPException(status_code=403, detail="You are not a participant in this collaboration")

    # Must be accepted
    if collab["status"] != "accepted":
        raise HTTPException(status_code=409, detail="Collaboration is not active")

    # Content type must be covered
    if content_type not in collab.get("content_types", []):
        raise HTTPException(
            status_code=400,
            detail=f"This collaboration does not cover '{content_type}' content. Allowed: {collab['content_types']}"
        )

    # Check validity window
    now = now_ts()
    if collab.get("valid_from") and now < collab["valid_from"]:
        raise HTTPException(status_code=409, detail="Collaboration has not started yet")
    if collab.get("valid_until") and now > collab["valid_until"]:
        raise HTTPException(status_code=409, detail="Collaboration has expired")

    # Check max content cap
    max_items = collab.get("max_content_items")
    if max_items and collab.get("content_count", 0) >= max_items:
        raise HTTPException(status_code=409, detail="Collaboration has reached its content item limit")

    return collab
```

#### 3.3.2 Dual Feed Index Writes for Collaborative Posts

```python
# In app/routers/newsfeed.py, after creating the post item:

def _write_collab_feed_entries(post_item: Dict[str, Any], collab: Dict[str, Any]) -> None:
    """Write feed index entries for both collaborators."""
    post_id = post_item["post_id"]
    ts = post_item.get("created_at", now_ts())

    for user_id in [collab["initiator_id"], collab["recipient_id"]]:
        feed_entry = {
            "pk": f"FEED#{user_id}",
            "sk": f"POST#{ts}#{post_id}",
            "post_id": post_id,
            "author_id": post_item["author_id"],
            "collaboration_id": collab["collaboration_id"],
            "created_at": ts,
        }
        try:
            tbl.put_item(Item=feed_entry)
        except Exception:
            logger.warning("Failed to write feed entry for collab user %s, post %s", user_id, post_id)
```

### 3.4 Collaboration Request Flow (Sequence Diagram)

```
Creator A                    Backend                        Creator B
    |                           |                               |
    |  POST /collaborations     |                               |
    |  {recipient_id, split,    |                               |
    |   content_types, title}   |                               |
    |-------------------------->|                               |
    |                           | validate(no self-collab,      |
    |                           |   no duplicate pending,       |
    |                           |   recipient accepts requests) |
    |                           |                               |
    |                           | write collab record           |
    |                           | (status=pending)              |
    |                           |                               |
    |                           | put_notification(recipient_id,|
    |                           |   "Alice wants to collab")    |
    |                           |------------------------------>|
    |  201 {collaboration_id}   |                               |
    |<--------------------------|                               |
    |                           |                               |
    |                           |  PATCH /collaborations/{id}   |
    |                           |  {action: "counter",          |
    |                           |   counter_split_pct: 50}      |
    |                           |<------------------------------|
    |                           |                               |
    |                           | snapshot current revision      |
    |                           | create new revision            |
    |                           | (status=counter, revision++)  |
    |                           |                               |
    |                           | put_notification(initiator_id,|
    |  notification: "Bob       |   "Bob counter-proposed 50/50")|
    |  counter-proposed"        |                               |
    |<--------------------------|                               |
    |                           |                               |
    |  PATCH /collaborations/{id}                               |
    |  {action: "accept"}       |                               |
    |-------------------------->|                               |
    |                           | conditional_update            |
    |                           | (status=pending->accepted)    |
    |                           | set accepted_at               |
    |                           |                               |
    |                           | put_notification(recipient_id,|
    |                           |   "Alice accepted the collab")|
    |                           |------------------------------>|
    |  200 {status: accepted}   |                               |
    |<--------------------------|                               |
```

### 3.5 Broadcast Tip Split Integration

The modification to the broadcast tip flow is minimal. In `app/routers/broadcast.py`, the `send_tip_message_route` currently calls `write_tip_ledger` with a single recipient. The updated flow:

```python
# app/routers/broadcast.py — modified send_tip_message_route

def _process_broadcast_tip(
    session: BroadcastSessionModel,
    tipper_user_id: str,
    amount_cents: int,
    currency: str,
    payment_method_id: str,
    content_id: str,
) -> Dict[str, Any]:
    """Process a broadcast tip, splitting if the session has a collaboration."""
    collaboration_id = getattr(session, "collaboration_id", None)

    if collaboration_id:
        # Split revenue according to collaboration agreement
        from app.services.collaboration_splits import write_collaboration_split_ledger
        return write_collaboration_split_ledger(
            payer_user_id=tipper_user_id,
            collaboration_id=collaboration_id,
            amount_cents=amount_cents,
            currency=currency,
            content_type="broadcast",
            content_id=content_id,
            payment_method_id=payment_method_id,
        )
    else:
        # Single recipient (existing behavior)
        entry = TipLedgerEntry(
            tipper_user_id=tipper_user_id,
            recipient_user_id=session.created_by,
            amount_cents=amount_cents,
            currency=currency,
            content_type="broadcast",
            content_id=content_id,
            payment_method_id=payment_method_id,
        )
        return {"single": write_tip_ledger(entry)}
```

### 3.6 Collaboration Settings Per Creator

Each creator can configure their collaboration preferences:

```python
# Stored in app_single_table
{
    "pk": "USER#{user_id}",
    "sk": "COLLAB_SETTINGS",
    "accepting_requests": True,
    "default_split_pct": 50,           # default initiator percentage for incoming requests
    "allowed_content_types": ["broadcast", "post", "vod"],
    "min_split_pct": 20,              # reject any offer below 20%
    "require_terms_text": False,       # require written terms
    "auto_reject_after_hours": 168,    # auto-reject pending requests after 7 days
    "discoverable": True,              # appear in collaboration discovery search
    "updated_at": 1748390400,
}
```

### 3.7 Expiry Background Worker

A background task checks for expired collaborations and auto-rejects stale pending requests:

```python
# app/services/collaboration_expiry.py

import logging
from app.core.tables import T
from app.core.time import now_ts
from boto3.dynamodb.conditions import Key

logger = logging.getLogger(__name__)


def process_expired_collaborations() -> Dict[str, int]:
    """Check and transition expired/stale collaborations.

    Called periodically (e.g., every 5 minutes) by the background scheduler.

    Returns counts of transitions performed.
    """
    now = now_ts()
    counts = {"expired": 0, "auto_rejected": 0}

    # 1. Expire active collaborations past valid_until
    active_items = _query_by_status("accepted")
    for item in active_items:
        valid_until = item.get("valid_until")
        if valid_until and now > valid_until:
            _transition_status(
                item["collaboration_id"],
                from_status="accepted",
                to_status="expired",
                reason="Validity period ended",
            )
            counts["expired"] += 1

    # 2. Auto-reject stale pending requests
    pending_items = _query_by_status("pending")
    for item in pending_items:
        created_at = int(item.get("created_at", 0))
        # Check recipient's auto_reject_after_hours setting
        recipient_settings = _get_collab_settings(item["recipient_id"])
        auto_reject_hours = recipient_settings.get("auto_reject_after_hours", 168)
        if auto_reject_hours and (now - created_at) > auto_reject_hours * 3600:
            _transition_status(
                item["collaboration_id"],
                from_status="pending",
                to_status="expired",
                reason=f"Auto-expired after {auto_reject_hours} hours without response",
            )
            counts["auto_rejected"] += 1

    return counts
```

---

## 4. API Endpoints

### 4.1 Collaboration CRUD

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/ui/collaborations` | `require_ui_session` | Create a collaboration proposal |
| GET | `/ui/collaborations` | `require_ui_session` | List my collaborations (sent + received) |
| GET | `/ui/collaborations/{collab_id}` | `require_ui_session` | Get collaboration detail |
| PATCH | `/ui/collaborations/{collab_id}` | `require_ui_session` | Accept, reject, counter, or terminate |
| DELETE | `/ui/collaborations/{collab_id}` | `require_ui_session` | Cancel a pending request (sender only) |
| GET | `/ui/collaborations/{collab_id}/content` | `require_ui_session` | List content created under this collab |
| GET | `/ui/collaborations/{collab_id}/revenue` | `require_ui_session` | Revenue breakdown for this collab |
| GET | `/ui/collaborations/{collab_id}/revisions` | `require_ui_session` | List all revisions for a collab |
| GET | `/ui/collaborations/settings` | `require_ui_session` | Get caller's collab settings |
| PATCH | `/ui/collaborations/settings` | `require_ui_session` | Update collab settings |
| GET | `/ui/collaborations/discover` | `require_ui_session` | Discover creators open to collaboration |

### 4.2 Admin Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/ui/admin/collaborations` | `require_admin_session` | List all collaborations (with filters) |
| GET | `/ui/admin/collaborations/{collab_id}` | `require_admin_session` | Get any collab detail (for dispute resolution) |
| GET | `/ui/admin/collaborations/{collab_id}/ledger` | `require_admin_session` | Full ledger entries for a collab |

### 4.3 Request/Response Models

```python
# app/models.py additions

class CollaborationCreateIn(BaseModel):
    recipient_id: str = Field(..., min_length=1, max_length=128, description="User ID of the creator to invite")
    content_types: List[str] = Field(..., min_length=1, description="Content types covered: broadcast, post, vod")
    split_pct: int = Field(..., ge=1, le=99, description="Initiator's percentage of the revenue split")
    title: str = Field(..., min_length=1, max_length=200, description="Short title for the collaboration")
    description: Optional[str] = Field(default=None, max_length=2000, description="Detailed description")
    terms_text: Optional[str] = Field(default=None, max_length=5000, description="Written terms/conditions")
    valid_from: Optional[int] = Field(default=None, description="Unix timestamp: collaboration start date")
    valid_until: Optional[int] = Field(default=None, description="Unix timestamp: collaboration end date (null=indefinite)")
    max_content_items: Optional[int] = Field(default=None, ge=1, le=10000, description="Maximum number of co-created items")

    @model_validator(mode="after")
    def validate_dates(self):
        if self.valid_from and self.valid_until and self.valid_from >= self.valid_until:
            raise ValueError("valid_from must be before valid_until")
        for ct in self.content_types:
            if ct not in ("broadcast", "post", "vod"):
                raise ValueError(f"Invalid content_type: {ct}. Must be one of: broadcast, post, vod")
        return self


class CollaborationActionIn(BaseModel):
    action: Literal["accept", "reject", "counter", "terminate"] = Field(..., description="Action to perform")
    reason: Optional[str] = Field(default=None, max_length=500, description="Optional reason for the action")
    # For counter-proposals:
    counter_split_pct: Optional[int] = Field(default=None, ge=1, le=99, description="New split percentage (initiator's share)")
    counter_terms_text: Optional[str] = Field(default=None, max_length=5000, description="Updated terms text")
    counter_valid_until: Optional[int] = Field(default=None, description="Updated end date")

    @model_validator(mode="after")
    def validate_counter(self):
        if self.action == "counter" and self.counter_split_pct is None:
            raise ValueError("counter_split_pct is required for counter-proposals")
        return self


class CollaborationOut(BaseModel):
    collaboration_id: str
    initiator_id: str
    recipient_id: str
    initiator_profile: Optional[Dict[str, Optional[str]]] = None  # {display_name, avatar_url}
    recipient_profile: Optional[Dict[str, Optional[str]]] = None
    status: str  # pending | accepted | rejected | counter | cancelled | terminated | expired
    content_types: List[str]
    split: Dict[str, int]  # {user_id: percentage}
    title: str
    description: Optional[str] = None
    terms_text: Optional[str] = None
    valid_from: Optional[int] = None
    valid_until: Optional[int] = None
    max_content_items: Optional[int] = None
    content_count: int = 0
    total_revenue_cents: int = 0
    revision: int = 1
    created_at: int
    updated_at: int
    accepted_at: Optional[int] = None
    terminated_at: Optional[int] = None
    terminated_by: Optional[str] = None
    termination_reason: Optional[str] = None


class CollaborationListOut(BaseModel):
    items: List[CollaborationOut] = Field(default_factory=list)
    next_cursor: Optional[str] = None
    total_count: int = 0


class CollaborationRevenueOut(BaseModel):
    collaboration_id: str
    total_revenue_cents: int
    split_breakdown: Dict[str, int]  # {user_id: cents_earned}
    content_count: int
    by_content_type: Dict[str, int]  # {"broadcast": 5000, "post": 2000}
    by_month: List[Dict[str, Any]]   # [{month: "2026-05", revenue_cents: 3000}, ...]
    currency: str = "USD"


class CollaborationRevisionOut(BaseModel):
    revision: int
    split: Dict[str, int]
    terms_text: Optional[str] = None
    proposed_by: str
    proposed_at: int
    status: str  # superseded | accepted | rejected


class CollaborationSettingsIn(BaseModel):
    accepting_requests: Optional[bool] = None
    default_split_pct: Optional[int] = Field(default=None, ge=10, le=90)
    allowed_content_types: Optional[List[str]] = None
    min_split_pct: Optional[int] = Field(default=None, ge=1, le=99)
    require_terms_text: Optional[bool] = None
    auto_reject_after_hours: Optional[int] = Field(default=None, ge=1, le=720)
    discoverable: Optional[bool] = None


class CollaborationSettingsOut(BaseModel):
    accepting_requests: bool = True
    default_split_pct: int = 50
    allowed_content_types: List[str] = Field(default_factory=lambda: ["broadcast", "post", "vod"])
    min_split_pct: int = 20
    require_terms_text: bool = False
    auto_reject_after_hours: int = 168
    discoverable: bool = True
    updated_at: int = 0


class CollaborationContentItem(BaseModel):
    content_id: str
    content_type: str  # "post" | "broadcast" | "vod"
    title: str
    created_at: int
    revenue_cents: int = 0
    status: str = ""
```

### 4.4 Endpoint Implementation Details

#### POST `/ui/collaborations` — Create Proposal

```python
@router.post("/ui/collaborations", response_model=CollaborationOut, status_code=201)
def create_collaboration(
    body: CollaborationCreateIn,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]

    # Validation
    if user_id == body.recipient_id:
        raise HTTPException(status_code=400, detail="Cannot create a collaboration with yourself")

    # Check recipient accepts requests
    recipient_settings = _get_collab_settings(body.recipient_id)
    if not recipient_settings.get("accepting_requests", True):
        raise HTTPException(status_code=403, detail="This creator is not accepting collaboration requests")

    # Check recipient's minimum split
    recipient_share = 100 - body.split_pct
    min_split = recipient_settings.get("min_split_pct", 1)
    if recipient_share < min_split:
        raise HTTPException(
            status_code=400,
            detail=f"Recipient requires at least {min_split}% share"
        )

    # Check no duplicate pending request between these users
    existing = _find_pending_between(user_id, body.recipient_id)
    if existing:
        raise HTTPException(status_code=409, detail="A pending collaboration request already exists between you and this creator")

    # Check outgoing request limit
    pending_count = _count_pending_outgoing(user_id)
    if pending_count >= 10:
        raise HTTPException(status_code=429, detail="Maximum 10 pending outgoing collaboration requests")

    # Create the record
    collab_id = f"collab_{uuid.uuid4().hex}"
    now = now_ts()
    item = {
        "collaboration_id": collab_id,
        "sk": "CURRENT",
        "initiator_id": user_id,
        "recipient_id": body.recipient_id,
        "status": "pending",
        "content_types": body.content_types,
        "split": {user_id: body.split_pct, body.recipient_id: 100 - body.split_pct},
        "title": body.title,
        "description": body.description,
        "terms_text": body.terms_text,
        "valid_from": body.valid_from,
        "valid_until": body.valid_until,
        "max_content_items": body.max_content_items,
        "content_count": 0,
        "total_revenue_cents": 0,
        "revision": 1,
        "previous_revision_id": None,
        "created_at": now,
        "updated_at": now,
        "accepted_at": None,
        "terminated_at": None,
        "GSI1PK": f"USER#{user_id}",
        "GSI1SK": now,
        "GSI2PK": f"USER#{body.recipient_id}",
        "GSI2SK": now,
        "GSI3PK": "STATUS#pending",
        "GSI3SK": now,
    }
    T.collaboration_agreements.put_item(Item=item)

    # Notify recipient
    put_notification(
        body.recipient_id,
        title="New Collaboration Request",
        body=f"{session.get('display_name', 'A creator')} wants to collaborate: {body.title}",
        action_url=f"/collaborations?id={collab_id}",
        meta={"collaboration_id": collab_id, "type": "collaboration_request"},
    )

    return _enrich_collab_out(item)
```

#### PATCH `/ui/collaborations/{collab_id}` — Accept/Reject/Counter/Terminate

```python
@router.patch("/ui/collaborations/{collab_id}", response_model=CollaborationOut)
def action_collaboration(
    collab_id: str,
    body: CollaborationActionIn,
    session=Depends(require_ui_session),
):
    user_id = session["user_sub"]
    collab = get_collaboration(collab_id)
    if not collab:
        raise HTTPException(status_code=404, detail="Collaboration not found")

    # Authorization checks
    is_initiator = user_id == collab["initiator_id"]
    is_recipient = user_id == collab["recipient_id"]
    if not is_initiator and not is_recipient:
        raise HTTPException(status_code=403, detail="You are not a participant in this collaboration")

    if body.action in ("accept", "reject", "counter"):
        # Only the non-proposer can accept/reject/counter
        current_proposer = collab.get("last_proposed_by", collab["initiator_id"])
        if user_id == current_proposer:
            raise HTTPException(status_code=403, detail="You cannot accept/reject your own proposal. Wait for the other party.")
        if collab["status"] not in ("pending", "counter"):
            raise HTTPException(status_code=409, detail=f"Cannot {body.action} a collaboration with status '{collab['status']}'")

    if body.action == "terminate":
        if collab["status"] != "accepted":
            raise HTTPException(status_code=409, detail="Can only terminate an active collaboration")

    now = now_ts()

    if body.action == "accept":
        _conditional_status_update(collab_id, collab["status"], "accepted", {
            "accepted_at": now,
            "GSI3PK": "STATUS#accepted",
        })
        other_party = collab["initiator_id"] if is_recipient else collab["recipient_id"]
        put_notification(other_party, title="Collaboration Accepted", body=f"Your collaboration '{collab['title']}' has been accepted!")

    elif body.action == "reject":
        _conditional_status_update(collab_id, collab["status"], "rejected", {
            "GSI3PK": "STATUS#rejected",
        })
        other_party = collab["initiator_id"] if is_recipient else collab["recipient_id"]
        put_notification(other_party, title="Collaboration Declined", body=f"Your collaboration '{collab['title']}' was declined.")

    elif body.action == "counter":
        # Snapshot current revision
        _save_revision(collab)
        # Update with counter-proposal
        new_split = {
            collab["initiator_id"]: body.counter_split_pct,
            collab["recipient_id"]: 100 - body.counter_split_pct,
        }
        _conditional_status_update(collab_id, collab["status"], "counter", {
            "split": new_split,
            "terms_text": body.counter_terms_text or collab.get("terms_text"),
            "revision": collab["revision"] + 1,
            "last_proposed_by": user_id,
            "GSI3PK": "STATUS#counter",
        })
        other_party = collab["initiator_id"] if is_recipient else collab["recipient_id"]
        put_notification(other_party, title="Counter-Proposal Received", body=f"New terms proposed for '{collab['title']}': {body.counter_split_pct}/{100 - body.counter_split_pct} split")

    elif body.action == "terminate":
        _conditional_status_update(collab_id, "accepted", "terminated", {
            "terminated_at": now,
            "terminated_by": user_id,
            "termination_reason": body.reason,
            "GSI3PK": "STATUS#terminated",
        })
        other_party = collab["initiator_id"] if is_recipient else collab["recipient_id"]
        put_notification(other_party, title="Collaboration Ended", body=f"The collaboration '{collab['title']}' has been terminated.")

    return _enrich_collab_out(get_collaboration(collab_id))
```

---

## 5. Frontend Components

### 5.1 New Pages and Components

| Component | Path | Purpose |
|-----------|------|---------|
| `CollaborationsPage` | `frontend/src/pages/collaborations/CollaborationsPage.tsx` | Main listing page with tabs: Active, Pending, History |
| `CollaborationDetailDialog` | `frontend/src/pages/collaborations/CollaborationDetailDialog.tsx` | View/respond to a collaboration proposal |
| `CreateCollaborationDialog` | `frontend/src/pages/collaborations/CreateCollaborationDialog.tsx` | Form to propose a new collaboration |
| `CollaborationRevenueCard` | `frontend/src/pages/collaborations/CollaborationRevenueCard.tsx` | Revenue breakdown card for a collaboration |
| `CollaboratorBadge` | `frontend/src/components/shared/CollaboratorBadge.tsx` | Small badge showing collaborator avatars on posts/broadcasts |
| `CollaborationSettingsPanel` | `frontend/src/pages/collaborations/CollaborationSettingsPanel.tsx` | Configure collaboration preferences |
| `RevisionTimeline` | `frontend/src/pages/collaborations/RevisionTimeline.tsx` | Visual timeline of counter-proposal revisions |

### 5.2 Frontend API Types

```typescript
// frontend/src/api/types.ts additions

export interface CollaborationCreateIn {
  recipient_id: string;
  content_types: ("broadcast" | "post" | "vod")[];
  split_pct: number;           // 1-99, initiator's share
  title: string;
  description?: string;
  terms_text?: string;
  valid_from?: number;
  valid_until?: number;
  max_content_items?: number;
}

export interface CollaborationActionIn {
  action: "accept" | "reject" | "counter" | "terminate";
  reason?: string;
  counter_split_pct?: number;
  counter_terms_text?: string;
  counter_valid_until?: number;
}

export interface CollaborationOut {
  collaboration_id: string;
  initiator_id: string;
  recipient_id: string;
  initiator_profile?: { display_name?: string; avatar_url?: string };
  recipient_profile?: { display_name?: string; avatar_url?: string };
  status: "pending" | "accepted" | "rejected" | "counter" | "cancelled" | "terminated" | "expired";
  content_types: string[];
  split: Record<string, number>;
  title: string;
  description?: string;
  terms_text?: string;
  valid_from?: number;
  valid_until?: number;
  max_content_items?: number;
  content_count: number;
  total_revenue_cents: number;
  revision: number;
  created_at: number;
  updated_at: number;
  accepted_at?: number;
  terminated_at?: number;
  terminated_by?: string;
  termination_reason?: string;
}

export interface CollaborationRevenueOut {
  collaboration_id: string;
  total_revenue_cents: number;
  split_breakdown: Record<string, number>;
  content_count: number;
  by_content_type: Record<string, number>;
  by_month: { month: string; revenue_cents: number }[];
  currency: string;
}

export interface CollaborationSettingsOut {
  accepting_requests: boolean;
  default_split_pct: number;
  allowed_content_types: string[];
  min_split_pct: number;
  require_terms_text: boolean;
  auto_reject_after_hours: number;
  discoverable: boolean;
  updated_at: number;
}
```

### 5.3 Frontend API Endpoints

```typescript
// frontend/src/api/endpoints/collaborations.ts

import api from "../client";
import type {
  CollaborationCreateIn,
  CollaborationActionIn,
  CollaborationOut,
  CollaborationRevenueOut,
  CollaborationSettingsOut,
} from "../types";

export async function createCollaboration(data: CollaborationCreateIn): Promise<CollaborationOut> {
  const res = await api.post("/ui/collaborations", data);
  return res.data;
}

export async function listCollaborations(params?: {
  status?: string;
  cursor?: string;
}): Promise<{ items: CollaborationOut[]; next_cursor?: string }> {
  const res = await api.get("/ui/collaborations", { params });
  return res.data;
}

export async function getCollaboration(collabId: string): Promise<CollaborationOut> {
  const res = await api.get(`/ui/collaborations/${collabId}`);
  return res.data;
}

export async function actionCollaboration(
  collabId: string,
  data: CollaborationActionIn
): Promise<CollaborationOut> {
  const res = await api.patch(`/ui/collaborations/${collabId}`, data);
  return res.data;
}

export async function deleteCollaboration(collabId: string): Promise<void> {
  await api.delete(`/ui/collaborations/${collabId}`);
}

export async function getCollabRevenue(collabId: string): Promise<CollaborationRevenueOut> {
  const res = await api.get(`/ui/collaborations/${collabId}/revenue`);
  return res.data;
}

export async function getCollabSettings(): Promise<CollaborationSettingsOut> {
  const res = await api.get("/ui/collaborations/settings");
  return res.data;
}

export async function updateCollabSettings(
  data: Partial<CollaborationSettingsOut>
): Promise<CollaborationSettingsOut> {
  const res = await api.patch("/ui/collaborations/settings", data);
  return res.data;
}
```

### 5.4 CollaborationsPage Component Design

```tsx
// frontend/src/pages/collaborations/CollaborationsPage.tsx (structure)

export default function CollaborationsPage() {
  const [tab, setTab] = useState<"active" | "pending" | "history">("active");
  const [createOpen, setCreateOpen] = useState(false);
  const [selectedCollab, setSelectedCollab] = useState<CollaborationOut | null>(null);

  const activeQuery = useQuery({
    queryKey: ["collaborations", "active"],
    queryFn: () => listCollaborations({ status: "accepted" }),
  });

  const pendingQuery = useQuery({
    queryKey: ["collaborations", "pending"],
    queryFn: () => listCollaborations({ status: "pending,counter" }),
  });

  return (
    <div className="mx-auto w-full max-w-5xl space-y-6 p-4 sm:p-6">
      <div className="flex items-center justify-between">
        <PageHeader title="Collaborations" description="Manage creator partnerships and revenue splits" />
        <Button onClick={() => setCreateOpen(true)}>
          <Plus className="mr-2 h-4 w-4" />
          New Collaboration
        </Button>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as typeof tab)}>
        <TabsList>
          <TabsTrigger value="active">
            Active {activeQuery.data?.items?.length ? `(${activeQuery.data.items.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="pending">
            Pending {pendingQuery.data?.items?.length ? `(${pendingQuery.data.items.length})` : ""}
          </TabsTrigger>
          <TabsTrigger value="history">History</TabsTrigger>
        </TabsList>

        <TabsContent value="active">
          {/* Active collaboration cards with revenue summary */}
        </TabsContent>

        <TabsContent value="pending">
          {/* Pending requests with accept/reject/counter buttons */}
        </TabsContent>

        <TabsContent value="history">
          {/* Past collaborations: rejected, cancelled, terminated, expired */}
        </TabsContent>
      </Tabs>

      <CreateCollaborationDialog open={createOpen} onOpenChange={setCreateOpen} />
      {selectedCollab && (
        <CollaborationDetailDialog
          collab={selectedCollab}
          open={!!selectedCollab}
          onOpenChange={() => setSelectedCollab(null)}
        />
      )}
    </div>
  );
}
```

### 5.5 CollaboratorBadge Component

```tsx
// frontend/src/components/shared/CollaboratorBadge.tsx

interface CollaboratorBadgeProps {
  coAuthors: { user_id: string; display_name?: string; avatar_url?: string }[];
  split?: Record<string, number>;
  size?: "sm" | "md";
}

export function CollaboratorBadge({ coAuthors, split, size = "sm" }: CollaboratorBadgeProps) {
  if (!coAuthors || coAuthors.length < 2) return null;

  const avatarSize = size === "sm" ? "h-5 w-5" : "h-7 w-7";
  const fontSize = size === "sm" ? "text-xs" : "text-sm";

  return (
    <div className="inline-flex items-center gap-1.5">
      <div className="flex -space-x-1.5">
        {coAuthors.map((author) => (
          <img
            key={author.user_id}
            src={author.avatar_url || "/default-avatar.png"}
            alt={author.display_name || "Collaborator"}
            className={cn(avatarSize, "rounded-full border-2 border-background")}
            title={
              split
                ? `${author.display_name} (${split[author.user_id]}%)`
                : author.display_name
            }
          />
        ))}
      </div>
      {split && (
        <span className={cn(fontSize, "text-muted-foreground")}>
          {Object.values(split).join("/")} split
        </span>
      )}
    </div>
  );
}
```

### 5.6 Integration Points

- **CreatePost.tsx**: Add optional collaboration selector dropdown when user has active collaborations
- **PostCard.tsx**: Show `CollaboratorBadge` when post has `co_authors`
- **BroadcastSessionCard**: Show collaboration indicator and split percentage
- **Earnings Dashboard**: Add `collaborations` breakdown category
- **Sidebar.tsx / AppShell.tsx**: Add "Collaborations" nav item under Creator Tools group
- **MobileNav.tsx**: Add "Collaborations" to `MORE_LINKS`
- **Profile page**: Show active collaborations count

### 5.7 Route

```tsx
// App.tsx
{ path: "/collaborations", element: <CollaborationsPage /> }
```

---

## 6. DynamoDB Table Definition

### 6.1 collaboration_agreements Table

```python
# scripts/local-ddb-init.py
TableDef(
    name="collaboration_agreements",
    pk="collaboration_id",
    sk="sk",  # "CURRENT" for main record, "REV#NNNN" for revisions
    gsis=[
        GsiDef(name="ByInitiator", pk="GSI1PK", sk="GSI1SK"),
        GsiDef(name="ByRecipient", pk="GSI2PK", sk="GSI2SK"),
        GsiDef(name="ByStatus", pk="GSI3PK", sk="GSI3SK"),
    ],
    attr_types={"GSI1SK": "N", "GSI2SK": "N", "GSI3SK": "N"},
),
```

Note: `GSI1SK`, `GSI2SK`, and `GSI3SK` use numeric sort keys (`created_at` as Unix timestamp), so `attr_types` must declare them as `"N"` to avoid the DynamoDB `ValidationException` documented in CLAUDE.md.

### 6.2 Table Handle Registration

```python
# app/core/tables.py addition
collaboration_agreements = ddb.Table(S.collaboration_agreements_table or "collaboration_agreements")
```

```python
# app/core/settings.py addition
collaboration_agreements_table: str = "collaboration_agreements"
```

### 6.3 DynamoDB Access Patterns

| Access Pattern | Table/Index | Key Condition | Filter |
|----------------|-------------|---------------|--------|
| Get collab by ID | Main table | `collaboration_id = X, sk = CURRENT` | - |
| Get revisions | Main table | `collaboration_id = X, sk begins_with REV#` | - |
| List by initiator | GSI1 ByInitiator | `GSI1PK = USER#{user_id}` | - |
| List by recipient | GSI2 ByRecipient | `GSI2PK = USER#{user_id}` | - |
| List by status | GSI3 ByStatus | `GSI3PK = STATUS#{status}` | - |
| Find pending between two users | GSI1 + filter | `GSI1PK = USER#{user_a}` | `recipient_id = user_b AND status = pending` |

### 6.4 Capacity Estimates

Collaboration agreements are low-volume: a very active creator might have 20-50 collaborations over their lifetime. The table will have:
- ~10K items for 500 active creators (including revisions)
- Read pattern: burst on page load (2-3 queries), then occasional polling
- Write pattern: very low (creates, status transitions, revenue counter updates)
- On-demand billing is appropriate; no need for provisioned capacity

---

## 7. E2E Test Plan

### 7.1 Test File

`frontend/e2e/creator-collaborations.spec.ts`

### 7.2 Test Sections

| Section | Title | Tests |
|---------|-------|-------|
| 1 | Collaboration CRUD API | 8 tests: create, get, list (sent/received), counter-propose, accept, reject, cancel, terminate |
| 2 | Revenue Split API | 5 tests: create collab content, verify split ledger entries, check revenue summary, validate rounding, check earnings dashboard category |
| 3 | Collaborative Broadcast API | 4 tests: create session with collab_id, verify tip split, verify product sale split, check co-author attribution |
| 4 | Collaborative Post API | 4 tests: create post with collab_id, verify post has co_authors, verify post tip split, verify locked post unlock split |
| 5 | Collaboration Lifecycle | 4 tests: expiry enforcement (valid_until passed), max content cap, terminated collab blocks new content, existing content keeps split after termination |
| 6 | CollaborationsPage UI | 5 tests: page loads with tabs, create dialog opens, pending tab shows incoming requests, accept/reject buttons work, revenue card renders |
| 7 | Collaboration Settings API | 4 tests: get default settings, update accepting_requests, reject requests when not accepting, min_split_pct enforcement |
| 8 | Validation & Edge Cases | 4 tests: self-collaboration 400, duplicate pending 409, split > 99 rejected, max revisions (10) enforced |

**Estimated total**: ~38 tests

### 7.3 Test Data Setup

```typescript
// beforeAll:
// 1. Seed Alice and Bob sessions via injectAuth
// 2. Alice creates a collaboration proposal to Bob (60/40 split)
// 3. Capture collab_id for subsequent tests

const TS = Date.now();
let collabId: string;
let aliceSub: string;
let bobSub: string;

test.beforeAll(async ({ browser }) => {
  const alicePage = await browser.newPage();
  await injectAuth(alicePage, "alice");
  aliceSub = sessions.alice.user_sub;
  bobSub = sessions.bob.user_sub;

  // Create collaboration
  const resp = await alicePage.request.post("/ui/collaborations", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      recipient_id: bobSub,
      content_types: ["broadcast", "post"],
      split_pct: 60,
      title: `E2E Collab ${TS}`,
      description: "Test collaboration",
    },
  });
  expect(resp.status()).toBe(201);
  const body = await resp.json();
  collabId = body.collaboration_id;

  // Bob accepts
  const bobPage = await browser.newPage();
  await injectAuth(bobPage, "bob");
  const acceptResp = await bobPage.request.patch(`/ui/collaborations/${collabId}`, {
    headers: { "x-csrf-token": sessions.bob.csrf_token },
    data: { action: "accept" },
  });
  expect(acceptResp.status()).toBe(200);

  await alicePage.close();
  await bobPage.close();
});
```

### 7.4 Example Test Cases

```typescript
// Section 1: CRUD

test("1.1 — Alice creates a collaboration proposal", async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  const resp = await page.request.post("/ui/collaborations", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      recipient_id: bobSub,
      content_types: ["broadcast", "post"],
      split_pct: 70,
      title: `Crud Test Collab ${TS}`,
    },
  });
  expect(resp.status()).toBe(201);
  const body = await resp.json();
  expect(body.status).toBe("pending");
  expect(body.split[aliceSub]).toBe(70);
  expect(body.split[bobSub]).toBe(30);
  expect(body.initiator_id).toBe(aliceSub);
  expect(body.recipient_id).toBe(bobSub);

  await page.close();
});

test("1.2 — Self-collaboration returns 400", async ({ browser }) => {
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  const resp = await page.request.post("/ui/collaborations", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      recipient_id: aliceSub,
      content_types: ["post"],
      split_pct: 50,
      title: "Self collab",
    },
  });
  expect(resp.status()).toBe(400);

  await page.close();
});

// Section 2: Revenue Split

test("2.1 — Revenue split distributes correctly", async ({ browser }) => {
  // Create a collaborative post, send a tip, verify ledger entries
  const page = await browser.newPage();
  await injectAuth(page, "alice");

  // Create post with collaboration_id
  const postResp = await page.request.post("/posts", {
    headers: { "x-csrf-token": sessions.alice.csrf_token },
    data: {
      body: `Collab post ${TS}`,
      collaboration_id: collabId,
    },
  });
  expect(postResp.status()).toBe(201);
  const post = await postResp.json();

  // Inject payment method for tipperr (Charlie or third user)
  // ... tip the post ...
  // ... verify billing ledger has two credit entries ...

  await page.close();
});
```

---

## 8. Edge Cases

| Case | Behavior |
|------|----------|
| Self-collaboration | 400 error -- `initiator_id` cannot equal `recipient_id` |
| Split does not sum to 100 | 400 error -- `split_pct` is initiator's share; recipient gets `100 - split_pct` |
| Duplicate pending request | 409 error -- only one pending request between the same two users at a time |
| Counter-proposal loop | Each counter increments `revision`. Max 10 revisions before auto-expire. |
| Revenue on terminated collab | Existing content retains its split. New content cannot be tagged to terminated collabs. |
| Rounding cents | `floor(amount * pct / 100)` for each party. Remainder (max N-1 cents for N parties) goes to initiator. |
| Collaboration expires (valid_until) | Background worker transitions to `expired`. Content created after expiry rejected with 409. |
| One party deletes account | Remaining party receives 100% of future revenue on existing collab content. Collab auto-terminates. |
| Concurrent accept and cancel | DynamoDB conditional update on `status=pending` ensures only one wins. Loser gets 409. |
| Split change request | Not supported mid-collaboration. Must terminate and create a new collaboration with new terms. |
| Recipient not accepting requests | 403 error when trying to create a collaboration with a creator who has `accepting_requests=false`. |
| Content type mismatch | 400 error when tagging content with a `collaboration_id` whose `content_types` list does not include the content type being created. |
| $0.01 tip with 60/40 split | Alice gets 1 cent (floor(1*60/100)=0, remainder=1 goes to initiator), Bob gets 0 cents. A zero-share credit is not written. |
| Stale pending request | Background worker auto-expires after `auto_reject_after_hours` (default 168 = 7 days) without response. |
| Rapid counter-proposals | Each counter is validated against `revision < 10`. At revision 10, further counters return 409 with "Maximum negotiation revisions reached". |
| Collaboration with banned user | Creating content under a collaboration where one party is banned (checked via `is_user_currently_banned`) returns 403. |
| Network partition during ledger write | If one collaborator's credit write fails, the other still succeeds. A reconciliation job can detect orphaned debits without matching credits and re-attempt. |

---

## 9. Security Considerations

### 9.1 Authorization

- Only the initiator can cancel a pending request
- Only the recipient can accept/reject/counter a pending request (when initiator proposed), and vice versa for counter-proposals
- Either party can terminate an active collaboration
- Revenue data for a collaboration is only visible to the two parties involved
- Admin/root users can view any collaboration for dispute resolution
- All CRUD operations require `require_ui_session` authentication with CSRF token validation

### 9.2 Financial Integrity

- Ledger entries are immutable once written (no retroactive split changes)
- Split percentages are stored on the collaboration agreement at acceptance time and cannot be modified
- Each content item records the `collaboration_id` and the split that was in effect at creation time (snapshot), protecting against agreement modifications
- Platform fee (if applicable) is deducted before the split is applied
- The `total_revenue_cents` counter on the collaboration record uses DynamoDB `ADD` atomic increment to prevent race conditions
- Ledger meta includes `collaboration_id`, `split_pct`, and `total_amount_cents` for full audit trail

### 9.3 Rate Limiting

- Max 10 pending outgoing collaboration requests per user (prevents spam)
- Counter-proposal loop capped at 10 revisions
- Collaboration creation rate-limited to 5 per hour per user
- Settings updates rate-limited to 10 per minute per user

### 9.4 Notifications

- Collaboration proposals trigger a notification to the recipient via `put_notification` (same pattern as `app/routers/newsfeed.py`)
- Acceptance/rejection/counter/termination all trigger notifications to the other party
- Revenue milestones (first $100 earned together, etc.) optionally trigger celebration notifications
- Notification body never includes financial amounts in push notifications (only in-app)

### 9.5 Input Validation

- `content_types` values validated against whitelist: `["broadcast", "post", "vod"]`
- `split_pct` constrained to 1-99 (Pydantic `ge=1, le=99`)
- `title` length: 1-200 characters
- `description` max: 2000 characters
- `terms_text` max: 5000 characters
- `valid_from` / `valid_until` must be valid Unix timestamps; `valid_from < valid_until`
- All user IDs validated as non-empty strings matching the platform's user ID format

### 9.6 Data Isolation

- GSI queries return only items where the caller is `initiator_id` or `recipient_id`
- The list endpoint merges results from ByInitiator and ByRecipient GSIs, deduplicating by `collaboration_id`
- Admin endpoints use a separate GSI (ByStatus) that does not filter by user, and require `require_admin_session`
