# CREATOR-001: Creator-to-Creator Collaboration Requests — Investigation & Implementation Write-up

## 1. Summary & Classification

Collaboration requests allow creators to propose formal content-creation partnerships with negotiated revenue splits. One creator proposes, the other accepts, rejects, or counter-proposes; once accepted, co-created broadcasts and newsfeed posts generate automatic split ledger entries. The backend service, router, Pydantic models, and TypeScript types are fully implemented. The frontend page (`CollaborationsPage.tsx`) covers core flows. Several designed features are absent or incomplete: revenue/discover/admin endpoints, the `CollaborationRevenueCard` and `CollaboratorBadge` components, integration into the newsfeed post creation flow, and pytest unit tests.

- **Type**: Feature
- **Priority**: Medium
- **Status**: Core backend fully implemented; some extension endpoints and frontend components missing.
- **Area**: Creator tools / Billing / Newsfeed
- **User persona**: Platform creators who want to collaborate with other creators and share revenue automatically.
- **Dependencies**: `tip_ledger.py` (billing ledger), `creator_earnings.py`, `broadcast_store.py`, `newsfeed.py`.
- **Cross-reference**: ANALYTICS-001 (creator analytics dashboard), BCAST-001 (broadcaster dashboard for collaboration-linked sessions).

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer (`app/services/collaborations.py`, 412 lines)

All core collaboration business logic lives here. The table is accessed via `T.collaboration_agreements` (from `app/core/tables.py`) for the main collaboration data, and via `_app_table()` (line 310 — returns `T.app`) for creator collaboration settings stored in the app single table.

Key functions:

| Function | Line | Purpose |
|---|---|---|
| `get_collaboration(collaboration_id)` | 23 | `get_item(Key={pk: collaboration_id, sk: "CURRENT"})` |
| `list_collaborations(user_sub, ...)` | 31 | Queries GSI1 (ByInitiator) and GSI2 (ByRecipient) and deduplicates |
| `create_collaboration(user_sub, body)` | 93 | Validates self-collab, settings, pending limit (10), writes CURRENT record |
| `accept_collaboration(collaboration_id, user_sub)` | 148 | Conditional update pending→accepted, `accepted_at = now_ts()` |
| `reject_collaboration(collaboration_id, user_sub)` | 166 | Conditional update pending/counter→rejected |
| `cancel_collaboration(collaboration_id, user_sub)` | 183 | Initiator-only cancel of pending/counter |
| `terminate_collaboration(collaboration_id, user_sub, reason)` | 200 | Either party can terminate accepted collaboration |
| `counter_propose(collaboration_id, user_sub, body)` | 219 | Saves revision snapshot, updates split/terms/status=counter |
| `get_revision_history(collaboration_id)` | 260 | Queries SK `begins_with("REV#")` on the same table |
| `find_pending_between(user_a, user_b)` | 272 | Prevents duplicate pending requests |
| `count_pending_outgoing(user_id)` | 295 | Enforces 10-request limit |
| `get_collab_settings(user_sub)` | 316 | Reads `USER#{sub}#COLLAB_SETTINGS` from app table |
| `update_collab_settings(user_sub, updates)` | 330 | Writes collab settings (`accepting_requests`, `min_split_pct`, `allowed_content_types`, `auto_expire_days`) |

DynamoDB design: Single table `collaboration_agreements`. PK = `collaboration_id` (UUID). SK = `"CURRENT"` for main record, `"REV#0001"`, `"REV#0002"` etc. for revision snapshots. GSI1 (ByInitiator): `GSI1PK = USER#{initiator_id}`, `GSI1SK = created_at`. GSI2 (ByRecipient): `GSI2PK = USER#{recipient_id}`, `GSI2SK = created_at`. GSI3 (ByStatus): `GSI3PK = STATUS#{status}`, `GSI3SK = created_at`. All numeric GSI sort keys declared with `attr_types={"created_at": "N"}` in `scripts/local-ddb-init.py:1451`.

Revenue split service lives at `app/services/collaboration_splits.py`. `write_collaboration_split_ledger` (the main function) fetches the collaboration record, computes floor-division shares for each collaborator, writes debit+credit via `write_tip_ledger` from `app/services/tip_ledger.py:88`, and calls `_update_collab_revenue` to atomically increment `total_revenue_cents`. Remainder cents (from rounding) go to the initiator.

Expiry background worker at `app/services/collaboration_expiry.py`: `process_expired_collaborations()` queries GSI3 for `pending` and `accepted` status items and transitions stale/expired collaborations. This must be registered with the background scheduler in `app/main.py`.

### 2.2 Router (`app/routers/collaborations.py`, 533 lines)

Registered in `app/main.py` with prefix `/ui/collaborations`. Feature flag at line 89: `if not S.collaborations_enabled: raise HTTPException(404, "Collaborations not enabled")`. Auth dependency: `require_ui_session` on all endpoints.

Implemented endpoints:

| Method | Path | Line |
|---|---|---|
| POST | `` | 97 — `create_collab` |
| GET | `` | 141 — `list_collabs` with `status`, `role` query filters |
| GET | `/settings` | 157 — `get_settings` |
| PUT | `/settings` | 164 — `update_settings` |
| GET | `/{collab_id}` | 172 — `get_collab` |
| POST | `/{collab_id}/accept` | 184 |
| POST | `/{collab_id}/reject` | 200 |
| POST | `/{collab_id}/counter` | 216 |
| POST | `/{collab_id}/cancel` | 240 |
| POST | `/{collab_id}/terminate` | 254 |
| GET | `/{collab_id}/revisions` | 268 |
| POST | `/{collab_id}/split` | 297 — manual revenue split trigger |
| POST | `/{collab_id}/content` | 366 — assign content to collaboration |
| GET | `/{collab_id}/content` | 392 |
| DELETE | `/{collab_id}/content/{content_id}` | 407 |
| POST | `/{collab_id}/content/{content_id}/revenue-event` | 423 |
| GET | `/{collab_id}/splits` | 450 |
| POST | `/{collab_id}/splits/{split_id}/dispute` | 470 |
| GET | `/{collab_id}/disputes` | 495 |
| POST | `/{collab_id}/disputes/{dispute_id}/resolve` | 511 |

The `_is_admin` helper at line 362 checks `ctx["role"] in ("admin", "root")` — used in content and dispute endpoints to allow admin override of participant-only access.

Notification calls use `put_notification(recipient_user_id=..., notif_type=..., payload={...})` (matching the actual signature at `app/routers/newsfeed.py:2177`).

### 2.3 Pydantic models (`app/models.py:3315-3417`)

Models differ from the design in a few ways:
- `CollaborationActionIn` was NOT implemented — separate models per action (`CollaborationCounterIn` at 3336, `CollaborationTerminateIn` at 3343).
- `CollaborationOut` at 3347 does NOT have `initiator_profile` / `recipient_profile` sub-objects (profile enrichment was deferred).
- `CollaborationSettingsOut` uses `auto_expire_days: int = 7` (not `auto_reject_after_hours`).
- `CollaborationSplitIn` at 3411 exists (not in original design).
- `CollaborationRevisionOut` at 3387 exists.
- `CollaborationListOut` at 3382 has `items` and `next_cursor` but no `total_count`.

Additional models added for the extended revenue/dispute functionality: `CollabContentItem`, `CollabSplitRecord`, `CollabDisputeOut`, `CollabContentListOut`, `CollabSplitHistoryOut`, `CollabDisputeListOut` — all present in `app/models.py` beyond line 3417 (the dispute and content tracking models added with the extended router endpoints at lines 366-530).

### 2.4 Frontend (`frontend/src/pages/collaborations/`)

Files in the directory:
- `CollaborationsPage.tsx` (387 lines) — all-in-one page with tabs: Incoming, Outgoing, Active, Settings. Create dialog, action buttons (accept/reject/counter/cancel/terminate), revision history modal are all inline.
- `CollaborationRevenuePage.tsx` — EXISTS (separate file for revenue breakdown view).
- `CollaborationSplitDisputeDialog.tsx` — EXISTS.

**Missing as separate components** (still inline or absent):
- `CollaborationRevenueCard` — referenced in the design; not extracted as standalone component
- `CollaboratorBadge` — not implemented; co-author attribution on posts/broadcasts has no UI badge
- `RevisionTimeline` — revision history shows as a list inside the page modal, not a standalone timeline component

TypeScript types at `frontend/src/api/types.ts:4031-4102`. API endpoints at `frontend/src/api/endpoints/collaborations.ts` (70 lines). The endpoint file uses `api.post/api.get/api.put` — NOT `res.data` — consistent with the `axios` instance in `api/client.ts` which already extracts `.data` in the interceptor.

### 2.5 Settings integration (`app/core/settings.py`)

- `collaborations_enabled: bool` at line 1865 — defaults to `"1"` (enabled in dev and prod)
- `collaboration_agreements_table_name: str` at line 1866 — `"collaboration_agreements"`
- `collaboration_revenue_enabled: bool` at line 1868 — defaults to `"1"`

### 2.6 Dev vs. prod behavior today

| Path | Dev | Prod |
|---|---|---|
| DDB writes | DDB Local port 8001 | AWS DynamoDB |
| Notifications | `put_notification` writes to app single table, SSE | same |
| Revenue splits | `write_tip_ledger` writes to `T.billing` | same |
| S3 (no S3 in this feature) | N/A | N/A |
| Feature flag | `COLLABORATIONS_ENABLED=1` by default | configurable |

No AWS-specific services (Cognito, SNS, SES) are involved. The entire collaboration system uses DynamoDB + the billing ledger, both of which are mocked by DDB Local + moto in dev.

## 3. Gap / Threat Analysis

### 3.1 Missing: `/discover` endpoint

The design specifies `GET /ui/collaborations/discover` to return creators who have opted into collaboration discovery (`accepting_requests=true`, `discoverable=true`). This endpoint is not implemented. Without it, creators have no in-platform way to find potential collaborators — they must know a specific creator's user ID to send a request.

The `discover` implementation would query the app table for all `USER#*#COLLAB_SETTINGS` items with `accepting_requests=true`. A GSI on the settings table would be needed, or a scan with `FilterExpression`. For v1, a scan is acceptable (settings table will be small).

### 3.2 Missing: admin endpoints

`GET /ui/admin/collaborations`, `GET /ui/admin/collaborations/{id}`, `GET /ui/admin/collaborations/{id}/ledger` are not implemented. The `_is_admin` helper at line 362 exists but is used only for content and dispute access, not a standalone admin listing endpoint.

### 3.3 Missing: integration into `broadcast.py` tip flow

`app/services/collaboration_splits.py` (`write_collaboration_split_ledger`) exists, but `app/routers/broadcast.py`'s `send_tip_message_route` (around line 1643) still writes a single-recipient ledger entry for all broadcast tips. The `collaboration_id` field on `BroadcastSessionModel` needs to be added and checked at tip time to trigger the split.

### 3.4 Missing: integration into `newsfeed.py` post creation

Posts created with a `collaboration_id` should:
1. Write dual feed index entries (one per co-author) via `_write_collab_feed_entries`
2. Set `co_author_ids` on the post item
3. Include `co_authors` in `PostResponse`

None of these changes exist in `app/routers/newsfeed.py`. The `PostResponse` model (line 1352) has no `co_authors` field.

### 3.5 Missing: pytest unit tests

`tests/test_collaborations.py` does not exist. The service functions (`create_collaboration`, `accept_collaboration`, `counter_propose`, `find_pending_between`, `count_pending_outgoing`, `write_collaboration_split_ledger`) are untested. The E2E spec `creator-collaborations.spec.ts` (718 lines) covers API-level scenarios but not edge cases like concurrent accept + reject, rounding in split math, or the 10-request limit.

### 3.6 Missing: `CollaboratorBadge` in post/broadcast renders

The design calls for co-author badges on newsfeed posts and broadcast headers. Neither `PostCard.tsx` nor the broadcast viewer renders a `CollaboratorBadge`. Without this, the content attribution benefit of the feature is invisible.

### 3.7 Earnings category gap

`app/services/creator_earnings.py:22` (`_reason_to_category`) does not have a `"collaborations"` case. Collaboration split credits use `reason="Collaboration {content_type} split"` (set in `collaboration_splits.py`). Without the category mapping, these credits fall under `"other"` in the dashboard breakdown.

## 4. Proposed Design / Fix

### 4.1 `/discover` endpoint

Add to `app/routers/collaborations.py`:
```python
@router.get("/discover", response_model=List[Dict])
def discover_collaborators(
    q: Optional[str] = None,
    ctx: Dict = Depends(require_ui_session),
):
    _check_enabled()
    # Scan app table for COLLAB_SETTINGS items with accepting_requests=True
    # Filter out the calling user's own settings
    # Return list of {user_id, display_name, avatar_url, allowed_content_types}
```
Enrich results with `get_profile_identity` from `app/services/profile`. Add a `discoverable: Optional[bool]` field to `CollaborationSettingsIn` / `CollaborationSettingsOut` models.

### 4.2 Broadcast tip split integration

In `app/routers/broadcast.py`, modify `send_tip_message_route` to check `session.collaboration_id`:
```python
if getattr(session, "collaboration_id", None):
    write_collaboration_split_ledger(
        payer_user_id=user_id,
        collaboration_id=session.collaboration_id,
        amount_cents=body.amount_cents,
        ...
    )
else:
    # existing single-recipient path
```
Add `collaboration_id: Optional[str] = None` field to `BroadcastSessionModel` in `app/services/broadcast_store.py` and persist it in `session_to_item`/`item_to_session`.

### 4.3 Earnings category

In `app/services/creator_earnings.py:22`, add before the `return "other"` line:
```python
if "collaboration" in reason_lower or "collab" in reason_lower:
    return "collaborations"
```
Add `"collaborations": 0` to the `breakdown` dict initializer at line 77.

### 4.4 Dev/prod parity

No additional dev/prod parity work needed. DDB Local handles all table operations. The `collaboration_expiry.py` background worker must be registered in `app/main.py`'s startup tasks — check if it is currently registered:
```python
# In app/main.py startup:
from app.services.collaboration_expiry import process_expired_collaborations
# Schedule via existing background task pattern (e.g., asyncio periodic task or APScheduler)
```

### 4.5 Unit tests (`tests/test_collaborations.py`)

Create with moto `@mock_aws`. Test cases:
- `test_create_collaboration_self_reject` — same user as recipient → 400
- `test_create_collaboration_not_accepting` — recipient has `accepting_requests=False` → 403
- `test_pending_limit` — 11th request → 429
- `test_counter_proposal_saves_revision` — revision SK `REV#0001` written
- `test_revenue_split_rounding` — $10.33 with 60/40 split → Alice $6.20, Bob $4.13
- `test_accept_only_by_non_proposer` — initiator tries to accept own proposal → 403
- `test_duplicate_pending_blocked` — second pending request → 409

## 5. Testing, Verification & Rollout

### 5.1 Existing E2E

`frontend/e2e/creator-collaborations.spec.ts` (718 lines) and `frontend/e2e/collaboration-revenue.spec.ts` exist. Run: `cd frontend && npx playwright test e2e/creator-collaborations.spec.ts e2e/collaboration-revenue.spec.ts`.

### 5.2 Manual QA steps

1. `just restart`.
2. Alice sends collaboration request to Bob (`POST /ui/collaborations`).
3. Bob receives notification — verify `notif_type="collaboration_request"` in alerts.
4. Bob counter-proposes 50/50 (`POST /{id}/counter`) — verify `revision` increments.
5. Alice accepts counter (`POST /{id}/accept`) — verify `status=accepted`, `accepted_at` set.
6. Alice creates a broadcast with `collaboration_id` set.
7. Charlie tips the broadcast — verify split ledger: Alice gets 50%, Bob gets 50% (verify in DDB `T.billing` table).
8. Alice views earnings dashboard — verify "Collaborations" category appears.
9. Either party terminates — verify `status=terminated`, `terminated_at` set.

### 5.3 Rollout

`COLLABORATIONS_ENABLED=0` disables all endpoints with 404. The sidebar "Collaborations" nav item in `Sidebar.tsx` should be conditionally hidden when the feature flag is off — verify this via the `/ui/config` endpoint or a dedicated check.

### 5.4 Observability

No metrics are currently emitted for collaboration events. Add the following counters via `app/metrics.py`:
- `collaboration_created_total` — on successful `create_collaboration`
- `collaboration_accepted_total` — on `accept_collaboration`
- `collaboration_rejected_total` — on `reject_collaboration`
- `collaboration_revenue_split_total_cents` — histogram / counter of split amounts, to track revenue flow through the collaboration system
- `collaboration_counter_proposals_total` — to understand negotiation round-trip rates

These counters connect to SECOPS-001 observability requirements. The `total_revenue_cents` field on the collaboration record is a running total visible via `GET /ui/collaborations/{id}`, but server-side metrics provide a cross-collaboration aggregate.

### 5.5 Financial correctness notes

The rounding strategy in `write_collaboration_split_ledger` uses floor division (`amount_cents * pct // 100`) with the remainder going to the initiator. This is correct and auditable: every ledger entry includes `meta.split_pct`, `meta.total_amount_cents`, and `meta.collaboration_id`, allowing per-entry audit of the expected versus actual payout. A reconciliation query can detect drift: sum all credits where `meta.collaboration_id = X` and compare to `collaboration.total_revenue_cents`.

The `_update_collab_revenue` atomic increment (`SET total_revenue_cents = total_revenue_cents + :amt`) is best-effort — it wraps a `try/except` and logs on failure. In a high-throughput broadcast tip scenario (many tips per second), this DDB write adds latency to the tip flow. Consider batching or making it fully async (fire-and-forget to a background queue) for hot broadcast sessions.

### 5.6 Known open risks

- **Terminated collaboration + in-flight content**: If a collaboration is terminated mid-broadcast, in-flight tips should still split correctly (the split service checks `status == "accepted"` and raises if not). The broadcaster must either end the collaboration after the broadcast ends or accept that tips during the termination race will raise an error in the split service. The UI should warn: "Terminating an active collaboration during a live broadcast will prevent revenue splitting for subsequent tips."
- **Circular collaboration prevention**: Nothing prevents Alice from proposing to Bob while Bob has a pending proposal to Alice. `find_pending_between` at `collaborations.py:272` checks for pending requests from either direction, preventing this loop.
- **Counter-proposal DoS**: No limit on counter-proposal rounds. A bad actor could use the counter-propose endpoint to flood a creator with notifications. Add `max_revision_depth: int = 10` — after 10 rounds, further counters are rejected with 409.

**Effort for remaining work**: Broadcast tip integration (M, 3 days). Newsfeed co-author integration (M, 3 days). `/discover` endpoint (S, 1 day). Unit tests (S, 1 day). Earnings category (XS, 30 minutes). `CollaboratorBadge` component (S, 2 days). Observability counters (S, 1 day). Total: ~2.5 weeks.
