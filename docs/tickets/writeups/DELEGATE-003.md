# DELEGATE-003: Newsfeed Delegation — Investigation & Implementation Write-up

## 1. Summary & Classification

DELEGATE-003 lets delegates manage a creator's newsfeed. Delegates with `feed_post` can create, edit, and delete posts (stored with `author_id=creator_id` and `posted_by_delegate=delegate_id`). A creator-controlled `require_post_approval` flag gates direct publish: when enabled, delegate posts enter a draft state (`approval_status=pending`) and the creator approves or rejects from a draft queue. Delegates with `feed_moderate` can hide, pin, and delete comments. Delegates with `feed_read` can query analytics.

- **Type**: Feature (content delegation with approval workflow)
- **Priority**: High
- **Status**: Backend fully implemented; frontend partially implemented (main page exists, sub-components and `PostCard`/`FeedPage` modifications are absent)
- **Owning area**: Newsfeed / content management / authorization
- **User personas**: Delegate (post/moderate/analytics), Creator (approve/reject drafts, audit)
- **Cross-references**: [[DELEGATE-001]] (required), [[SEC-005]] (IDOR — post ownership verified before edit/delete), [[SEC-018]] (revocation — instant via service-layer permission check), [[SECOPS-007]] (DDB Local vs prod), [[DELEGATE-005]] (feed delegation via API key)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Service layer — `app/services/delegate_feed.py` (799 lines, fully implemented)

The service uses a single-table pattern via `ddb.Table(APP_TABLE)` where `APP_TABLE = os.environ.get("APP_TABLE", "app_single_table")`. Post items use keys `pk=POST#{post_id}`, `sk=META`. This mirrors the existing `newsfeed.py` patterns.

| Function | Location | Notes |
|----------|----------|-------|
| `create_post_as_creator` | `delegate_feed.py:101` | Calls `require_delegate_permission(..., "feed_post")`; checks `require_post_approval` setting; sets `approval_status=pending` + `GSI5PK=DRAFT_QUEUE#{creator_id}` when approval needed; calls `_fan_out` on direct publish |
| `edit_post_as_creator` | `delegate_feed.py:210` | Validates post `user_id == creator_id`; requires `feed_post` |
| `delete_post_as_creator` | `delegate_feed.py:302` | Validates post `user_id == creator_id`; requires `feed_post` |
| `list_creator_posts` | `delegate_feed.py:330` | Requires `feed_read`; queries by creator's feed |
| `list_pending_drafts` | `delegate_feed.py:359` | Creator-only; queries `GSI5` with `GSI5PK=DRAFT_QUEUE#{creator_id}` |
| `approve_draft` | `delegate_feed.py:378` | Validates `user_id == creator_id` and `approval_status == pending`; updates to `published`, removes `GSI5PK/GSI5SK`, calls `_fan_out` |
| `reject_draft` | `delegate_feed.py:435` | Validates same; sets `approval_status=rejected`, removes from queue |
| `moderate_comment` | `delegate_feed.py:483` | Requires `feed_moderate`; validates `action in ("hide","pin","unpin","delete")`; verifies post belongs to creator |
| `get_creator_feed_analytics` | `delegate_feed.py:616` | Requires `feed_read`; returns aggregate counts |
| `list_delegate_feed_actions` | `delegate_feed.py:666` | Creator audit; filters audit entries to feed-related `action` values |

`_fan_out` at `delegate_feed.py:789` calls `newsfeed_fanout.fan_out_post_to_followers` — the existing fanout mechanism — so approved delegate posts propagate to followers identically to creator-direct posts.

### 2.2 Draft approval GSI

The ticket design proposed a new `DraftApprovalQueue` GSI on the `newsfeed` table. The actual implementation reuses the existing `GSI5` on `app_single_table` (defined at `scripts/local-ddb-init.py:372`). However, `GSI5SK` is declared as type `"S"` (string) at `local-ddb-init.py:377`, and the feed delegation code does not set `GSI5SK` on draft items. Examining `create_post_as_creator`: when `approval_status=pending`, the code sets `GSI5PK=DRAFT_QUEUE#{creator_id}` but does NOT set `GSI5SK`. The `list_pending_drafts` query uses `KeyConditionExpression=Key("GSI5PK").eq(...)` without a sort key condition, which works for DDB Local but in prod `GSI5SK` being absent may cause items to not appear in the index depending on DynamoDB Local version.

**Gap**: `GSI5SK` is not set on draft post items created by `create_post_as_creator`. This could cause `list_pending_drafts` to return empty in some DynamoDB configurations. The `GSI5` sort key for the social follow pattern (`{created_at}#{follower_id}`) is entirely different from what delegate drafts need.

### 2.3 Router — `app/routers/delegate_feed.py` (281 lines)

All 12 endpoints from the ticket design are implemented under `/ui/newsfeed/delegate`. Creator-only endpoints (drafts, audit, settings) enforce `user["user_sub"] == creator_id` at `delegate_feed.py:129,144,163,230,248,268`. The delegate CRUD endpoints delegate to the service which calls `require_delegate_permission`.

`delegate_feed_router` is registered in `app/main.py:698`.

### 2.4 Frontend

**`DelegateFeedPage.tsx` (386 lines)**: A comprehensive component with tabs for Posts, Analytics, and Audit. It calls `getFeedAnalytics(creatorId)` and `getFeedDelegateAudit(creatorId)` from `delegateFeed.ts`.

**Sub-components not created as standalone files**: `DraftApprovalQueue.tsx`, `CommentModerationPanel.tsx`, `FeedAnalyticsSummary.tsx`, `FeedDelegateAuditLog.tsx` — the ticket described them as separate files. The actual implementation embeds equivalent functionality inline within `DelegateFeedPage.tsx`.

**`PostCard.tsx`**: No `delegate_tag` or `approval_status` rendering exists. The ticket required PostCard to show `"[Draft - Pending Approval]"` badge and `"[Posted by @delegate]"` tag — these are absent.

**`FeedPage.tsx`**: No `"Draft Queue"` notification badge exists for creators with pending delegate drafts.

**Route**: `frontend/src/App.tsx:340` has `<Route path="feed/delegate/:creatorId" element={<DelegateFeedPage />} />` — correctly registered.

**E2E test file**: `frontend/e2e/delegates-newsfeed.spec.ts` exists.

### 2.5 Dev vs Prod behavior

`delegate_feed.py` uses `os.environ.get("APP_TABLE", "app_single_table")` which resolves to DDB Local in dev. The `newsfeed_fanout` import is conditional (`try/except` in `_fan_out`) so fanout failures don't crash draft approvals. `delegate_feed_enabled` setting (`settings.py:2100`) gates the feature; defaults to `True`. In dev and prod, the same code path runs.

---

## 3. Gap / Threat Analysis

### 3.1 GSI5 sort key missing on draft items (correctness gap)

`list_pending_drafts` queries `GSI5` with `GSI5PK=DRAFT_QUEUE#{creator_id}`. DynamoDB requires that items appear in a GSI only when the GSI partition key is present. The sort key (`GSI5SK`) is optional for the query but for the item to be indexed, `GSI5PK` must be set. The code does set `GSI5PK` — so items will appear in `GSI5`. The concern is that `GSI5SK` is declared `attr_type="S"` (for the social follow use case), but delegate draft items don't set `GSI5SK`. DynamoDB allows GSI items without the sort key, so they are still queryable. No runtime failure is expected, but the draft items will appear in an arbitrary internal order (not sorted by any delegate-meaningful key). The ticket intended a `created_at`-ordered draft queue.

**Fix**: In `create_post_as_creator`, when setting `GSI5PK`, also set `GSI5SK=str(created_at)` to get chronological ordering. This requires no schema change since `GSI5SK` is `"S"` type and `str(created_at)` is a string. Zero-padded ISO strings would sort correctly.

### 3.2 PostCard delegation metadata not rendered (UX gap)

`PostCard.tsx` does not render `posted_by_delegate` or `approval_status`. Viewers of a creator's feed see no indication that a post was written by a delegate. Creators cannot see pending-approval badges directly in their main feed. These are UX gaps, not security issues.

### 3.3 FeedPage draft queue badge missing (UX gap)

`FeedPage.tsx` has no badge or notification for pending delegate drafts. Creators must navigate to `/feed/delegate/:creatorId` to see the draft queue, with no proactive notification.

### 3.4 Authorization (SEC-005)

Post ownership is verified at `delegate_feed.py:226` (`edit_post_as_creator`) and `delegate_feed.py:312` (`delete_post_as_creator`) via `post.get("user_id") != creator_id → 403`. This prevents a delegate for creator A from editing creator B's posts even if both have `feed_post` permission. Comment moderation also verifies post ownership at `moderate_comment:509` ��� `post.get("user_id") != creator_id → 403`.

The `list_creator_posts` endpoint (`delegate_feed.py:330`) calls `require_delegate_permission` with `feed_read` but does not appear to filter posts to only the creator's content — it queries by creator ID, which is correct. A delegate for creator A cannot list creator B's posts (the `creator_id` in the URL is validated against the delegation record).

### 3.5 Approval workflow idempotency (SEC-005 variant)

`approve_draft` (`delegate_feed.py:388`) checks `approval_status == "pending"` before updating, raising 409 on double-approve. `reject_draft` does the same. No race condition exists because DynamoDB conditional expressions are used.

### 3.6 Allow-delegate-locking enforcement

`get_feed_delegation_settings` at `delegate_feed.py:59` returns `allow_delegate_locking` (default `False`). `create_post_as_creator` at `delegate_feed.py:131` enforces this:
```python
if lock_price_cents and not settings.get("allow_delegate_locking", False):
    raise HTTPException(403, "Delegate locking is not permitted")
```
This is correct.

### 3.7 Code sites needing changes

| File | What | Why |
|------|------|-----|
| `app/services/delegate_feed.py:147-155` | Add `GSI5SK=str(created_at)` when setting `GSI5PK` on draft items | Ordered draft queue |
| `frontend/src/pages/feed/PostCard.tsx` | Add `approval_status` badge and `delegate_tag` rendering | Creator/viewer UX |
| `frontend/src/pages/feed/FeedPage.tsx` | Add draft queue notification badge | Creator UX |

---

## 4. Proposed Design / Fix

### 4.1 GSI5 sort key fix (immediate)

In `create_post_as_creator`, in the block where `GSI5PK` is set (around line 155):

```python
# Ensure draft items appear in GSI5 with chronological order
"GSI5PK": f"DRAFT_QUEUE#{creator_id}",
"GSI5SK": str(created_at),  # ISO string, lexicographically ordered
```

In `approve_draft` and `reject_draft`, the existing `REMOVE GSI5PK, GSI5SK` expression (line 404) already removes both keys — no change needed there.

### 4.2 PostCard delegation metadata

Add to `PostCard.tsx`, after the existing post header (author + timestamp):
```tsx
{post.approval_status === "pending" && (
  <Badge variant="outline" className="text-yellow-600">Draft — Pending Approval</Badge>
)}
{post.posted_by_delegate && post.delegate_tag && (
  <span className="text-xs text-muted-foreground">{post.delegate_tag}</span>
)}
```

### 4.3 FeedPage draft queue badge

Query `GET /ui/newsfeed/delegate/{userId}/drafts` on `FeedPage` mount (creator perspective only). Show a badge: "N draft(s) awaiting approval" linking to `/feed/delegate/{userId}`.

### 4.4 Dev/Prod parity (SECOPS-007)

All storage uses `app_single_table` which is DDB Local in dev. `newsfeed_fanout` is called via `try/except` — fanout failures are silent in dev (no real follower subscriptions). No mock is needed. Feature flag `DELEGATE_FEED_ENABLED` defaults to `"1"` — same in dev and prod.

### 4.5 Scheduled + approval interaction

When `require_post_approval=True` and a delegate creates a scheduled post:
- `create_post_as_creator` sets `status=draft`, `approval_status=pending`, preserves `scheduled_at`.
- Creator approves → `approve_draft` sets `status=published` if `scheduled_at` is in the past, else `status=scheduled`.
- The existing `newsfeed_scheduler` will pick it up at `scheduled_at`.
This logic needs to be verified in `approve_draft` — currently it always sets `status=published`. Add:
```python
if scheduled_at and scheduled_at > now_ts():
    new_status = "scheduled"
else:
    new_status = "published"
```

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests (`tests/test_delegate_feed.py`)

| Case | Assertion |
|------|-----------|
| `test_create_post_direct_publish` | `status=published`, `posted_by_delegate=delegate_id`, `author_id=creator_id`, fanout triggered |
| `test_create_post_pending_approval` | `status=draft`, `approval_status=pending`, `GSI5PK=DRAFT_QUEUE#...` set |
| `test_approve_draft` | `status=published`, `approval_status=approved`, GSI5PK removed, fanout triggered |
| `test_reject_draft` | `approval_status=rejected`, GSI5PK removed |
| `test_approve_already_approved` | 409 |
| `test_edit_post_wrong_creator` | 403 (other creator's post) |
| `test_moderate_comment_requires_feed_moderate` | 403 with only `feed_post` |
| `test_locking_blocked_without_permission` | 403 when `allow_delegate_locking=False` and `lock_price_cents>0` |
| `test_list_pending_drafts_returns_gsi5_items` | Verify GSI5PK query returns draft posts |

### 5.2 Playwright E2E (`frontend/e2e/delegates-newsfeed.spec.ts`)

File exists. Covers sections 495-498 per ticket (16 tests). Tests that navigate to the PostCard delegate badges will fail until `PostCard.tsx` is updated.

### 5.3 Manual verification

1. `just restart`.
2. Alice enables `require_post_approval=True` in delegation settings.
3. Bob (delegate with `feed_post`) creates a post via `POST /ui/newsfeed/delegate/alice/posts`.
4. Alice queries `GET /ui/newsfeed/delegate/alice/drafts` — post appears.
5. Alice approves — post status transitions to `published`, appears in feed.
6. Bob with `feed_moderate` pins a comment on the post.
7. Check audit log shows all events.

### 5.4 Rollout

`DELEGATE_FEED_ENABLED` is already in `settings.py:2100`. Setting to `"0"` disables all `/ui/newsfeed/delegate/*` endpoints at the router level.

### 5.5 Effort estimate

- GSI5SK fix: **S** (30 min)
- PostCard delegation badge: **S** (0.5 day)
- FeedPage draft notification: **S** (0.5 day)
- Scheduled + approval interaction fix: **S** (1 hour)
- E2E run and fixes: **S** (0.5 day)
