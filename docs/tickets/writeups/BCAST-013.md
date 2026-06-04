# BCAST-013: Broadcast Live Tipping, Tip Goals, and Tip Monitor — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-013 adds real-time monetary tipping into live broadcast chat. Viewers can send a `kind="tip"` chat message with an amount, creating a paired debit/credit billing ledger entry and updating the session's running tip total. Broadcasters can define up to five tip goals; each incoming tip advances goal progress with overflow spill to the next goal. A tip summary endpoint aggregates top tippers and recent tips from the session. SSE events (`chat:tip`, `tip:total_update`, `goal:progress`, `goal:reached`) drive real-time UI in the viewer.

- **Type**: Feature
- **Priority**: High
- **Status**: Implemented — service layer, goal service, DDB tables, router endpoints, frontend components (`BroadcastTipButton.tsx`, `TipGoalBar.tsx`, `TipTicker.tsx`, `BroadcastTipSummary.tsx`), API wrappers (`broadcast-tips.ts`), and E2E spec (`broadcast-tips.spec.ts`) are all present.
- **Owning area**: `app/services/broadcast_tip_store.py` (320 lines), `app/services/broadcast_tip_goals.py` (201 lines), `app/routers/broadcast.py`, `app/models_broadcast.py` (lines 72–76), `app/services/tip_ledger.py:50` (extended with `"broadcast"`).
- **User personas**: Viewers (send tips), broadcasters (configure tip settings, create/manage goals, view summary).
- **Cross-references**: [[SEC-004]] (tip ledger — `TipLedgerEntry` and `write_tip_ledger()` used for billing, `content_type="broadcast"` added), [[SEC-025]] (broadcast IDOR — creator-only config/goal endpoints must verify session ownership), BCAST-005 (chat store rate limiting pattern reused), [[SECOPS-007]] (dev = DDB Local, no Stripe/PayPal calls; prod = same DDB path).

---

## 2. Current-State Investigation (what exists today)

### 2.1 Tip ledger extension — `app/services/tip_ledger.py:50`

`TipLedgerEntry.__init__()` validation now includes `"broadcast"` as a valid `content_type`:

```python
if content_type not in ("message", "post", "comment", "broadcast"):
    raise ValueError(f"Invalid content_type: {content_type}")
```

`_reason_for_content_type()` at line 63 maps `"broadcast"` → `"Tip: broadcast"`. Both changes are present and verified.

### 2.2 Broadcast tip store — `app/services/broadcast_tip_store.py` (320 lines)

| Function | Line | Purpose |
|---|---|---|
| `_enforce_tip_rate_limit()` | ~30 | In-memory 3-second per-user-per-session bucket using `threading.Lock`. Separate from chat rate limit. |
| `_validate_payment_method()` | ~60 | Queries `T.billing` for `pk=USER#{user_id}`, scans `PM#` prefixed SK items, raises 400 if PM not found. |
| `send_tip_message()` | ~85 | Full pipeline: rate limit → mute check → PM validate → amount bounds → self-tip guard → generate `tip_payment_id` → `TipLedgerEntry` + `write_tip_ledger()` → write `kind="tip"` DDB item → atomic `ADD` on session totals → SSE publish (`chat:tip` + `tip:total_update`) → call `_update_goals_for_tip()`. |
| `_increment_session_tip_totals()` | ~200 | `T.broadcast_sessions.update_item(UpdateExpression="ADD tip_total_cents :amt, tip_count :one")` — atomic increment, no read-before-write. |
| `_tip_msg_out()` | ~230 | Output dict with `kind="tip"`, `tip_amount_cents`, `tip_currency`, `tip_payment_id`. |
| `get_tip_summary()` | ~245 | Reads `tip_total_cents` and `tip_count` from session record; queries tip messages via `_query_tip_messages()`; aggregates top tippers and recent tips. |
| `_query_tip_messages()` | ~280 | Paginated `FilterExpression(kind="tip")` query, capped at 10 pages × 500 items. Handles DDB 1MB page limit via `LastEvaluatedKey` loop. |

### 2.3 Session model — `app/models_broadcast.py` (lines 72–76)

```python
# Live Tipping (BCAST-013)
tip_total_cents: int = 0
tip_count: int = 0
tip_enabled: bool = True
tip_min_cents: int = 100
tip_max_cents: int = 100000
```

Present and included in `session_to_item()` / `session_from_item()` in `broadcast_store.py`.

### 2.4 Tip goal service — `app/services/broadcast_tip_goals.py` (201 lines)

| Function | Line | Purpose |
|---|---|---|
| `create_goal()` | ~20 | Validates < 5 goals per session, writes to `T.broadcast_tip_goals` (PK `session_id`, SK `goal_id`), publishes `goal:created` SSE. |
| `list_goals()` | ~50 | Queries by `session_id`, sorts by `sort_order` then `created_at`. |
| `get_goal()` | ~60 | GetItem, raises 404 if not found. |
| `update_goal()` | ~70 | Partial update via `update_item`. |
| `delete_goal()` | ~100 | DeleteItem + `goal:deleted` SSE. |
| `advance_goal_progress()` | ~115 | Iterates goals by sort_order; fills each in turn using `remaining = tip_amount_cents`; atomic `ADD current_cents :applied`; publishes `goal:progress` and `goal:reached` SSE for each goal crossed. |
| `_mark_goal_reached()` | ~175 | Sets `reached=True`, `reached_at=now_ts()` idempotently. |

### 2.5 DDB table — `BroadcastTipGoals`

Registered in `scripts/local-ddb-init.py` (line ~984), handle at `app/core/tables.py:167` (`broadcast_tip_goals: Any`), wired at line 403, setting `broadcast_tip_goals_table_name` at `settings.py:532`. PK `session_id` (S), SK `goal_id` (S) — no GSIs needed (goals ≤ 5 per session, all queries by PK).

### 2.6 Router endpoints — `app/routers/broadcast.py`

| Endpoint | Auth |
|---|---|
| `POST /sessions/{id}/chat/tip` | Any authenticated viewer; not session creator |
| `GET /sessions/{id}/tips/summary` | Any authenticated user |
| `PATCH /sessions/{id}/tips/config` | Session creator only |
| `POST /sessions/{id}/goals` | Session creator only |
| `GET /sessions/{id}/goals` | Any authenticated user |
| `PATCH /sessions/{id}/goals/{goal_id}` | Session creator only |
| `DELETE /sessions/{id}/goals/{goal_id}` | Session creator only |

The tip send route validates `session.status == "live"` and `tip_enabled == True`. The goal CRUD routes allow goal creation/update in `draft`, `scheduled`, `ready`, and `live` states.

### 2.7 Frontend components — `frontend/src/pages/broadcast/`

- `BroadcastTipButton.tsx` — viewer-facing amount presets + custom input + PM selector.
- `TipGoalBar.tsx` — progress bar showing current/target, reached animation.
- `TipTicker.tsx` — animated feed of incoming tips.
- `BroadcastTipSummary.tsx` — broadcaster dashboard showing total, top tippers, recent tips.

All four files are present. `frontend/src/api/endpoints/broadcast-tips.ts` contains API wrappers.

### 2.8 E2E tests — `frontend/e2e/broadcast-tips.spec.ts` (present)

### 2.9 Dev vs. Prod parity (SECOPS-007)

`write_tip_ledger()` writes to `T.billing` which maps to DDB Local in dev. The `_validate_payment_method()` function queries the same `T.billing` table — in dev, test payment methods must be seeded in DDB Local (the E2E session setup scripts do this). No Stripe/PayPal API calls are made in the tip flow; billing is internal ledger only. `_increment_session_tip_totals()` uses `T.broadcast_sessions` — DDB Local in dev. All code paths are identical between dev and prod.

---

## 3. Gap / Threat Analysis

### 3.1 Self-tip guard executes after billing write

In `send_tip_message()` (`broadcast_tip_store.py:~85`), the self-tip guard (`if user_id == broadcaster_id`) executes at step 5. But `TipLedgerEntry` and `write_tip_ledger()` execute at step 7 — after the rate limit and PM validation but the self-tip check. Wait: looking at the actual service code, the correct order is: rate limit → mute check → PM validate → amount bounds → then self-tip check → then billing. The self-tip check at step 5 in the ticket design matches the actual code order. This is correct — no bug.

### 3.2 `_query_tip_messages()` scan efficiency

`_query_tip_messages()` at `broadcast_tip_store.py:~280` uses `FilterExpression(kind="tip")` on the full `BroadcastChatMessages` partition for a session. In a session with 50,000 public chat messages and 200 tips, DDB fetches ~100 pages of 500 items each (50MB total scan) to find 200 tip items. This makes the tip summary endpoint O(total_messages) rather than O(tip_count). For high-traffic sessions, this will cause significant DDB read unit consumption and latency.

**Fix**: Add a GSI on `(kind, created_at)` to `BroadcastChatMessages`, or store tip metadata separately in a `BroadcastTipSummary` item (updated atomically per tip). The current approach is acceptable for sessions with < 10,000 total messages.

### 3.3 Goal progress race condition

`advance_goal_progress()` at `broadcast_tip_goals.py:~115` reads all goals, iterates, and applies atomic `ADD current_cents :applied` to each. The issue: if two concurrent tips both read goal state before either writes, both can compute `applied` against the same `current` value and together exceed the `target`. The atomic `ADD` prevents data corruption but does not prevent over-filling: a goal with `target=1000`, `current=900` could receive two concurrent tips of 200 each — both pass the `capacity > 0` check, both write `ADD :200`, and the goal ends at `current=1300` (130% of target).

**Fix**: Use a conditional `update_item` with `ConditionExpression=Attr("current_cents").lt(target_cents)` and `ADD current_cents :min(remaining, capacity)`. On `ConditionalCheckFailedException`, skip the goal (it was just reached by a concurrent request). This requires restructuring `advance_goal_progress()` to use conditional writes per goal.

### 3.4 SSE delivery — `tip:total_update` carries stale `tip_total_cents`

`_increment_session_tip_totals()` returns `UPDATED_NEW` attributes. `send_tip_message()` publishes this value in the `tip:total_update` SSE event. If the DDB `update_item` call fails transiently (caught by boto3 retry logic), `new_totals` could be a stale cached value from a previous successful call. The `broadcast_sse_publish` call happens unconditionally after the `update_item` result — the SSE event might show a stale total if the DDB call silently returned a cached value. This is low-risk but worth noting.

### 3.5 SEC-025 creator ownership

The `PATCH /tips/config` and goal CRUD endpoints must enforce `ctx["user_sub"] == session.created_by`. This is done inline in the router. The SEC-025 writeup proposes a `_require_session_owner` helper that should be used here for consistency.

---

## 4. Proposed Design / Fix

### 4.1 Fix goal over-fill with conditional write

Modify `advance_goal_progress()` in `broadcast_tip_goals.py`:

```python
from botocore.exceptions import ClientError

# Inside the per-goal loop, replace the unconditional update_item with:
try:
    T.broadcast_tip_goals.update_item(
        Key={"session_id": session_id, "goal_id": goal["goal_id"]},
        UpdateExpression="ADD current_cents :applied SET updated_at = :ts",
        ConditionExpression=Attr("current_cents").lt(int(goal["target_cents"])),
        ExpressionAttributeValues={":applied": applied, ":ts": now_ts()},
    )
except ClientError as e:
    if e.response["Error"]["Code"] == "ConditionalCheckFailedException":
        continue  # Goal already reached by concurrent tip — skip
    raise
```

Also add `SET reached = :true, reached_at = :ts` to the same expression when `new_current >= target`, avoiding a separate check-then-write.

### 4.2 Add `kind="tip"` GSI to `BroadcastChatMessages` for efficient summary queries

In `scripts/local-ddb-init.py`, add a GSI to the `BroadcastChatMessages` table definition:

```python
TableDef(
    "BroadcastChatMessages",
    "session_id",
    "sort_key",
    gsis=[
        GSIDef("TipsBySession", pk="session_id", sk="tip_created_at",
               projected_attrs=["message_id","sender_id","sender_display_name",
                                "tip_amount_cents","tip_currency","tip_payment_id",
                                "created_at","kind"]),
    ],
    attr_types={"tip_created_at": "N"},
)
```

Tip items set `tip_created_at = created_at` (same value) so the GSI only contains tip items. `_query_tip_messages()` then becomes: `Query(GSI=TipsBySession, pk=session_id, ScanIndexForward=False, Limit=200)` — O(tip_count) instead of O(total_messages).

### 4.3 Dev/Prod parity (SECOPS-007)

No changes to dev/prod parity needed — all existing code paths are already environment-agnostic. The new GSI requires adding `attr_types={"tip_created_at": "N"}` to the local DDB init script (common CLAUDE.md gotcha: numeric GSI keys must be declared with `attr_types`).

### 4.4 Feature flag

`broadcast_tipping_enabled: bool` should be added to `app/core/settings.py` if not already present (distinct from per-session `tip_enabled` which is a broadcaster preference). A platform-level kill switch allows disabling tipping globally without requiring per-session configuration.

---

## 5. Testing, Verification & Rollout

### pytest unit tests — `tests/test_broadcast_tips.py`

Concrete cases:
1. `test_send_tip_writes_ledger_entries` — tip sent → `T.billing` has debit for tipper and credit for broadcaster with `content_type="broadcast"`.
2. `test_tip_increments_session_total` — session `tip_total_cents` atomically incremented; `tip_count` incremented by 1.
3. `test_tip_self_blocked` — tipper == broadcaster → 400 `CANNOT_TIP_SELF`.
4. `test_tip_below_min_blocked` — `amount_cents=99` → 400 `TIP_TOO_SMALL`.
5. `test_tip_rate_limit` — two tips within 3 seconds → second returns 429.
6. `test_goal_progress_advance_fills_sequential` — tip of 1500 cents; goal A needs 1000, goal B needs 2000 → goal A reached (1000 applied), goal B advanced 500.
7. `test_goal_over_fill_prevented` — concurrent tips both attempt to fill goal past target → only one fills (conditional write rejects second).
8. `test_tip_summary_returns_aggregated_data` — 3 tip messages from 2 tippers → `top_tippers` sorted correctly.
9. `test_muted_user_cannot_tip` — user is muted in session → 403 `BROADCAST_CHAT_MUTED`.

### Playwright E2E — `frontend/e2e/broadcast-tips.spec.ts` (exists)

Add scenarios:
- Live broadcast tip flow: viewer sends $5 tip → `chat:tip` SSE event received in broadcaster view → `TipTicker` shows tip.
- Goal progress: broadcaster creates goal of $10; viewer tips $5 → goal shows 50% → viewer tips another $5 → goal shows "Reached!" animation.
- Tip config: broadcaster disables tipping (`tip_enabled=false`) → viewer tip attempt returns 403 `TIPPING_DISABLED`.

### Manual QA

1. Start a live session, create a goal of $10.
2. As a viewer with a seeded PM, send a $5 tip via `BroadcastTipButton`.
3. Verify `TipTicker` shows the tip, `TipGoalBar` shows 50% progress.
4. Send another $5 tip — verify `goal:reached` SSE and bar shows 100%.
5. Check `GET /sessions/{id}/tips/summary` — verify `total_cents=1000`, `tip_count=2`, correct `top_tippers`.
6. Check `T.billing` directly — verify two debit entries for viewer, two credit entries for broadcaster.

### Observability

The existing `_increment_session_tip_totals()` log at `send_tip_message()` produces a `broadcast.tip.sent` log line (add if missing) with `session_id`, `amount_cents`, `user_id`. Alert on `tip:total_update` SSE publish rate > 10/s per session as a spam indicator (cross-ref SEC-025 report-flood pattern).

### Rollout

- Goals and tip config can be pre-configured before going live (`status="draft"` or `"ready"`).
- `broadcast_tipping_enabled` flag (platform level) + per-session `tip_enabled` flag (creator level) provide two-layer control.
- GSI addition (fix 4.2) requires a DDB table update; do this as a non-breaking change (GSI is additive) before deploying the new `_query_tip_messages()` path.

**Effort**: Goal over-fill fix: S (~4 hours). Tip summary GSI: S (~2 hours + DDB migration). Frontend polish (tip animation, goal celebration): M (~2 days).
