# BCAST-004: Real-Time Viewer Count and Stream Health Metrics — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-004 specified real-time viewer count tracking (DynamoDB TTL-based, SSE fan-out), stream health metrics (ingest bitrate, dropped frames, quality classification), and frontend components (`ViewerCountBadge`, `StreamHealthIndicator`, `useBroadcastStream` hook). The ticket was written when none of this infrastructure existed. The full implementation — backend services, endpoints, DDB tables, and frontend components — is now present.

- **Type**: Feature (observability and social-proof infrastructure)
- **Priority**: High (broadcaster and viewer engagement)
- **Status**: Implemented — all service files, endpoints, DDB tables, and frontend components exist
- **User persona**: Broadcaster (stream health panel, detailed metrics), Viewer (viewer count badge on player page), Platform (TTL-based cleanup)
- **Cross-referenced tickets**: BCAST-001 (broadcaster dashboard embeds health panel), BCAST-002 (viewer player uses viewer join/heartbeat + viewer count badge), BCAST-003 (prod mode: CloudWatch metrics replace client-reported health), BCAST-005 (viewer count context for chat rate decisions), SEC-010 (SSE event stream at `/broadcast/sessions/{id}/stream` lacks viewer access check — the health/viewer-count SSE is the same endpoint)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Viewer tracking service

`app/services/broadcast_viewers.py` — full implementation:
- `register_viewer(session_id, user_sub)` → writes to `T.broadcast_viewers` with `expires_at = now + VIEWER_TTL_SECONDS`, publishes `viewer_count` SSE event via `broadcast_sse_publish`
- `touch_viewer(session_id, viewer_id)` → conditional `update_item` extending `expires_at`
- `unregister_viewer(session_id, viewer_id)` → `delete_item` + SSE publish with `delta=-1`
- `get_viewer_count(session_id)` → `query(Select="COUNT")` on `T.broadcast_viewers` PK

### 2.2 Health service

`app/services/broadcast_health.py` — full implementation:
- `classify_connection_quality(dropped_frames_pct, ingest_bitrate_kbps, input_loss_seconds)` → returns one of `excellent|good|fair|poor|critical`
- `store_health_snapshot(session_id, *, ingest_bitrate_kbps, ...)` → puts item to `T.broadcast_health_snapshots`, calls `broadcast_sse_publish` with `_type: "health_update"`
- `get_latest_health(session_id)` → `query(ScanIndexForward=False, Limit=1)` returns most recent snapshot
- `get_health_history(session_id, from_ts, to_ts, limit)` → range query on `snapshot_ts` SK

### 2.3 SSE pub/sub service

`app/services/broadcast_sse.py`:
- `_BROADCAST_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]]` — in-memory session-scoped queues
- `broadcast_sse_subscribe(session_id)` → creates `asyncio.Queue(maxsize=100)`, adds to set
- `broadcast_sse_unsubscribe(session_id, q)` → removes queue; cleans up empty sets
- `broadcast_sse_publish(session_id, event)` → `q.put_nowait(event)` for all subscribers; drops full queues (dead slow consumers)

This follows the alerts SSE pattern from `app/services/alerts.py` exactly.

### 2.4 Backend endpoints (broadcast.py)

**Viewer count endpoints** (`broadcast.py:549–625`):

| Method | Path | Line | Auth | Notes |
|--------|------|------|------|-------|
| POST | `/sessions/{id}/viewers/join` | 568 | `require_ui_session` | Geo-check + privacy gate for non-owners |
| POST | `/sessions/{id}/viewers/heartbeat` | 596 | `require_ui_session` | `_ = ctx` — no ownership check on viewer_id |
| POST | `/sessions/{id}/viewers/leave` | 608 | `require_ui_session` | `_ = ctx` — no ownership check on viewer_id |
| GET | `/sessions/{id}/viewers/count` | 620 | `require_ui_session` | No access scoping |

**Health endpoints** (`broadcast.py:628–737`):

| Method | Path | Line | Auth | Notes |
|--------|------|------|------|-------|
| POST | `/sessions/{id}/health/report` | 658 | `require_ui_session` | `_ = ctx` — no ownership check |
| GET | `/sessions/{id}/health` | 684 | `require_ui_session` | `_ = ctx` — no access scoping |
| GET | `/sessions/{id}/health/history` | 697 | `require_ui_session` | `_ = ctx` — no access scoping |
| GET | `/sessions/{id}/stream` | 717 | `require_ui_session` | SSE; no viewer access gate |

### 2.5 DynamoDB tables

`scripts/local-ddb-init.py:715–720` and `app/core/settings.py:511–512`:

**`BroadcastViewers`** (PK `session_id`, SK `viewer_id`, numeric `expires_at` TTL):
```python
TableDef(_resolve_table_name(S.broadcast_viewers_table_name, "BroadcastViewers"), "session_id", "viewer_id", attr_types={"joined_at": "N", "expires_at": "N"})
```
Table handle at `app/core/tables.py:151`.

**`BroadcastHealthSnapshots`** (PK `session_id`, SK `snapshot_ts` numeric):
```python
TableDef(_resolve_table_name(S.broadcast_health_snapshots_table_name, "BroadcastHealthSnapshots"), "session_id", "snapshot_ts", attr_types={"snapshot_ts": "N"})
```
Table handle at `app/core/tables.py:152`.

### 2.6 Frontend components

- `frontend/src/pages/broadcast/ViewerCountBadge.tsx` — renders `<Users>` icon + count with `"viewer"/"viewers"` pluralisation
- `frontend/src/pages/broadcast/StreamHealthIndicator.tsx` — color-coded quality indicator with tooltip showing bitrate and drop percentage
- `frontend/src/hooks/useBroadcastStream.ts` — `EventSource` hook connected to `/broadcast/sessions/{id}/stream`; listens for `viewer_count`, `health_update`, `session_status`, `ad:break` events; exponential backoff reconnect
- `LivePlayer.tsx:60`: `const { adBreak, clearAdBreak } = useBroadcastStream(...)` — the hook is already wired into the player

E2E test suite: `frontend/e2e/broadcast-health.spec.ts` (747 lines), sections 90–93 covering viewer join/leave, count polling, health metrics API, and SSE stream.

### 2.7 Dev vs Prod behavior (SECOPS-007)

**Dev (`BROADCAST_PROVIDER=local`)**: Health metrics are client-reported via `POST /sessions/{id}/health/report`. The broadcaster client (OBS stats, browser ingest UI) POSTs metrics; no CloudWatch polling. DynamoDB Local (port 8001) stores viewer records and health snapshots. SSE pub/sub is in-memory (single-process; compatible with `--workers 1` requirement). DDB TTL-based viewer expiry works on DynamoDB Local (TTL daemon runs). All offline.

**Prod (`BROADCAST_PROVIDER=aws`)**: A CloudWatch poll background task (described in the ticket as `broadcast_health_collector.py`) reads `AWS/MediaLive` metrics (`NetworkIn`, `DroppedFrames`, `InputVideoFrameRate`) every `S.broadcast_health_poll_interval_seconds` (default 10s) and calls `store_health_snapshot` directly, bypassing the HTTP report endpoint. The same `store_health_snapshot` function is used in both modes. The `POST /health/report` endpoint also remains active in prod for supplemental OBS-reported metrics.

Note: `broadcast_health_collector.py` is described in the ticket but does **not exist** yet as a separate file. The poll logic is intended as a background task similar to `broadcast_reconciler.py`. This is the primary remaining gap.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-010 — SSE event stream has no viewer access check

`broadcast_event_stream_route` at `broadcast.py:717–737` calls `get_session(session_id)` (existence check) then immediately subscribes to the SSE queue. `ctx` is set to `_ = ctx` (ignored). There is no call to `check_viewer_access` from `app/services/broadcast_privacy.py`. For private sessions (`broadcast_privacy_visibility = "private"`) or subscriber-gated sessions, any authenticated user can receive real-time viewer count deltas, health updates, and ad-break signals by subscribing to the stream — a direct information-disclosure IDOR. See SEC-010 write-up for full analysis.

### 3.2 Heartbeat IDOR — `viewer_id` is caller-controlled

`viewer_heartbeat_route` at `broadcast.py:596–605`:
```python
def viewer_heartbeat_route(session_id: str, viewer_id: str = Query(...), ctx: dict = Depends(_ctx)):
    _ = ctx
    count = touch_viewer(session_id, viewer_id)
    return ViewerHeartbeatOut(ok=True, viewer_count=count)
```

`ctx` is ignored — `viewer_id` is accepted directly from the query parameter without verifying it was minted for `ctx["user_sub"]`. User Alice can heartbeat on Bob's `viewer_id` (extending Bob's TTL or confirming Bob's presence). Similarly, `viewer_leave_route` at line 608 ignores `ctx`, allowing any user to evict any other viewer.

`viewer_id` is constructed in `broadcast_viewers.py` as `f"{user_sub}#{connection_id}"` where `connection_id` is a 12-character hex UUID. If the format is validated on heartbeat, Alice cannot guess Bob's `viewer_id`. However there is no format validation — the endpoint accepts any string for `viewer_id`.

### 3.3 Health report endpoint — no broadcaster ownership check

`report_session_health_route` at `broadcast.py:658–681`:
```python
def report_session_health_route(session_id: str, body: BroadcastHealthReportIn, ctx: dict = Depends(_ctx)):
    _ = ctx
    session = get_session(session_id)
    if session.status != "live":
        raise HTTPException(...)
    result = store_health_snapshot(session_id, ...)
```

Any authenticated user can POST fabricated health metrics to any live session. This poisons the health history and will trigger misleading SSE `health_update` events to the broadcaster's dashboard. The broadcaster cannot distinguish real OBS-reported metrics from attacker-injected values.

### 3.4 Missing CloudWatch health collector for prod

`broadcast_health_collector.py` (the CloudWatch polling background task) does not exist. In prod mode (`BROADCAST_PROVIDER=aws`), health metrics can only be reported via the client-side `POST /health/report` endpoint (same as dev). The broadcaster's OBS must be configured to POST stats — this is not automatic. CloudWatch-based collection was the intended prod source.

### 3.5 SSE in-memory pub/sub and multi-worker restriction

`_BROADCAST_SUBSCRIBERS` is a module-level dict. The existing CLAUDE.md note ("Run uvicorn with `--workers 1` in dev mode") applies here: if uvicorn ever runs multiple workers in prod, SSE subscribers on worker A will not receive events published from worker B (where the viewer join/health report occurred). This is not a bug in the current single-worker dev stack but is a prod-readiness concern.

---

## 4. Proposed Design / Fix

### 4.1 SEC-010 fix — viewer access check on SSE stream

In `app/routers/broadcast.py:717`, add before subscribing:
```python
from app.services.broadcast_privacy import check_viewer_access
check_viewer_access(session_id, ctx["user_sub"],
                    creator_id=session.created_by,
                    visibility=session.broadcast_privacy_visibility,
                    invite_token=invite_token)
```
Add `invite_token: Optional[str] = Query(default=None)` to the endpoint signature. Full fix in SEC-010 write-up.

### 4.2 Heartbeat/leave IDOR fix

Validate that the `viewer_id` in the heartbeat/leave request belongs to the calling user. Since `viewer_id` is constructed as `{user_sub}#{connection_id}`, validate the prefix:

```python
def viewer_heartbeat_route(session_id: str, viewer_id: str = Query(...), ctx: dict = Depends(_ctx)):
    expected_prefix = ctx["user_sub"] + "#"
    if not viewer_id.startswith(expected_prefix):
        raise HTTPException(status_code=403, detail={"code": "VIEWER_ID_MISMATCH", "detail": "viewer_id does not belong to the calling user"})
    count = touch_viewer(session_id, viewer_id)
    return ViewerHeartbeatOut(ok=True, viewer_count=count)
```

Same fix for `viewer_leave_route`.

### 4.3 Health report ownership check

```python
def report_session_health_route(session_id: str, body: BroadcastHealthReportIn, ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    if ctx["user_sub"] != session.created_by and ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(status_code=403, detail={"code": "BROADCAST_HEALTH_FORBIDDEN", "detail": "Only the broadcaster or admin may report health metrics"})
    if session.status != "live":
        raise HTTPException(...)
    ...
```

### 4.4 CloudWatch health collector (prod)

Create `app/services/broadcast_health_collector.py` — a background `asyncio` task started on FastAPI startup (follow `broadcast_reconciler.py` pattern):

```python
async def _health_collector_loop():
    while True:
        if S.broadcast_provider != "aws":
            await asyncio.sleep(S.broadcast_health_poll_interval_seconds)
            continue
        for session in list_live_sessions():
            channel_id = _resolve_channel_id_from_db(session)
            if not channel_id:
                continue
            metrics = _poll_cloudwatch_metrics(session.id, channel_id)
            if metrics:
                store_health_snapshot(session.id, **metrics)
        await asyncio.sleep(S.broadcast_health_poll_interval_seconds)
```

Dev mode: the loop is a no-op (the `if S.broadcast_provider != "aws"` guard skips the AWS call). Client-reported health via `POST /health/report` continues to work in dev. Same `store_health_snapshot` function — SECOPS-007 parity maintained.

Register in `app/main.py` alongside other startup tasks:
```python
from app.services.broadcast_health_collector import start_broadcast_health_collector_task
app.add_event_handler("startup", start_broadcast_health_collector_task)
```

### 4.5 Multi-worker SSE readiness

For future multi-worker prod deployments, replace `_BROADCAST_SUBSCRIBERS` in-memory queue with Redis pub/sub or DynamoDB Streams. Until then, document the `--workers 1` requirement explicitly in `scripts/run_local_mock_backend.sh` comments and in the CLAUDE.md "Common gotchas" section.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests

**Files**: `tests/test_broadcast_viewers.py`, `tests/test_broadcast_health.py`

| Test | Description |
|------|-------------|
| `test_viewer_join_increments_count` | `register_viewer`; `get_viewer_count` returns 1 |
| `test_viewer_leave_decrements_count` | Join then unregister; count returns to 0 |
| `test_heartbeat_extends_ttl` | `touch_viewer`; `expires_at` updated; count unchanged |
| `test_heartbeat_idor_rejected` | After fix: heartbeat with wrong user_sub prefix → 403 |
| `test_health_report_non_owner_rejected` | After fix: non-owner health report → 403 |
| `test_store_health_snapshot_persisted` | `store_health_snapshot`; `get_latest_health` returns snapshot |
| `test_health_history_sorted_desc` | Seed 5 snapshots; history returns newest first |
| `test_quality_thresholds` | `classify_connection_quality` → `excellent/good/fair/poor/critical` per bitrate/drop values |
| `test_sse_publish_delivers_to_subscriber` | `subscribe`; `publish`; `await q.get()` returns event |
| `test_sse_full_queue_drops_silently` | maxsize=1 queue; second publish doesn't raise |

### 5.2 Playwright E2E tests

Existing `frontend/e2e/broadcast-health.spec.ts` (sections 90–93) already covers viewer join/leave (section 90), count polling (section 91), health metrics API (section 92), SSE stream (section 93). Add to section 90:

- `90.5` Heartbeat with wrong `viewer_id` prefix → 403 `VIEWER_ID_MISMATCH` (post-fix)
- `90.6` Leave with wrong `viewer_id` prefix → 403 (post-fix)

Add to section 92:
- `92.5` Non-owner health report → 403 `BROADCAST_HEALTH_FORBIDDEN` (post-fix)
- `92.6` Admin can report health for any session → 200 (post-fix)

Add new section 94 (SSE access control):
- `94.1` SSE subscribe to private session as non-viewer → 403 (post-fix)
- `94.2` SSE subscribe to public session → `event: hello` received

### 5.3 Manual QA

1. `just restart`; Root creates + starts a session
2. Alice (`injectAuth`) joins as viewer; verify `GET /viewers/count` returns 1; wait 90s (or mock TTL); verify count returns to 0
3. Root POSTs health metrics; verify `GET /health` returns matching snapshot; StreamHealthIndicator in BroadcastPage shows correct colour
4. Alice attempts to POST health metrics on Root's session → verify 403

### 5.4 Observability

`app/metrics.py` additions:
- `broadcast_viewer_joins_total` / `broadcast_viewer_leaves_total` — counters for join/leave events
- `broadcast_viewer_count_gauge` — current viewer count per session (exported as gauge)
- `broadcast_health_reports_total` — counter for health report POSTs (labels: `source`: `client`/`cloudwatch`)

Alarm: viewer count metric drops > 80% within 5 minutes for a session in `live` status → potential stream failure.

### 5.5 Rollout

All three auth fixes (4.1, 4.2, 4.3) are pure code changes, no schema changes. Deploy atomically. The CloudWatch collector (4.4) is a new startup task; in dev mode it is a no-op (SECOPS-007 compliant). Risk for 4.1: existing SSE clients for non-private sessions will continue to work — `check_viewer_access` is a no-op when `visibility=None`. Private session enforcement is new and intentional.

### 5.6 Effort estimate

- SEC-010 SSE fix: **S** (1 hour, shares implementation with BCAST-002 fix)
- Heartbeat/leave IDOR fix: **S** (1 hour + unit tests)
- Health report ownership check: **XS** (30 minutes)
- CloudWatch health collector: **M** (3–4 hours: CloudWatch SDK calls + background task + unit test with moto CloudWatch mock)
- Multi-worker documentation: **XS** (15 minutes)

### 5.7 Open questions

1. **Viewer count accuracy vs. DynamoDB TTL lag**: DynamoDB TTL deletes are not instantaneous — the documentation states TTL items may persist up to 48 hours after the `expires_at` epoch. In practice the TTL daemon on DynamoDB Local and on AWS typically removes items within a few minutes, but during high-load periods stale viewer records will inflate the `SELECT COUNT` query result. A stronger consistency guarantee is to use an atomic counter in a separate row (`viewer_count#{session_id}` → count value) updated on every join/leave, accepting the risk of count going negative if a leave fires without a corresponding join. The current TTL approach is simpler and acceptable for a social-proof counter.

2. **`broadcast_health_poll_interval_seconds` setting description**: `app/core/settings.py:512` defines `broadcast_health_poll_interval_seconds` (default 10). The BCAST-004 ticket does not document whether this governs (a) the CloudWatch polling interval for the health collector background task, or (b) the recommended client poll interval for the `GET /health` REST fallback. Clarify in the settings docstring; both use cases should reference the same value.

3. **Viewer join geo-check performance**: `viewer_join_route` at `broadcast.py:578–592` reads the raw DDB item a second time (`_T.broadcast_sessions.get_item(...)`) to extract `geo_mode` and `geo_countries` for the geo-check, even though the session was already loaded via `get_session(session_id)` at line 577. The `BroadcastSessionModel` should expose these fields so the second DDB read can be avoided; this is a minor performance issue that becomes significant at high join rates.

4. **Health history query pagination**: `get_health_history` in `broadcast_health.py` issues a single DDB query with `Limit=limit` (max 360 per request at `broadcast.py:702`). If the session has accumulated thousands of snapshots (10-second intervals over hours), a 60-snapshot window covers only 10 minutes. Long time-range chart requests must paginate via `LastEvaluatedKey`; the current `get_health_history` implementation does not expose a cursor, leaving historical data inaccessible beyond the first page.
