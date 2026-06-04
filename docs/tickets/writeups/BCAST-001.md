# BCAST-001: Broadcaster Dashboard Page (Create/Manage Sessions) — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-001 called for a dedicated broadcaster UI covering the full session lifecycle: creating encoding profiles, creating and launching sessions, monitoring status transitions, copying RTMP ingest credentials, minting playback URLs, and viewing the admin audit log. The ticket was written at a time when the broadcast backend was fully operational but described the frontend as entirely absent — "zero frontend code referencing broadcast endpoints." That gap has since been filled completely.

- **Type**: Feature (frontend implementation + backend list endpoint)
- **Priority**: High (broadcaster-facing core workflow; no other management surface existed)
- **Status**: Implemented — both the frontend and all backend endpoints are present; the ticket's gap analysis is outdated throughout
- **User persona**: Broadcaster (creator role; create profile/session, view status, copy RTMP URL), Admin/Root (start/stop/delete operations requiring `_require_operator_role`), Viewer (indirectly, via sessions created on this page)
- **Cross-referenced tickets**: BCAST-002 (viewer player consumes sessions and playback URLs created here), BCAST-004 (viewer count badge and stream health panel embedded in this same page's session detail dialog), BCAST-007 (sidebar navigation links to `/broadcast`), BCAST-009 (session scheduling uses the same CRUD endpoints), SEC-025 (broadcast session IDOR — the `start`/`stop`/`delete` endpoints used by this page's action buttons check operator role but not session ownership)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Backend endpoints

All endpoints are registered via `app/main.py:550` (`app.include_router(broadcast_router)`) under the prefix registered in `broadcast_router`. The full surface exposed under `/broadcast/*`:

| Method | Path | Auth | Line |
|--------|------|------|------|
| POST | `/broadcast/profiles` | `require_ui_session` | `broadcast.py:262` |
| GET | `/broadcast/profiles` | `require_ui_session` | `broadcast.py:352` |
| POST | `/broadcast/sessions` | `require_ui_session` | `broadcast.py:286` |
| GET | `/broadcast/sessions` | `require_ui_session` | `broadcast.py:310` |
| GET | `/broadcast/sessions/scheduled` | `require_ui_session` | `broadcast.py:324` |
| GET | `/broadcast/sessions/{id}` | `require_ui_session` | `broadcast.py:480` |
| POST | `/broadcast/sessions/{id}/start` | `_require_operator_role` | `broadcast.py:360` |
| POST | `/broadcast/sessions/{id}/stop` | `_require_operator_role` | `broadcast.py:402` |
| DELETE | `/broadcast/sessions/{id}` | `_require_operator_role` | `broadcast.py:453` |
| POST | `/broadcast/sessions/{id}/playback-url` | `require_ui_session` | `broadcast.py:492` |
| GET | `/broadcast/admin/audit` | `_require_operator_role` | `broadcast.py:531` |
| GET | `/broadcast/playback/verify` | `require_ui_session` | `broadcast.py:521` |

`_require_operator_role` at `broadcast.py:231–236`:
```python
def _require_operator_role(ctx: dict) -> None:
    if ctx.get("role") not in {"admin", "root"}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail={"code": "BROADCAST_ROLE_FORBIDDEN", "detail": "admin or root role required"},
        )
```

This checks `role` against `{"admin", "root"}` only — it does **not** verify that the caller owns the session. Any admin or root user can start, stop, or delete any other broadcaster's session. This is the SEC-025 IDOR.

`list_sessions_route` at `broadcast.py:310–322`:
```python
@router.get("/sessions", response_model=BroadcastSessionListOut)
def list_sessions_route(status: Optional[str] = Query(default=None),
                        limit: int = Query(default=50, ge=1, le=200),
                        ctx: dict = Depends(_ctx)):
    if status:
        result = list_sessions_by_status(status, limit=limit)
    else:
        result = list_sessions_by_creator(ctx["user_sub"], limit=limit)
    items = [_to_session_out(s) for s in result["items"]]
    return BroadcastSessionListOut(items=items, has_more=bool(result.get("cursor")))
```

When `status` is supplied, `list_sessions_by_status` scans across all creators (GSI `ByStatusCreatedAt`), not scoped to `ctx["user_sub"]`. A non-admin broadcaster can enumerate all sessions of any status belonging to other creators by querying with `?status=live`.

`list_profiles_route` at `broadcast.py:352–358` always scopes to `list_profiles_by_creator(ctx["user_sub"])` — correct.

`_to_session_out` at `broadcast.py:244–259` merges the `BroadcastSessionModel` with its `BroadcastOutputModel` from the `BroadcastOutputs` table (CloudFront URL, MediaPackage endpoint, S3 archive prefix, ARNs), which is how the session detail dialog can display full infrastructure context.

### 2.2 Pydantic models and create bodies

`BroadcastProfileCreateIn` at `broadcast.py:80`: `name`, `region` (max 32 chars), `rendition_preset` (max 64 chars), optional `watermark_asset`, `drm_policy_id`, `drm_credentials_ref`, `drm_credentials_rotation_interval_seconds`.

`BroadcastSessionCreateIn` at `broadcast.py:106`: `profile_id`, optional `ingest_url` (max 1024 chars), `stream_key_ref` (max 512 chars), `stream_key_rotation_interval_seconds` (default 86400, min 60). The backend always stamps `created_by=ctx["user_sub"]` at `broadcast.py:289`.

`BroadcastSessionOut` at `broadcast.py:129` exposes status, `ingest_url`, `stream_key_ref`, `started_at`, `stopped_at`, `cloudfront_playback_url`, `aws_input_arn`, `aws_channel_arn`, `mediapackage_endpoint`, `s3_archive_prefix`, `provider_state_snapshot`.

### 2.3 State machine

`app/services/broadcast_state_machine.py` validates all transitions. Legal paths:
```
draft → provisioning | error
provisioning → ready | error
ready → live | stopping | error
live → stopping | error
stopping → stopped | error
stopped → (terminal)
error → provisioning | stopped
```
The orchestrator (`broadcast_orchestrator.py:17`) drives two consecutive transitions on start: `draft → provisioning → ready` (provision) then `ready → live` (start). Illegal transitions raise HTTP 409 from `transition_session_status` in `broadcast_store.py`.

### 2.4 DynamoDB tables

`scripts/local-ddb-init.py:513–578` and `app/core/settings.py:488ff`:

| Table | Key | GSIs | Settings key |
|-------|-----|------|-------------|
| `BroadcastProfiles` | PK `profile_id` | none | `broadcast_profiles_table_name` |
| `BroadcastSessions` | PK `session_id` | `ByStatusCreatedAt`, `ByCreatorCreatedAt` | `broadcast_sessions_table_name` |
| `BroadcastOutputs` | PK `session_id`, SK `scope` | none | `broadcast_outputs_table_name` |
| `BroadcastActionAudit` | PK `audit_id` | `ByActorCreatedAt`, `ByCreatedAt` | `broadcast_action_audit_table_name` |
| `BroadcastSessionTransitions` | PK `transition_id`, SK `session_id` | none | `broadcast_session_transitions_table_name` |

All table handles in `app/core/tables.py:102–107`. `T.broadcast_sessions`, `T.broadcast_profiles`, `T.broadcast_outputs`, `T.broadcast_action_audit`, `T.broadcast_session_transitions`.

### 2.5 Frontend — fully implemented

The ticket's claim of "zero frontend code" is no longer accurate. The full implementation:

**Page and routes** (`frontend/src/App.tsx:102–103, 361–363`):
```typescript
const BroadcastPage = lazy(() => import("@/pages/broadcast/BroadcastPage"));
// ...
{showBroadcastNavigation && <Route path="broadcast" element={<BroadcastPage />} />}
{showBroadcastNavigation && <Route path="broadcast/schedule" element={<BroadcastSchedulePage />} />}
```

The route is gated by `isBroadcastNavigationEnabled()` from `frontend/src/lib/featureFlags.ts:117–118`, which reads `VITE_BROADCAST_NAVIGATION_ENABLED` (default `true`) and `VITE_BROADCAST_NAVIGATION_KILL_SWITCH` (default `false`).

**Vite proxy** (`frontend/vite.config.ts:89`): `/broadcast` target `http://localhost:8000` — already present.

**`BroadcastPage.tsx`** (1096 lines, `frontend/src/pages/broadcast/BroadcastPage.tsx`):
- React Query keys: `["broadcast", "sessions", {status}]` with `refetchInterval: 10_000` for the list (line 138); `["broadcast", "sessions", selectedSessionId]` with `refetchInterval: 5_000` for detail (line 152)
- Tabs: Sessions / Profiles / Audit Log (shadcn/ui `<Tabs>` at line 241)
- `StatusBadge` component at line 105 using `STATUS_STYLES` dict (line 93) for `draft/provisioning/ready/live/stopping/stopped/error`
- Mutations for `start`, `stop`, `delete` with `useMutation` + `queryClient.invalidateQueries`
- Session detail dialog with RTMP URL copy, playback URL mint, ARN display

**Component directory** (`frontend/src/pages/broadcast/`) has 30+ files including `LivePlayer.tsx`, `BroadcastChat.tsx`, `BroadcastPrivacyControls.tsx`, `ProductShelf.tsx`, `ChatOverlay.tsx`, `ModeratorPanel.tsx`, `GuestInviteDialog.tsx`, `InputManager.tsx`, `AdBreakButton.tsx`.

**API endpoints**: `frontend/src/api/endpoints/broadcast.ts` (and `broadcast-chat.ts`, `broadcast-recordings.ts`, etc.) with typed wrappers for all backend endpoints.

**E2E test suite**: `frontend/e2e/broadcast.spec.ts` — sections 1 (profile creation), 2 (session lifecycle), 3 (playback URL), 4 (session deletion), 5 (audit log), 6–9 (auth enforcement, profile listing).

### 2.6 Dev vs Prod behavior (SECOPS-007)

In dev (`BROADCAST_PROVIDER=local`, `app/core/settings.py:488` default), `LocalBroadcastProvider.provision/start/stop/teardown` at `broadcast_provider.py:57–82` return instant synthetic `ProviderResult` objects with no AWS calls, no polling delays. In prod (`BROADCAST_PROVIDER=aws`), `AwsBroadcastProvider` makes real MediaLive/MediaPackage calls. The orchestrator at `broadcast_orchestrator.py:25` calls `get_broadcast_provider()` which reads `S.broadcast_provider` — same code path, different provider object. No `if dev:` branches in the orchestrator or router.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-025 IDOR on lifecycle routes

The three lifecycle routes each call `_require_operator_role(ctx)` and then immediately proceed to `start_session_with_provider` / `stop_session_with_provider` / `delete_session_with_provider` without checking whether the caller owns the session:

- `start_session_route` at `broadcast.py:360–399`: `_require_operator_role(ctx)` only
- `stop_session_route` at `broadcast.py:402–450`: `_require_operator_role(ctx)` only
- `delete_session_route` at `broadcast.py:453–477`: `_require_operator_role(ctx)` only

A `_require_session_owner` helper already exists at `broadcast.py:1338–1346` (used for privacy, allowlist, and recording endpoints) but is absent from the lifecycle routes. Exploit: Root B can call `DELETE /broadcast/sessions/{alice_session_id}` to permanently destroy Alice's live session, MediaLive channel, and all recordings.

### 3.2 Status-filter list exposes all creators' sessions

`list_sessions_route` at `broadcast.py:316` calls `list_sessions_by_status(status, limit=limit)` with no `creator_id` filter when `status` is supplied. Any authenticated user can enumerate all sessions in state `live`, `draft`, etc. platform-wide. The unfiltered path should be restricted to admin/root.

### 3.3 Audit log — no per-operator scoping

`query_audit_route` at `broadcast.py:531–546` is gated by `_require_operator_role` but does not restrict `actor` to `ctx["user_sub"]` for non-root callers. Any operator can omit the `actor` param and retrieve audit entries for all actors.

### 3.4 Missing `broadcast_aws_teardown_timeout_seconds`

`app/core/settings.py` defines `broadcast_aws_start_timeout_seconds` (line 524, default 120) and `broadcast_aws_stop_timeout_seconds` (line 525, default 120) but has no `broadcast_aws_teardown_timeout_seconds`. The teardown hard-codes `timeout_seconds=90` at `broadcast_provider.py:400`.

### 3.5 `BroadcastSessionCreateIn.profile_id` is not validated at create time

`create_session_route` at `broadcast.py:286–308` passes `profile_id=body.profile_id` to `create_session()` without verifying (a) the profile exists and (b) the profile was created by `ctx["user_sub"]`. An operator could create a session linked to another broadcaster's profile, inheriting their DRM credentials and region config.

---

## 4. Proposed Design / Fix

### 4.1 SEC-025 fix — add ownership check to lifecycle routes

In `app/routers/broadcast.py`, replace the bare `_require_operator_role(ctx)` at lines 369, 411, 455 with:

```python
def _require_operator_and_owner(session_id: str, ctx: dict) -> BroadcastSessionModel:
    """Require admin/root role AND session ownership; admin/root may bypass ownership."""
    session = get_session(session_id)
    is_owner = session.created_by == ctx["user_sub"]
    is_admin = ctx.get("role") in {"admin", "root"}
    if not (is_owner or is_admin):
        raise HTTPException(
            status_code=403,
            detail={"code": "BROADCAST_FORBIDDEN", "detail": "Only the session owner or admin may perform this action."},
        )
    _require_operator_role(ctx)
    return session
```

This aligns with the existing `_require_session_owner` at line 1338 and extends it to also enforce the operator role check.

### 4.2 Status filter scoping

In `list_sessions_route`:
```python
if status:
    if ctx.get("role") in {"admin", "root"}:
        result = list_sessions_by_status(status, limit=limit)
    else:
        result = list_sessions_by_status(status, creator_id=ctx["user_sub"], limit=limit)
```

`list_sessions_by_status` in `broadcast_store.py` needs a `creator_id` keyword parameter that adds a `FilterExpression` on the GSI query.

### 4.3 Profile ownership validation at session create

In `create_session_route`, before calling `create_session()`:
```python
profile = get_profile(body.profile_id)
if not profile:
    raise HTTPException(status_code=404, detail={"code": "BROADCAST_PROFILE_NOT_FOUND"})
if profile.created_by != ctx["user_sub"] and ctx.get("role") not in {"admin", "root"}:
    raise HTTPException(status_code=403, detail={"code": "BROADCAST_PROFILE_FORBIDDEN", "detail": "You do not own this profile."})
```

### 4.4 `broadcast_aws_teardown_timeout_seconds` setting

`app/core/settings.py`:
```python
broadcast_aws_teardown_timeout_seconds: int = int(os.environ.get("BROADCAST_AWS_TEARDOWN_TIMEOUT_SECONDS", "180"))
```

Use in `AwsBroadcastProvider.teardown` at `broadcast_provider.py:400`.

### 4.5 Dev/Prod parity (SECOPS-007)

All fixes are pure auth-logic changes in the FastAPI router/service layer. They call existing DDB queries via `get_profile()` and `get_session()` which operate on DynamoDB Local in dev and DynamoDB in prod via the same `T.*` table handles. No new AWS dependency is introduced. The `broadcast_aws_teardown_timeout_seconds` setting at 4.4 is a configuration-only change.

### 4.6 Alternatives considered

Making `start`/`stop`/`delete` self-service (no operator role required, just ownership) was considered. Rejected: the platform model requires that broadcasters need the operator/admin role to control their own sessions — this is an intentional privilege escalation gate. The combined ownership-and-role check is correct.

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests

**File**: `tests/test_broadcast_auth.py`

| Test | Assertion |
|------|-----------|
| `test_operator_cannot_start_others_session` | Non-owner admin → 403 `BROADCAST_FORBIDDEN` |
| `test_owner_with_admin_role_can_start` | Owner with admin role → 202 |
| `test_root_can_start_any_session` | Root (non-owner) → 202 |
| `test_status_filter_scoped_to_creator` | Non-admin with `?status=live` → only own sessions |
| `test_admin_status_filter_returns_all` | Admin `?status=live` → all creators |
| `test_invalid_transition_returns_409` | Start on `stopped` session → 409 |
| `test_profile_ownership_enforced_at_session_create` | Alice creates session with Bob's `profile_id` → 403 |
| `test_audit_log_non_admin_cannot_see_others` | Operator without admin role + no `actor` param → only own entries |
| `test_teardown_timeout_configurable` | `S.broadcast_aws_teardown_timeout_seconds = 10`; mock patch asserts 10s passed to poll |

All run offline with `@mock_aws` moto mocks. No real AWS credentials.

### 5.2 Playwright E2E tests

Existing `frontend/e2e/broadcast.spec.ts` already covers sections 1–9 (profile creation, session lifecycle, playback URL, deletion, audit, auth). Add:

**Section 10 (SEC-025 enforcement — to add)**:
- `10.1` Bob (admin role, non-owner) POST `start` on Alice's session → 403
- `10.2` Bob POST `stop` on Alice's session → 403
- `10.3` Bob DELETE Alice's session → 403
- `10.4` Root (non-owner) POST `start` on Alice's session → 202 (admin bypass)
- `10.5` Alice (owner, admin role) POST `start` her own session → 202

**Section 11 (status filter scoping — to add)**:
- `11.1` Alice queries `GET /broadcast/sessions?status=draft`; result contains only Alice's sessions
- `11.2` Root queries `GET /broadcast/sessions?status=draft`; result contains all creators' sessions

Auth pattern: `injectAuth(page, "alice")` / `injectAuth(page, "root")` + CSRF header for POST/DELETE.

### 5.3 Manual / QA steps

1. `just restart`; log in as Root, create a profile, create a session
2. Log in as a second admin account; navigate to `/broadcast`; list should show only own sessions (no other creators' sessions)
3. Attempt to start Root's session while logged in as second admin → verify 403 in network tab
4. Log in as Root; start the session → verify status badge transitions to `provisioning` then `live` within 10 seconds (polling)
5. Use the "Copy RTMP URL" button in the session detail dialog; verify clipboard receives the `ingest_url` value

### 5.4 Observability

`app/metrics.py` already defines `broadcast_session_actions_total` (labels: `provider`, `action`, `result`). Add:
- `broadcast_auth_rejection_total` (labels: `endpoint`: `start`/`stop`/`delete`/`status_filter`, `reason`: `ownership`/`role`) — counts 403 rejections from the new ownership check
- Alarm: `broadcast_auth_rejection_total > 20/5min` — potential automated abuse of lifecycle endpoints

### 5.5 Rollout

1. SEC-025 ownership check (4.1): pure code change, no schema changes; deploy atomically
2. Status filter scoping (4.2): deploy with 4.1 — requires `list_sessions_by_status` parameter addition in `broadcast_store.py`
3. Profile ownership check (4.3): deploy independently — only tightens access
4. `broadcast_aws_teardown_timeout_seconds` (4.4): add env var to `.env.local.example`; deploy
5. Rollback: all changes are purely more restrictive; rollback restores the previous (more permissive) behavior

### 5.6 Effort estimate

- SEC-025 ownership fix + status filter scoping: **S** (2–3 hours including unit tests)
- Profile ownership validation: **S** (1 hour)
- Teardown timeout setting: **XS** (15 minutes)
- E2E sections 10–11: **S** (2 hours)
- Total: **M** (6–7 hours)
