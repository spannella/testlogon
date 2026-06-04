# BCAST-002: Viewer Playback Page with HLS Player — Investigation & Implementation Write-up

## 1. Summary & Classification

BCAST-002 specifies a public-facing broadcast viewer page that acquires a signed HLS playback URL and an entitlement JWT, initialises an `hls.js`-based adaptive bitrate player with DRM key injection, and handles token refresh, quality selection, and error recovery gracefully. The ticket described the frontend as completely absent. In reality the frontend implementation is complete: `LivePlayer.tsx` exists, `hls.js ^1.6.16` is in `package.json`, routes are registered, and entitlement infrastructure is fully wired.

- **Type**: Feature (viewer-facing streaming UI)
- **Priority**: High (core consumption experience)
- **Status**: Implemented — frontend and backend are live; ticket's gap analysis is outdated
- **User persona**: Any authenticated viewer; broadcaster shares a `/live/:sessionId` link
- **Cross-referenced tickets**: BCAST-001 (session CRUD, provides `session_id`), BCAST-004 (viewer count badge and health indicator displayed within the player page), BCAST-005 (live chat panel integrated into `LivePlayer.tsx`), SEC-010 (SSE/stream IDOR — the SSE event stream at `/broadcast/sessions/{id}/stream` and chat stream at `/broadcast/sessions/{id}/chat/stream` lack viewer access checks; details in SEC-010 write-up)

---

## 2. Current-State Investigation (what exists today)

### 2.1 Player component

`frontend/src/pages/broadcast/LivePlayer.tsx` is the main player component. It:
- Is lazy-loaded via `App.tsx:104`: `const LivePlayer = lazy(() => import("@/pages/broadcast/LivePlayer"))`
- Is mounted at `App.tsx:285`: `<Route path="live/:sessionId" element={<LivePlayer />} />` — a **public** route (no `ProtectedRoute` wrapper) matching the `/live/:sessionId` path, outside the authenticated shell
- Imports `useBroadcastStream` from `@/hooks/useBroadcastStream` (line 18), `BroadcastChat` from `./BroadcastChat` (line 20)
- Uses `hls.js ^1.6.16` (`package.json:49`), confirmed as a hard dependency

### 2.2 Backend: playback URL minting

`POST /broadcast/sessions/{session_id}/playback-url` at `app/routers/broadcast.py:492–518`:

```python
@router.post("/sessions/{session_id}/playback-url", response_model=BroadcastPlaybackUrlOut)
def mint_playback_url_route(session_id: str, invite_token: Optional[str] = Query(default=None), ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    from app.services.broadcast_privacy import check_viewer_access
    check_viewer_access(session_id, ctx["user_sub"], creator_id=session.created_by,
                        visibility=session.broadcast_privacy_visibility, invite_token=invite_token)
    existing = get_output(session_id)
    minted = mint_local_playback_url(session.id)
    playback_url = existing.cloudfront_playback_url if existing and existing.cloudfront_playback_url else minted.url
    return BroadcastPlaybackUrlOut(session_id=session.id, playback_url=playback_url, expires_at=minted.expires_at)
```

The endpoint prefers the CloudFront URL from the output record (set in prod by `broadcast_orchestrator.py:104` when `provider.name == "aws"`) and falls back to the locally-minted MD5-signed URL from `app/services/broadcast_playback.py`. It calls `check_viewer_access` from `app/services/broadcast_privacy.py`, so private/invite-gated sessions are enforced here.

### 2.3 Backend: playback token verification

`GET /broadcast/playback/verify?path=...&cf_token=...&cf_expires=...` at `broadcast.py:521–528` calls `validate_cloudfront_token` from `app/services/broadcast_cloudfront.py`. Used by CDN edge (Lambda@Edge or CloudFront Functions) to verify viewer access before serving segments. Returns `{"valid": true}` or 403.

### 2.4 Backend: playback entitlement system

`app/routers/playback_entitlements.py` exposes three endpoints under `/v1/playback`:

| Method | Path | Purpose |
|--------|------|---------|
| POST | `/entitlements/issue` | Mint short-lived HMAC-signed JWT (HS256, `typ=PLAYBACKJWT`) |
| POST | `/entitlements/revoke` | Revoke by JTI or session_id + tenant_id |
| GET | `/protected/ping` | Validate a Bearer playback token |

`app/main.py:137` registers `_playback_entitlement_middleware()` that intercepts all `/v1/playback/protected/*` requests and validates the Bearer token, attaching `request.state.playback_claims`. Max TTL is `S.playback_entitlement_max_ttl_seconds` (default 300).

### 2.5 Backend: local DRM key delivery

`app/services/broadcast_local_drm.py`:
- `mint_local_drm_token(stream_key, ttl)` — HMAC-SHA256 signed token (`{b64url(payload)}.{b64url(sig)}`)
- `validate_local_drm_token(token, stream_key)` — verifies signature + expiry; also accepts static dev token `S.broadcast_local_drm_static_token` (default `"dev-token"`)
- `load_local_drm_key(stream_key, token)` — returns 16-byte AES-128 key from `S.broadcast_local_drm_key_root` (default `tmp/broadcast-hls/keys/{stream_key}.key`)

AES-128 keys are delivered to hls.js via `#EXT-X-KEY:METHOD=AES-128,URI=...` in the HLS manifest, with the token passed as a query parameter.

### 2.6 Settings relevant to viewer playback

From `app/core/settings.py:468–489`:
- `broadcast_local_cache_public_base_url` (default `http://localhost:8090`) — HLS manifest/segment base URL
- `broadcast_local_cache_token_secret` (default `local-cache-secret`) — MD5 URL signing secret
- `broadcast_local_cache_token_ttl_seconds` (default 600) — playback URL validity
- `broadcast_local_drm_token_secret` (default `local-drm-secret`) — DRM token secret
- `broadcast_local_drm_static_token` (default `dev-token`) — bypass token for offline tests
- `broadcast_cloudfront_domain` — production CDN domain (empty in dev)
- `broadcast_cloudfront_token_ttl_seconds` (default 600)
- `playback_entitlement_secret` — HMAC secret for entitlement JWTs (must be non-empty in prod)
- `playback_entitlement_max_ttl_seconds` (default 300)

### 2.7 DynamoDB: viewer tables

`app/core/tables.py:151–152` defines `T.broadcast_viewers` and `T.broadcast_health_snapshots`. `scripts/local-ddb-init.py:715–720` creates both. These back the viewer join/heartbeat/count endpoints that the player invokes on mount.

### 2.8 Dev vs Prod behavior

In dev, the playback URL resolves to `http://localhost:8090/hls/{stream_key}/master.m3u8?md5=...&expires=...` — the local HLS nginx server (or mock). The DRM key endpoint at `/broadcast/drm/keys/{stream_key}` accepts `dev-token` without signature check. In prod, CloudFront signs the URL via `mint_cloudfront_signed_playback_url` at `broadcast_orchestrator.py:104`; the CDN validates via Lambda@Edge calling `/broadcast/playback/verify`. Same backend code path selected by `provider.name == "aws"` in the orchestrator; same `mint_playback_url_route` endpoint for the browser.

---

## 3. Gap / Threat Analysis

### 3.1 SEC-010 IDOR — SSE event stream lacks viewer access check

`broadcast_event_stream_route` at `broadcast.py:717–737`:

```python
@router.get("/sessions/{session_id}/stream")
async def broadcast_event_stream_route(session_id: str, ctx: dict = Depends(_ctx)):
    _ = ctx
    _ = get_session(session_id)  # 404 if session doesn't exist
    q = broadcast_sse_subscribe(session_id)
```

`ctx["user_sub"]` is authenticated but `check_viewer_access` is **not called**. Any authenticated user can subscribe to any broadcast session's SSE stream (viewer count events, health updates, ad-break signals). For private or subscription-gated sessions (`broadcast_privacy_visibility = "private"` or `"subscribers_only"`), this leaks operational data to non-entitled viewers. Compare: `mint_playback_url_route` at line 500–506 explicitly calls `check_viewer_access` before granting a URL.

### 3.2 SEC-010 IDOR — chat stream lacks viewer access check

`broadcast_chat_stream_route` at `broadcast.py:1763–1822`:

```python
async def broadcast_chat_stream_route(session_id: str, ..., ctx: dict = Depends(_ctx)):
    _ = ctx
    session = get_session(session_id)  # existence check only
    if session.status not in ("live", "ready"):
        raise HTTPException(…)
    # No check_viewer_access call
```

Again, `ctx` is discarded after extraction. Combined with the missing `viewer_user_id` argument to `_chat_msg_out` at line 1806 (called as `_chat_msg_out(msg)` not `_chat_msg_out(msg, ctx["user_sub"])`), this means locked/expiry-redacted message fields are delivered in clear to any subscriber. The `_chat_msg_out` signature in `app/services/broadcast_chat_store.py:344` accepts an optional `viewer_user_id` parameter for per-viewer redaction that is never passed from this stream endpoint.

### 3.3 Playback entitlement `playback_entitlement_secret` may be empty in dev

`app/core/settings.py` does not assert `playback_entitlement_secret` is non-empty at startup (unlike `UI_ACCESS_TOKEN_SECRET` which has a `validate_ui_access_token_secret` validator). An empty secret produces a trivially forgeable HMAC. Needs a startup assertion matching the pattern used for `UI_ACCESS_TOKEN_SECRET`.

### 3.4 DRM key root path traversal

`load_local_drm_key` constructs the key path as `{broadcast_local_drm_key_root}/{stream_key}.key`. If `stream_key` contains `..` segments, this can traverse outside the key root. The stream key is validated by `mint_local_playback_url` with a regex `/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/` but the DRM endpoint should independently re-validate the stream_key format before constructing the path.

---

## 4. Proposed Design / Fix

### 4.1 SEC-010 fix — add `check_viewer_access` to SSE and chat stream endpoints

**`app/routers/broadcast.py:717`** — broadcast event stream:

```python
@router.get("/sessions/{session_id}/stream")
async def broadcast_event_stream_route(session_id: str,
                                        invite_token: Optional[str] = Query(default=None),
                                        ctx: dict = Depends(_ctx)):
    session = get_session(session_id)
    from app.services.broadcast_privacy import check_viewer_access
    check_viewer_access(session_id, ctx["user_sub"],
                        creator_id=session.created_by,
                        visibility=session.broadcast_privacy_visibility,
                        invite_token=invite_token)
    q = broadcast_sse_subscribe(session_id)
    # ... existing generator
```

**`app/routers/broadcast.py:1763`** — chat stream: same pattern, plus pass `ctx["user_sub"]` to `_chat_msg_out`:

```python
    out = _chat_msg_out(msg, viewer_user_id=ctx["user_sub"])
```

### 4.2 Startup assertion for entitlement secret

In `app/core/settings.py`, add a validator:

```python
@validator("playback_entitlement_secret")
def validate_playback_entitlement_secret(cls, v):
    if not v and not os.environ.get("DEV_MODE", "1") not in ("0", "false"):
        import warnings
        warnings.warn("PLAYBACK_ENTITLEMENT_SECRET is empty; entitlement tokens are not secure")
    return v
```

Or raise `ValueError` in prod mode (when `dev_mode=False`). Mirror the existing `UI_ACCESS_TOKEN_SECRET` validation pattern.

### 4.3 DRM key path sanitisation

In `app/services/broadcast_local_drm.py`, re-validate `stream_key` format before constructing the path:

```python
import re, os
_SK_PATTERN = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')
def load_local_drm_key(stream_key: str, token: str) -> bytes:
    if not _SK_PATTERN.match(stream_key):
        raise ValueError(f"invalid stream_key format: {stream_key!r}")
    key_path = os.path.join(S.broadcast_local_drm_key_root, f"{stream_key}.key")
    # Ensure resolved path is under key root (defence-in-depth)
    root = os.path.realpath(S.broadcast_local_drm_key_root)
    resolved = os.path.realpath(key_path)
    if not resolved.startswith(root + os.sep):
        raise ValueError("stream_key path traversal rejected")
    ...
```

### 4.4 Dev/Prod parity (SECOPS-007)

The fix at 4.1 calls `check_viewer_access` which is already dual-mode: in dev it evaluates against the DDB `BroadcastAllowlist` table on DynamoDB Local; in prod against the same DDB schema on AWS. No new AWS dependency is introduced. The DRM fix (4.3) is pure path-validation logic, env-agnostic. The entitlement secret assertion (4.2) warns in dev, enforces in prod — matching the SECOPS-007 rule "graceful degradation in dev; strict in prod."

### 4.5 Alternatives considered

An alternative to checking `check_viewer_access` in the SSE route is to issue a short-lived "stream ticket" at playback-URL mint time and require it as a query parameter on the SSE connection, avoiding a DDB lookup per SSE subscribe. This is cleaner for high-concurrency scenarios but is a larger change. For now the direct DDB-based check is consistent with the existing pattern on `viewer_join_route` (line 585).

---

## 5. Testing, Verification & Rollout

### 5.1 Pytest unit tests

**File**: `tests/test_broadcast_player.py`

| Test | Assertion |
|------|-----------|
| `test_mint_playback_url_returns_signed_url` | minted URL contains `md5=` and `expires=` params; `expires_at > now_ts()` |
| `test_playback_url_private_session_denied` | viewer without allowlist → `check_viewer_access` raises 403 |
| `test_sse_stream_private_session_denied` | SSE subscribe on private session for non-viewer → 403 (post-fix) |
| `test_chat_stream_private_session_denied` | Chat SSE on private session → 403 (post-fix) |
| `test_drm_key_path_traversal_rejected` | `stream_key = "../etc/passwd"` → `ValueError` (post-fix) |
| `test_entitlement_issue_returns_jwt` | Issue entitlement; token is valid HS256 JWT with correct claims |
| `test_cloudfront_token_verify_valid` | Valid CF token → `{"valid": true}` |
| `test_cloudfront_token_verify_expired` | Expired CF token → 403 |

### 5.2 Playwright E2E tests

**File**: `frontend/e2e/broadcast.spec.ts` (existing sections 3, playback URL). Add:

**Section 11 (viewer access enforcement — to add)**:
- `11.1` Unauthenticated SSE subscribe → 401 (EventSource with no cookie)
- `11.2` Non-invited user SSE subscribe to private session → 403
- `11.3` Invited user SSE subscribe with `invite_token` → 200, `event: hello` received
- `11.4` Chat stream on non-live session → 403
- `11.5` Chat stream for non-entitled viewer of private session → 403

Pattern: `injectAuth(page, "alice")` + `page.evaluate(() => new EventSource("/broadcast/sessions/{id}/stream", {withCredentials: true}))` + check response status via `page.route`.

### 5.3 Manual / QA steps

1. `just restart`; create a broadcast session via Root, start it
2. Open private incognito window logged in as Alice; navigate to `/live/{sessionId}`
3. Verify player loads, heartbeat fires (Network tab shows `POST /viewers/join` 200)
4. Mark session as private via privacy settings; reload Alice's player → verify 403 toast

### 5.4 Observability

`app/metrics.py` already defines `broadcast_output_errors_total`. Add:
- `broadcast_viewer_access_denied_total` (labels: `reason`, `endpoint`) — counts 403s on SSE and playback-url endpoints after the check_viewer_access fix
- `broadcast_drm_key_requests_total` (labels: `result`: `success`/`invalid_token`/`path_traversal`)

### 5.5 Rollout

SEC-010 stream fixes are auth tightening with no schema changes. Deploy immediately. All existing entitled viewers continue to work (they already pass `check_viewer_access` for non-private sessions since `check_viewer_access` is a no-op when `visibility=None`). Risk: any code path that was relying on unauthenticated or cross-session SSE will break — this is the intended correction.

### 5.6 Effort estimate

- SEC-010 SSE stream fix: **S** (2 hours — two call sites + unit tests)
- SEC-010 chat stream `_chat_msg_out` fix: **S** (1 hour)
- DRM path traversal: **XS** (30 minutes)
- Entitlement secret assertion: **XS** (15 minutes)
- E2E auth section 11: **S** (2 hours)

### 5.7 Open questions

1. **Playback entitlement `ttl_seconds` negotiation**: The player hook (`usePlaybackEntitlement`) issues tokens with `ttl_seconds=120`. If the backend's `PLAYBACK_ENTITLEMENT_MAX_TTL_SECONDS` is set lower (e.g., for tighter replay protection), the issue endpoint silently caps it without signalling the client. The response's `ttl_seconds` field should be used for the refresh timer rather than the requested value — verify this is the case in the existing `usePlaybackEntitlement.ts` implementation.

2. **Safari FairPlay DRM**: The ticket's Phase 1 covers AES-128 key delivery via hls.js built-in XHR interception. Safari requires `video.webkitSetMediaKeys` (not the W3C EME `video.setMediaKeys`) for FairPlay — a DRM path that is intentionally deferred. Document this as a known limitation in the player's error handling: if `EXT-X-KEY:METHOD=SAMPLE-AES` is encountered on Safari, show "DRM not supported on this browser."

3. **Viewer page without authentication**: The `/live/:sessionId` route is public (outside `ProtectedRoute` at `App.tsx:285`). `mint_playback_url_route` and `viewer_join_route` both require `require_ui_session`. Unauthenticated visitors will receive a 401 and see an error state. A guest token mechanism (linking to the invite-token flow from BCAST-011) is needed for fully public broadcasts.

4. **HLS.js version pinning**: `package.json:49` pins `"hls.js": "^1.6.16"`. The `^` semver range allows minor updates. Given that hls.js regularly ships EME and MSE behavior changes, a stricter `~1.6.16` pin may be appropriate to prevent unexpected playback regressions from automatic dependency updates.

5. **Viewer join rate and geo-check cost**: `viewer_join_route` at `broadcast.py:578–592` reads the raw DDB item a second time to extract `geo_mode` and `geo_countries` for the geo-check, even though `get_session(session_id)` was already called at line 577. At scale (thousands of concurrent viewer joins on stream start), this doubles DDB read throughput on `BroadcastSessions`. The `BroadcastSessionModel` should expose `geo_mode`/`geo_countries` fields directly to eliminate the redundant read.

6. **`/live/:sessionId` vs `/watch/:sessionId` naming**: The ticket proposed `/watch/:sessionId` as the public viewer route; the actual implementation uses `/live/:sessionId` (App.tsx:285). All links in BCAST-001's "mint playback URL" section, documentation, share buttons, and E2E specs should use `/live/:sessionId`. This discrepancy exists in the original ticket text and should not cause confusion in new work, but is noted for completeness.
