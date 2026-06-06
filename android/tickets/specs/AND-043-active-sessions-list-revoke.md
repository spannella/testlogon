---
id: AND-043
title: Active sessions list + revoke
milestone: M1
epic: E06
priority: P1
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027, AND-029]
blocks: []
---

# AND-043 — Active sessions list + revoke

## 1. Overview & Goal

Give the authenticated user a screen that lists every active server-side session
attached to their account, clearly marks the session running on this device, and
lets them revoke an individual remote session or revoke all other sessions in one
action. This is a security-hygiene feature ("Where you're logged in") backed by
the existing cookie-based session system.

The screen lives in `feature-account` (Settings → Security → Active sessions) and
talks to the backend through the already-built `AuthApi` (AND-027) and the
persistent auth state store / `getMe()` (AND-029). The local device's current
session is identified by correlating the `sub`/session id returned from
`GET /ui/me` (and the current session marker in the list payload) so it can be
highlighted and protected from accidental self-revocation through the "revoke
others" path. (Verified: the list itself already returns a per-row `is_current`
boolean — see §5 — so the `getMe()` correlation is a defensive fallback, not the
primary signal the web client uses.)

Success means: the list renders from `GET /ui/sessions`, the current session is
visibly and programmatically distinguishable, single-session revoke removes that
row, "revoke others" removes every row except the current one, and all of these
behaviors are covered by deterministic tests (MockWebServer + ViewModel unit
tests + a Compose UI test).

## 2. Context & References

- Repo `spannella/testlogon`, Android app under `android/`, branch `android-port`.
- Namespace / applicationId base: `com.testlogon.android`.
- Feature module: `feature-account` → consumes `core-network`, `core-model`,
  `core-data`, `core-ui`, `core-testing`.
- **AND-027** owns `AuthApi`, including `sessions()` and `revoke`. This ticket
  must not redefine those Retrofit methods; if the contract below requires a
  signature not yet present, extend `AuthApi` in coordination with AND-027.
- **AND-029** owns `getMe()` and the persistent auth state store
  (`authenticated`, `user_sub`). This ticket reads `user_sub` / current session
  id from that store to mark the current row; it does not write auth state.
- Cookie-based session: requests carry the session cookies + `X-CSRF-Token`
  header echoed from the `ui_csrf` cookie. On `401`, the OkHttp authenticator
  (from earlier E04 tickets) performs `POST /ui/session/refresh` once and
  retries. Revoke is a mutating `DELETE`/`POST` and therefore requires the CSRF
  header and is **not** eligible for idempotent-GET backoff retry.
- Dev backend `http://18.222.237.167:8000` is plaintext HTTP and unreliable:
  ~20s timeouts, offline/stale UI states, no automatic retry on mutations.
- Web reference: `frontend/src/api/endpoints/*.ts` (sessions endpoint) and
  `frontend/src/api/types.ts`. Confirm exact field names against `/openapi.json`
  at build time; the shapes below are the contract this ticket implements.

## 3. Functional Requirements

FR-1. On entering the screen the app calls `GET /ui/sessions` and shows a loading
state, then a list of sessions sorted by `last_seen_at` descending. (Field name
corrected: backend uses `last_seen_at`, an epoch-seconds **number**, not
`last_active_at`. The web client does not sort — see §6 note — so client-side
sorting is an Android design choice.)

FR-2. Each row shows: a device/client label derived from `user_agent` (the
backend has **no** `device` field), the IP (`ip`, not `ip_address`), last-seen
time (relative, e.g. "2 hours ago"; backend supplies `last_seen_at` and
`created_at` as epoch seconds), a "This device" badge when the row is current,
and a "Revoked" badge when `revoked == true`. (There is **no** `location` field
in the payload; any coarse-geo display is out of contract.)

FR-3. The current session is determined primarily by the row's `is_current`
boolean (the field the web client uses), with a defensive fallback of matching
the row's `session_id` against the current session id from `getMe()`/auth store.
(Field name corrected: the list flag is `is_current`, not `current`.)

FR-4. A non-current row exposes a "Sign out" / revoke affordance that calls the
single-session revoke endpoint. On success the row is removed from the list
(optimistic with rollback on failure).

FR-5. A "Sign out all other sessions" button revokes every session except the
current one. On success all non-current rows are removed; the current row
remains.

FR-6. The current session's row must NOT offer a single-session revoke control
(self sign-out is handled by the existing Logout flow, not this screen).

FR-7. Pull-to-refresh re-fetches the list. Empty state (only the current
session, or unexpectedly zero rows) shows an explanatory message.

FR-8. All revoke actions require an inline confirmation (dialog) before
executing, because they are destructive.

FR-9. Errors (network, 401-after-refresh-failure, 403 CSRF, 5xx) surface a
non-blocking, retryable message and leave the list in a consistent state.

## 4. Technical Design

Module: `feature-account`. MVVM with Hilt, `StateFlow<UiState>`.

```kotlin
// core-model
// NOTE: field names/shape corrected to match the verified backend SessionInfo
// (frontend src/api/types.ts: SessionInfo). Timestamps are epoch SECONDS
// (number) on the wire — DTO carries Long, domain maps to Instant.
data class SessionInfo(
    val sessionId: String,      // session_id
    val isCurrent: Boolean,     // is_current  (was wrongly "current")
    val userAgent: String,      // user_agent  (label derived client-side)
    val ipAddress: String,      // ip          (was wrongly "ip_address")
    val createdAt: Instant,     // created_at  (epoch seconds on wire)
    val lastSeenAt: Instant,    // last_seen_at (was wrongly "last_active_at")
    val revoked: Boolean,       // revoked
    val revokedAt: Instant?,    // revoked_at (optional)
)
// REMOVED: no `device` and no `location` field exist in the backend payload;
// the display label is derived from `user_agent` in the mapper.
```

```kotlin
// core-network — extends/uses AuthApi (AND-027)
interface AuthApi {
    // ... existing start/finalize/refresh/logout/me ...
    @GET("ui/sessions")
    suspend fun getSessions(): Response<SessionListDto>

    // CORRECTED: single revoke is POST /ui/sessions/revoke with a JSON body
    // { "session_id": "<id>" } — NOT a DELETE with a path param. Verified
    // against OpenAPI 'POST /ui/sessions/revoke' and
    // frontend src/api/endpoints/auth.ts: revokeSession.
    @POST("ui/sessions/revoke")
    suspend fun revokeSession(@Body body: RevokeSessionDto): Response<StatusDto>

    // CORRECTED: path is /ui/sessions/revoke_others (underscore), takes NO
    // body, and returns StatusDto {status}. There is NO revoked_count field.
    // Verified against OpenAPI 'POST /ui/sessions/revoke_others' and
    // frontend src/api/endpoints/auth.ts: revokeOtherSessions.
    @POST("ui/sessions/revoke_others")
    suspend fun revokeOtherSessions(): Response<StatusDto>
}

// RevokeSessionDto { @Json(name="session_id") val sessionId: String }
// StatusDto       { val status: String }   // frontend types.ts: StatusResp
// SessionListDto  { val sessions: List<SessionInfoDto> }  // no named schema
//   in OpenAPI (resp schema is empty {}); shape verified from
//   frontend auth.ts: getSessions -> { sessions: SessionInfo[] }.
```

Repository in `core-data` wraps the API and maps DTO → domain + `ApiResult<T>`:

```kotlin
class SessionsRepository @Inject constructor(
    private val authApi: AuthApi,
    private val authStateStore: AuthStateStore, // AND-029
    private val dispatchers: AppDispatchers,
) {
    suspend fun listSessions(): ApiResult<List<SessionInfo>>
    suspend fun revoke(sessionId: String): ApiResult<Unit>
    // CORRECTED: backend returns StatusResp {status}, NOT a count. The repo
    // computes "revoked count" locally (non-current rows it asked to drop) for
    // the UI message; it is not authoritative from the server.
    suspend fun revokeOthers(): ApiResult<Unit>
    fun currentSessionId(): String?            // from AuthStateStore
}
```

ViewModel:

```kotlin
@HiltViewModel
class ActiveSessionsViewModel @Inject constructor(
    private val repo: SessionsRepository,
) : ViewModel() {

    data class UiState(
        val isLoading: Boolean = false,
        val isRefreshing: Boolean = false,
        val sessions: List<SessionRow> = emptyList(),
        val pendingRevokeIds: Set<String> = emptySet(),
        val revokingOthers: Boolean = false,
        val error: UiError? = null,
        val confirm: ConfirmTarget? = null, // null | RevokeOne(id) | RevokeOthers
    )
    data class SessionRow(val info: SessionInfo, val isCurrent: Boolean)

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    fun load()                                   // initial + retry
    fun refresh()                                // pull-to-refresh
    fun requestRevoke(sessionId: String)         // opens confirm
    fun requestRevokeOthers()                    // opens confirm
    fun confirm()                                // executes pending action
    fun dismissConfirm()
    fun dismissError()
}
```

Composables (Material 3, `core-ui` components):

```kotlin
@Composable
fun ActiveSessionsRoute(
    viewModel: ActiveSessionsViewModel = hiltViewModel(),
    onBack: () -> Unit,
)

@Composable
fun ActiveSessionsScreen(
    state: ActiveSessionsViewModel.UiState,
    onRefresh: () -> Unit,
    onRevoke: (String) -> Unit,
    onRevokeOthers: () -> Unit,
    onConfirm: () -> Unit,
    onDismissConfirm: () -> Unit,
    onDismissError: () -> Unit,
    onBack: () -> Unit,
)
```

Navigation: register `accountActiveSessions` route in the account nav graph
(Navigation-Compose). Reached from the Security settings entry.

Current-session resolution order in the mapper: (1) `dto.is_current == true`
(the field the web client uses), (2) `dto.sessionId == repo.currentSessionId()`
(defensive fallback via `getMe().session_id`). The mapper sets exactly one
`isCurrent = true`; if neither method resolves a current row (degraded backend),
no row is marked current and "revoke others" is disabled to prevent revoking the
device's own session.

"Revoke others" uses the single backend call `POST /ui/sessions/revoke_others`
(underscore). VERIFIED present in OpenAPI ('POST /ui/sessions/revoke_others') and
used by the web client (auth.ts: revokeOtherSessions), so the previously specced
"fall back to sequential revokeSession calls if absent" branch is **not needed
for correctness** and is dropped from the contract; it may remain only as an
optional degraded-mode safety net (bounded, stop/report on first hard failure).
The repository hides this behind `revokeOthers()`.

## 5. API Contract

`GET /ui/sessions` → 200 (CORRECTED to the verified shape; the OpenAPI response
schema is an untyped `{}`, so the field names below come from
frontend `src/api/types.ts: SessionInfo` and `auth.ts: getSessions`):

```json
{
  "sessions": [
    {
      "session_id": "sess_01HX...",
      "is_current": true,
      "user_agent": "TestLogonAndroid/1.0 (Android 15; Pixel 8)",
      "ip": "203.0.113.7",
      "created_at": 1748786531,
      "last_seen_at": 1749116204,
      "revoked": false,
      "revoked_at": null
    }
  ]
}
```

Notes: `created_at`/`last_seen_at`/`revoked_at` are **epoch seconds (numbers)**,
not ISO-8601 strings (the web multiplies by 1000 before `new Date(...)`). There
is **no** `device` and **no** `location` field; the display label is derived from
`user_agent` client-side. The current-session flag is `is_current`, not
`current`.

`POST /ui/sessions/revoke` → 200 `{ "status": "ok" }` (CORRECTED: it is a POST
with JSON body `{ "session_id": "<id>" }`, NOT a `DELETE` with a path param, and
it returns 200 with a `StatusResp` body, NOT 204). Requires the cookie session +
`X-CSRF-Token`. Verified: OpenAPI 'POST /ui/sessions/revoke',
frontend `auth.ts: revokeSession`, `types.ts: StatusResp`.
ASSUMPTION (unverified): that revoking the *current* session id is rejected
server-side — not expressed in OpenAPI; treat any `400/409` as a guarded client
error and rely on the client guard (FR-6) regardless.

`POST /ui/sessions/revoke_others` → 200 `{ "status": "ok" }` (CORRECTED: path is
`revoke_others` with an UNDERSCORE, takes **no** request body, and returns a
`StatusResp`. There is **no** `revoked_count` field). Verified: OpenAPI
'POST /ui/sessions/revoke_others', frontend `auth.ts: revokeOtherSessions`.

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "msg": "Session not found" }] }
{ "detail": { "code": "session_not_found", "message": "..." } }
```

Status handling: 200 success (revoke endpoints return 200 + `{status}`, **not**
204); 401 → authenticator refresh-once-then-retry (transparent — verified in
frontend `client.ts`); 403 → CSRF/forbidden surfaced as retryable error;
422 (FastAPI validation) and 404/409 on revoke → drop the row locally and refresh
(already gone / bad id); 5xx / timeout → retryable error, list unchanged. Field
names are verified above against the frontend DTOs (the OpenAPI 200 schemas for
these three ops are untyped `{}`); Moshi DTOs use `@Json(name=...)` for
snake_case mapping. The exact `AuthApi` method set is owned by AND-027.

## 6. Data & State Management

- No Room persistence: the sessions list is security-sensitive and must always
  reflect live server state, so it is fetched on demand and held only in
  `StateFlow` memory. No disk cache.
- Current session id is read from `AuthStateStore` (DataStore, AND-029). This
  ticket only reads it; it does not write auth state.
- Optimistic update model for revoke: on confirm, add the id to
  `pendingRevokeIds` and remove the row from the rendered list; on API success,
  clear the pending id; on failure, re-insert the row at its original index and
  show an error. "Revoke others" snapshots the removed rows for rollback.
- Refresh is idempotent and replaces the entire list; in-flight optimistic
  removals are reconciled against the fresh server list (server is source of
  truth).
- Sorting/derivation happens in the mapper, not the UI: rows are sorted by
  `lastSeenAt` desc with the current row pinned to the top. NOTE: this ordering
  is an Android UX choice — the web reference (`pages/security/Sessions.tsx`)
  renders the server's order unmodified and does not pin the current row. The
  backend does not guarantee an order.

## 7. Error Handling & Resilience

- Timeouts ~20s (OkHttp config from core-network). The initial GET is an
  idempotent read and MAY use the existing bounded-backoff retry for GETs;
  revoke mutations MUST NOT auto-retry (no duplicate destructive effects).
- 401: handled by the OkHttp authenticator (single `POST /ui/session/refresh`
  then retry). If refresh fails, the call returns 401 → map to "Session
  expired"; route the user to re-auth (delegated to the auth flow, not
  re-implemented here).
- 403 (CSRF mismatch): surface "Couldn't verify your session, try again";
  retry re-reads the `ui_csrf` cookie via the existing interceptor.
- Network offline: show an offline banner with Retry; keep last-rendered list if
  present (clearly marked stale) rather than blanking the screen.
- Partial failure in fallback "revoke others" loop: stop at first failure,
  report "Revoked X of Y", refresh the list so state is accurate.
- Guard rail: "revoke others" is disabled whenever the current session cannot be
  identified (see §4), preventing accidental self-logout.

## 8. Security & Privacy

- All calls go over the existing authenticated cookie jar with `X-CSRF-Token`;
  no session tokens are logged or persisted to disk by this feature.
- `session_id` values are sensitive; never write them to logcat in release, never
  include in analytics payloads, never put in crash report breadcrumbs.
- `ip_address`/`location` are PII shown only to the owning user in-session; not
  cached, not exported.
- Destructive actions require explicit confirmation (FR-8). The current session
  is protected from single-revoke (FR-6) and excluded from "revoke others".
- Dev backend is plaintext HTTP; production must be HTTPS. This screen adds no
  new cleartext exemptions beyond the existing dev `network_security_config`.

## 9. Accessibility & i18n

- All strings in `feature-account` `strings.xml`; no hardcoded text. Relative
  times via `DateUtils.getRelativeTimeSpanString` / a locale-aware formatter.
- Each row has a merged `contentDescription` summarizing the derived device
  label, IP, last-seen time, and current-session status (e.g. "This device,
  Chrome on Android, 203.0.113.7, last seen 2 hours ago"). NOTE: no location
  field exists, so location is not announced.
- Revoke buttons have explicit `contentDescription` ("Sign out <device>"); the
  "This device" badge is exposed to TalkBack.
- Touch targets ≥ 48dp; confirmation dialogs are focus-trapped and TalkBack
  announceable; supports dynamic font scaling and dark theme via Material 3.
- RTL-safe layouts (start/end paddings, no hardcoded left/right).

## 10. Telemetry & Logging

- Events (no PII; ids hashed or omitted): `sessions_viewed`,
  `session_revoked` (`{source: "single"|"others"}`),
  `revoke_others` (`{count}`), `sessions_load_error` (`{type}`).
- Logging via the project Timber wrapper; debug-only for request/response
  metadata, and never the `session_id`, cookies, or `X-CSRF-Token` value.
- Error mapping records the normalized `UiError.type` (network/auth/csrf/server)
  for triage, not raw `detail` strings that may contain identifiers.

## 11. Testing Strategy

- **MockWebServer (core-testing)**: enqueue `GET /ui/sessions` fixtures (with and
  without an `is_current` row), `POST /ui/sessions/revoke` → 200 `{status:"ok"}`,
  `POST /ui/sessions/revoke_others` → 200 `{status:"ok"}`, and error responses
  (403 CSRF, 422 validation, 404, 500, timeout). Assert verbs (POST, not DELETE),
  paths (underscore in `revoke_others`), the JSON body `{session_id}` on single
  revoke, and the presence of `X-CSRF-Token` on mutations.
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - list maps and sorts; exactly one `isCurrent` row.
  - current row resolved by `getMe` id when `is_current` flag absent.
  - single revoke removes the row optimistically; rollback on failure restores
    it at the original index.
  - "revoke others" removes all non-current rows; current remains.
  - "revoke others" disabled when current session unidentifiable.
  - confirm/dismiss gating: no API call without confirmation.
- **Repository tests**: DTO→domain mapping, fallback loop for revoke-others,
  error envelope mapping (string/array/object forms).
- **Compose UI test**: current session marked badge present and asserted;
  revoke control absent on current row; confirm dialog appears and on confirm the
  row disappears (the AC "current session marked (tested)" and "revoke updates
  list").
- Coverage focus matches Acceptance Criteria; tests are deterministic (no real
  network).

## 12. Dependencies & Sequencing

- **Depends on AND-027** (`AuthApi` with `sessions(+revoke)`): provides the
  Retrofit endpoints; this ticket extends/consumes them. Hard blocker.
- **Depends on AND-029** (`getMe()` + auth state store): provides current
  `user_sub`/session id used to mark the current row. Hard blocker.
- Transitively relies on the cookie jar, CSRF interceptor, and 401-refresh
  authenticator from earlier E04 network tickets (assumed present via AND-027's
  chain).
- Blocks: none currently tracked.
- Sequencing: implement DTOs/mapper + repository first (unit + MockWebServer
  tested), then ViewModel, then Compose screen + nav wiring, then UI test.

## 13. Risks & Open Questions

- Q1: RESOLVED. `/ui/sessions` returns a per-row `is_current` boolean (not
  `current`), and `POST /ui/sessions/revoke_others` (underscore) exists. Verified
  against OpenAPI + frontend `auth.ts`/`types.ts`. The §4 fallback loop is
  therefore not required for correctness.
- Q2: RESOLVED. `GET /ui/me` returns `MeResp { user_sub, session_id, ip }`, so a
  stable current-session id IS available for the defensive fallback. (Verified:
  `types.ts: MeResp`.) Primary signal remains the list's `is_current` flag.
- Q3: OPEN. The OpenAPI does not document behavior when revoking the *current*
  session id via `POST /ui/sessions/revoke`. Keep the client-side guard (FR-6)
  and treat any `400/409` defensively; confirm with backend before relying on a
  server-side reject.
- Q4: RESOLVED/REVISED. There are **no** `device` or `location` fields in the
  payload at all; the mapper must derive the label from `user_agent` only. `ip`
  is present; `revoked_at` may be null. Mapper tolerates nulls accordingly.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer
  coverage being the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Navigating to Active sessions issues `GET /ui/sessions` and renders all
returned sessions, sorted by `last_seen_at` desc with the current session pinned
and badged. (MockWebServer + Compose UI test.)

AC-2. The current session is marked both visually ("This device" badge) and in
state (`isCurrent = true` on exactly one row), resolved via the `is_current` flag
or, as a fallback, the `getMe` `session_id`. (Unit + UI test — satisfies
"current session marked (tested)".)

AC-3. Revoking a single non-current session calls `POST /ui/sessions/revoke`
with body `{session_id}` and `X-CSRF-Token`, removes the row on success, and
rolls it back on failure. (MockWebServer + ViewModel test — satisfies "revoke
updates list".)

AC-4. "Sign out all other sessions" removes every non-current row on success and
leaves the current row intact. (ViewModel test.)

AC-5. The current row never offers single-revoke; "revoke others" is disabled
when the current session cannot be identified. (UI + unit test.)

AC-6. All revoke actions require confirmation; dismissing makes no API call.
(ViewModel test.)

AC-7. Network/CSRF/server errors surface a retryable message and leave the list
consistent (no row lost on a failed revoke). (MockWebServer test.)

## 15. Definition of Done

- `feature-account` Active sessions screen, ViewModel, repository, DTOs/mapper,
  and nav wiring implemented under `com.testlogon.android`.
- `AuthApi` session/revoke methods present (coordinated with AND-027) and used;
  no duplicate endpoint definitions.
- All AC-1…AC-7 tests green; MockWebServer, ViewModel/repository unit, and at
  least one Compose UI test included and passing in CI.
- No `session_id`/cookie/CSRF leakage in logs or telemetry; strings externalized;
  TalkBack and dynamic-type verified.
- Lint/detekt/ktlint clean; builds on `compileSdk 35` / AGP 8.7.3 / JDK 17.
- PR on `android-port` references AND-043 and links AND-027, AND-029.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **List endpoint is `GET /ui/sessions`.** VERIFIED. OpenAPI `GET /ui/sessions`
   (op `ui_sessions_ui_sessions_get`); frontend `src/api/endpoints/auth.ts:
   getSessions`.
2. **List response shape is `{ sessions: SessionInfo[] }`.** VERIFIED (shape) /
   note: the OpenAPI 200 schema is untyped `{}`, so the field contract comes from
   the frontend. Source: `src/api/endpoints/auth.ts: getSessions`
   (`api.get<{ sessions: SessionInfo[] }>`).
3. **Row field is `is_current` (boolean), not `current`.** CORRECTED. Source:
   `src/api/types.ts: SessionInfo` (`is_current: boolean`); web usage in
   `src/pages/security/Sessions.tsx` (`s.is_current`).
4. **Row IP field is `ip`, not `ip_address`.** CORRECTED. Source:
   `src/api/types.ts: SessionInfo` (`ip: string`).
5. **Last-active field is `last_seen_at`, not `last_active_at`, and is epoch
   SECONDS (number), not an ISO string.** CORRECTED. Source:
   `src/api/types.ts: SessionInfo` (`last_seen_at: number`); web multiplies by
   1000: `src/pages/security/Sessions.tsx:99` (`new Date(s.last_seen_at * 1000)`).
6. **`created_at` is epoch seconds (number), not an ISO string.** CORRECTED.
   Source: `src/api/types.ts: SessionInfo` (`created_at: number`).
7. **There is NO `device` field; label is derived from `user_agent`.** CORRECTED.
   Source: `src/api/types.ts: SessionInfo` (only `user_agent`); web derives via
   `parseUserAgent(s.user_agent)` in `src/pages/security/Sessions.tsx`.
8. **There is NO `location` field.** CORRECTED. Source: `src/api/types.ts:
   SessionInfo` (no such field); not referenced in `Sessions.tsx`.
9. **`revoked` and `revoked_at` fields exist (spec originally omitted them).**
   CORRECTED (added). Source: `src/api/types.ts: SessionInfo`
   (`revoked: boolean; revoked_at?: number`); web renders a "Revoked" badge and
   hides the revoke button on revoked rows (`Sessions.tsx:87,104`).
10. **Single revoke is `POST /ui/sessions/revoke` with JSON body
    `{ session_id }` — NOT `DELETE /ui/sessions/{id}`.** CORRECTED. Source:
    OpenAPI `POST /ui/sessions/revoke` (op `ui_sessions_revoke_ui_sessions_revoke_post`,
    requestBody object); frontend `src/api/endpoints/auth.ts: revokeSession`
    (`api.post("/ui/sessions/revoke", { session_id: sessionId })`).
11. **Revoke-others path is `POST /ui/sessions/revoke_others` (UNDERSCORE), no
    request body — NOT `revoke-others` (hyphen).** CORRECTED. Source: OpenAPI
    `POST /ui/sessions/revoke_others`; frontend `src/api/endpoints/auth.ts:
    revokeOtherSessions` (`api.post("/ui/sessions/revoke_others")`).
12. **Both revoke endpoints return 200 with `StatusResp { status: string }` —
    NOT 204, and there is NO `revoked_count`.** CORRECTED. Source: frontend
    `src/api/endpoints/auth.ts` (both typed `api.post<StatusResp>`);
    `src/api/types.ts: StatusResp` (`{ status: string }`). OpenAPI 200 schemas
    for both ops are untyped `{}`.
13. **`GET /ui/me` returns `{ user_sub, session_id, ip }`, so a current
    session_id IS available.** VERIFIED. Source: `src/api/types.ts: MeResp`;
    OpenAPI `GET /ui/me`.
14. **Transport is cookie session (`credentials: include`) + `X-CSRF-Token` from
    the `ui_csrf` cookie + optional `Authorization: Bearer`.** VERIFIED. Source:
    `src/api/client.ts` (lines ~157-171, 183 `credentials: "include"`).
15. **On 401, the client refreshes once via `POST /ui/session/refresh` then
    retries once; if refresh fails the user is logged out.** VERIFIED. Source:
    `src/api/client.ts` (`refreshSession()` + 401 branch, lines ~119-237);
    OpenAPI `POST /ui/session/refresh`.
16. **403 surfaces as a (retryable) error.** VERIFIED. Source: `src/api/client.ts`
    403 branch (lines ~239-255).
17. **Error envelope `detail` is string | `[{msg}]` | `{code,...}`.** VERIFIED.
    Source: `src/api/client.ts: normalizeErrorDetail` (lines ~66-102).
18. **Validation errors are 422 `HTTPValidationError`.** VERIFIED. Source:
    OpenAPI 422 responses on all three `/ui/sessions*` ops; schema
    `components.schemas.HTTPValidationError`.
19. **Mapper sets exactly one `isCurrent` row; "revoke others" disabled when none
    resolved.** UNVERIFIED-ASSUMPTION (Android design decision; not a web/back
    behavior). Reasonable safety guard; cite as framework/design choice.
20. **List sorted by `last_seen_at` desc with current pinned to top.**
    UNVERIFIED-ASSUMPTION (Android UX choice). The web reference does NOT sort or
    pin (`src/pages/security/Sessions.tsx` renders server order). Backend order
    is unspecified.
21. **Pull-to-refresh on the screen.** UNVERIFIED-ASSUMPTION (Android UX choice).
    Web instead auto-refetches (`refetchInterval: 30_000`, `refetchOnWindowFocus`)
    in `src/pages/security/Sessions.tsx`.
22. **Optimistic remove-with-rollback for single revoke.** UNVERIFIED-ASSUMPTION
    (Android design). Web simply invalidates/refetches the query on success
    (`Sessions.tsx` `onSuccess: invalidateQueries`); rollback is an Android
    addition, contract-compatible.
23. **Revoking the current session id is rejected server-side.**
    UNVERIFIED-ASSUMPTION. Not documented in OpenAPI; the client guard (FR-6) is
    the authoritative protection.
24. **MVVM + Hilt + StateFlow, Navigation-Compose, Material 3, Moshi
    `@Json(name=...)`.** Framework refs (Android architecture choices), not
    backend-verifiable. framework ref:
    https://developer.android.com/topic/architecture ;
    https://developer.android.com/jetpack/compose/navigation .
25. **`compileSdk 35` / AGP 8.7.3 / JDK 17 build target.** Framework ref / project
    convention (carried from DoD); not verifiable from backend sources.

### Corrections made

- C-3/4/5/6: Field names fixed — `current`→`is_current`, `ip_address`→`ip`,
  `last_active_at`→`last_seen_at`, and timestamps are epoch-second numbers (not
  ISO strings) for `created_at`/`last_seen_at`/`revoked_at`. (§1, §3 FR-2/FR-3,
  §4 model, §5, §6, §11, §14.)
- C-7/8: Removed non-existent `device` and `location` fields; label is derived
  from `user_agent`. (§3, §4, §5, §9, §13.)
- C-9: Added the `revoked`/`revoked_at` fields and the "Revoked" row state /
  revoke-button suppression. (§3 FR-2, §4 model, §5.)
- C-10: Single revoke changed from `DELETE /ui/sessions/{id}` to
  `POST /ui/sessions/revoke` with body `{session_id}`. (§4 Retrofit, §5, §14 AC-3.)
- C-11: Revoke-others path corrected `revoke-others` → `revoke_others`
  (underscore), no body. (§4 Retrofit + prose, §5.)
- C-12: Revoke responses are 200 + `StatusResp{status}`, not 204; removed the
  fictional `revoked_count`; repo `revokeOthers()` returns `Unit`. (§4, §5, §11.)
- C-fallback: De-scoped the "sequential revoke fallback if revoke_others absent"
  branch since the endpoint is verified present. (§4.)
- C-Q: Updated §13 Q1/Q2/Q4 to RESOLVED with sources; Q3 left OPEN.

### Open assumptions

- A-19 (single `isCurrent` invariant + disable revoke-others when unresolved):
  Android-side safety design; not a backend/web behavior — unverifiable from
  sources, kept as an intentional guard.
- A-20 (sort by `last_seen_at` desc + pin current): Android UX; web does not sort
  or pin and backend order is unspecified — cannot verify "correct" ordering.
- A-21 (pull-to-refresh): Android UX; web uses polling/focus refetch instead.
- A-22 (optimistic update + rollback): Android design; web uses invalidate +
  refetch. Contract-compatible but not mirrored in the reference.
- A-23 (server rejects revoking the current session id): not documented in
  OpenAPI; needs backend confirmation. Client guard does not depend on it.
- A-24/25 (Android architecture + build toolchain versions): framework/project
  conventions, outside the backend contract.

## 17. Test Plan

Test targets: **JVM** = JVM unit/Robolectric (local, no device); **MWS** =
MockWebServer contract test (JVM); **emu35** = headless AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
serial R5CX821TA9R, API 34, arm64-v8a). Prefer A15 only for real-hardware
behavior; this ticket is network/UI logic, so most cases run on JVM/emu35.

- **TC-AND-043-01** — Type: contract/MockWebServer (MWS). Target: JVM/MWS.
  Preconditions: MWS enqueues `GET /ui/sessions` → 200 with 3 rows, one
  `is_current:true`, mixed `last_seen_at`. Steps: call `SessionsRepository
  .listSessions()`. Expected: request is `GET /ui/sessions`; 3 `SessionInfo`
  mapped; epoch-second `last_seen_at`/`created_at` parsed to `Instant`; exactly
  one `isCurrent`; rows sorted `last_seen_at` desc with current pinned top.
  Traces: AC-1, AC-2.

- **TC-AND-043-02** — Type: Compose-UI. Target: emu35. Preconditions: ViewModel
  fed a fixed 3-row state (one current). Steps: render `ActiveSessionsScreen`.
  Expected: all 3 rows shown in order; current row shows "This device" badge;
  derived `user_agent` label visible; IP and relative last-seen shown.
  Traces: AC-1, AC-2.

- **TC-AND-043-03** — Type: unit (Turbine). Target: JVM. Preconditions: list
  fixture WITHOUT any `is_current:true` but one row's `session_id` equals
  `getMe().session_id` (repo `currentSessionId()`). Steps: `load()`. Expected:
  fallback resolves exactly one `isCurrent=true` by id match; no row marked when
  neither flag nor id matches and revoke-others becomes disabled.
  Traces: AC-2, AC-5.

- **TC-AND-043-04** — Type: contract/MockWebServer (MWS). Target: JVM/MWS.
  Preconditions: MWS enqueues `POST /ui/sessions/revoke` → 200 `{"status":"ok"}`.
  Steps: `repo.revoke("sess_X")`. Expected: recorded request is **POST**
  `/ui/sessions/revoke` (not DELETE), JSON body `{"session_id":"sess_X"}`,
  header `X-CSRF-Token` present; result is success `Unit`. Traces: AC-3, AC-7.

- **TC-AND-043-05** — Type: unit (Turbine). Target: JVM. Preconditions: 3-row
  state (current + 2 others); `revoke` API stubbed success. Steps:
  `requestRevoke(id)` → `confirm()`. Expected: confirm dialog target set first;
  on confirm the row is removed optimistically and stays removed on success;
  `pendingRevokeIds` cleared. Traces: AC-3, AC-6.

- **TC-AND-043-06** — Type: unit (Turbine). Target: JVM. Preconditions: same
  state; `revoke` API stubbed to fail (500). Steps: `requestRevoke(id)` →
  `confirm()`. Expected: row removed optimistically, then re-inserted at its
  ORIGINAL index on failure; retryable `UiError(type=server)` surfaced; list
  otherwise consistent (no other row lost). Traces: AC-3, AC-7.

- **TC-AND-043-07** — Type: contract/MockWebServer (MWS). Target: JVM/MWS.
  Preconditions: MWS enqueues `POST /ui/sessions/revoke_others` → 200
  `{"status":"ok"}`. Steps: `repo.revokeOthers()`. Expected: recorded request is
  **POST** `/ui/sessions/revoke_others` (underscore), **no** body, `X-CSRF-Token`
  present; result success. Traces: AC-4, AC-7.

- **TC-AND-043-08** — Type: unit (Turbine). Target: JVM. Preconditions: state
  with current + 2 others; revoke-others stubbed success. Steps:
  `requestRevokeOthers()` → `confirm()`. Expected: all non-current rows removed;
  current row remains; success message reflects locally-computed count (2).
  Traces: AC-4.

- **TC-AND-043-09** — Type: unit (Turbine). Target: JVM. Preconditions: state
  where current session is unidentifiable (no `is_current`, no id match). Steps:
  inspect derived UiState; attempt `requestRevokeOthers()`. Expected:
  revoke-others action disabled/blocked (no API call); guard prevents
  self-logout. Traces: AC-5.

- **TC-AND-043-10** — Type: Compose-UI. Target: emu35. Preconditions: state with
  current + 1 other row. Steps: assert controls; tap "Sign out" on the other
  row, confirm in dialog (revoke stubbed success). Expected: current row exposes
  NO single-revoke control; other row's revoke shows a confirm dialog; on confirm
  the row disappears. Traces: AC-5, AC-3, AC-6.

- **TC-AND-043-11** — Type: unit (Turbine). Target: JVM. Preconditions: any
  revocable state. Steps: `requestRevoke(id)` then `dismissConfirm()` (and
  `requestRevokeOthers()` then `dismissConfirm()`). Expected: NO revoke API call
  is made for either; list unchanged. Traces: AC-6.

- **TC-AND-043-12** — Type: contract/MockWebServer (MWS). Target: JVM/MWS.
  Preconditions: MWS enqueues `GET /ui/sessions` → 403 `{"detail":"Invalid CSRF
  token"}`, then on retry 200 with rows. Steps: `load()`, then user retry.
  Expected: 403 mapped to retryable `UiError(type=csrf)` "Couldn't verify your
  session, try again"; list left consistent; retry re-reads `ui_csrf` and
  succeeds. Traces: AC-7.

- **TC-AND-043-13** — Type: contract/MockWebServer (MWS). Target: JVM/MWS.
  Preconditions: MWS enqueues `POST /ui/sessions/revoke` → 404 (session already
  gone) and a separate case → 422 `HTTPValidationError`. Steps: `repo.revoke(id)`
  for each. Expected: 404/409 → drop row locally + refresh (treated as already
  gone); 422 → mapped error from `detail` (string/array/object forms all handled),
  list consistent. Traces: AC-3, AC-7.

- **TC-AND-043-14** — Type: integration (flaky-host/offline). Target: A15
  (physical device — REQUIRED: real radio toggling / true offline socket
  behavior differs from emulator). Preconditions: app pointed at dev host
  `http://18.222.237.167:8000`; device airplane mode ON (or host unreachable);
  a prior list previously rendered. Steps: open Active sessions; trigger refresh;
  re-enable network and retry. Expected: ~20s timeout surfaces an offline banner
  with Retry; last-rendered list kept and marked stale (screen not blanked); no
  auto-retry of any mutation; on reconnect, Retry repopulates the list.
  Traces: AC-7.

- **TC-AND-043-15** — Type: Compose-UI / accessibility. Target: emu35.
  Preconditions: 3-row state (one current, one revoked, one other). Steps: run
  TalkBack/semantics assertions and dynamic-type/dark-theme checks. Expected:
  each row has a merged `contentDescription` (label, IP, last-seen, current/
  revoked status, no location); revoke buttons have explicit descriptions; "This
  device" badge announced; touch targets >= 48dp; confirm dialog focus-trapped;
  layout holds at large font scale, RTL, and dark theme. Traces: AC-2, AC-5.

### Coverage matrix

| AC   | Covered by |
|------|------------|
| AC-1 | TC-01, TC-02 |
| AC-2 | TC-01, TC-02, TC-03, TC-15 |
| AC-3 | TC-04, TC-05, TC-06, TC-10, TC-13 |
| AC-4 | TC-07, TC-08 |
| AC-5 | TC-03, TC-09, TC-10, TC-15 |
| AC-6 | TC-05, TC-10, TC-11 |
| AC-7 | TC-04, TC-06, TC-07, TC-12, TC-13, TC-14 |
