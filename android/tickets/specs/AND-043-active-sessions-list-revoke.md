---
id: AND-043
title: Active sessions list + revoke
milestone: M1
epic: E06
priority: P1
size: M
status: draft
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
others" path.

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
state, then a list of sessions sorted by `last_active_at` descending.

FR-2. Each row shows: device/client label (`device` or `user_agent` summarized),
approximate location/IP (`ip_address`), created time, last-active time
(relative, e.g. "2 hours ago"), and a "This device" badge when the row is the
current session.

FR-3. The current session is determined by matching the row's `session_id`
against the current session id from `getMe()` / auth store (preferred), falling
back to the boolean `current` flag in the list payload when present.

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
data class SessionInfo(
    val sessionId: String,
    val current: Boolean,
    val device: String?,        // human label, derived from user_agent if null
    val userAgent: String?,
    val ipAddress: String?,
    val location: String?,      // optional coarse geo from backend
    val createdAt: Instant,
    val lastActiveAt: Instant,
)
```

```kotlin
// core-network — extends/uses AuthApi (AND-027)
interface AuthApi {
    // ... existing start/finalize/refresh/logout/me ...
    @GET("ui/sessions")
    suspend fun getSessions(): Response<SessionListDto>

    @DELETE("ui/sessions/{sessionId}")
    suspend fun revokeSession(@Path("sessionId") sessionId: String): Response<Unit>

    @POST("ui/sessions/revoke-others")
    suspend fun revokeOtherSessions(): Response<RevokeResultDto>
}
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
    suspend fun revokeOthers(): ApiResult<Int> // count revoked
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

Current-session resolution order in the mapper: (1) `dto.current == true`,
(2) `dto.sessionId == repo.currentSessionId()`. The mapper sets exactly one
`isCurrent = true`; if neither method resolves a current row (degraded backend),
no row is marked current and "revoke others" is disabled to prevent revoking the
device's own session.

"Revoke others" prefers the single backend call `POST /ui/sessions/revoke-others`.
If that endpoint is unavailable per `/openapi.json`, fall back to issuing
sequential `revokeSession` calls for every non-current id (bounded; stop and
report on first hard failure). The repository hides this choice behind
`revokeOthers()`.

## 5. API Contract

`GET /ui/sessions` → 200:

```json
{
  "sessions": [
    {
      "session_id": "sess_01HX...",
      "current": true,
      "device": "Pixel 8 (Android 15)",
      "user_agent": "TestLogonAndroid/1.0 (Android 15; Pixel 8)",
      "ip_address": "203.0.113.7",
      "location": "Columbus, OH, US",
      "created_at": "2026-06-01T14:02:11Z",
      "last_active_at": "2026-06-05T09:31:44Z"
    }
  ]
}
```

`DELETE /ui/sessions/{session_id}` → 204 (no body) on success. Requires
`X-CSRF-Token`. Revoking the current session id is rejected here (use Logout);
treat `400/409` "cannot revoke current" as a guarded client error.

`POST /ui/sessions/revoke-others` → 200:

```json
{ "revoked_count": 3 }
```

Error envelope (FastAPI `detail`, mapped per project convention — string |
`[{msg}]` | `{code,...}`):

```json
{ "detail": "Invalid CSRF token" }
{ "detail": [{ "msg": "Session not found" }] }
{ "detail": { "code": "session_not_found", "message": "..." } }
```

Status handling: 200/204 success; 401 → authenticator refresh-once-then-retry
(transparent); 403 → CSRF/forbidden surfaced as retryable error; 404/409 on
revoke → drop the row locally and refresh (already gone); 5xx / timeout →
retryable error, list unchanged. Field names MUST be verified against
`/openapi.json`; Moshi DTOs use `@Json(name=...)` for snake_case mapping. The
exact `AuthApi` method set is owned by AND-027.

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
- Sorting/derivation happens in the mapper, not the UI: rows arrive pre-sorted
  by `lastActiveAt` desc with the current row pinned to the top regardless of
  time.

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
- Each row has a merged `contentDescription` summarizing device, location, last
  active, and current-session status (e.g. "This device, Pixel 8, Columbus OH,
  active 2 hours ago").
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
  without `current` flag), `DELETE /ui/sessions/{id}` 204, `revoke-others` 200,
  and error responses (403 CSRF, 404, 500, timeout). Assert verbs, paths, and the
  presence of `X-CSRF-Token` on mutations.
- **ViewModel unit tests** (Turbine + coroutine test rule):
  - list maps and sorts; exactly one `isCurrent` row.
  - current row resolved by `getMe` id when `current` flag absent.
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

- Q1: Does `/ui/sessions` return a `current` boolean, and does a
  `POST /ui/sessions/revoke-others` endpoint exist? Verify against
  `/openapi.json`; the fallback loop in §4 covers the latter's absence.
- Q2: Is the per-row identifier exposed as `session_id` in `/ui/me`? If `me`
  only returns `sub`, we need a stable current-session id; otherwise rely solely
  on the list's `current` flag (and disable "revoke others" if absent).
- Q3: Backend behavior when revoking the current id via `DELETE` — confirm it is
  rejected (expected) so the client guard and tests align.
- Q4: Are `location`/`device` always present? Mapper must tolerate nulls and
  derive a label from `user_agent`.
- Risk: unreliable dev host makes manual QA flaky; mitigated by MockWebServer
  coverage being the source of truth for correctness.

## 14. Acceptance Criteria

AC-1. Navigating to Active sessions issues `GET /ui/sessions` and renders all
returned sessions, sorted by last-active desc with the current session pinned and
badged. (MockWebServer + Compose UI test.)

AC-2. The current session is marked both visually ("This device" badge) and in
state (`isCurrent = true` on exactly one row), resolved via `current` flag or
`getMe` id. (Unit + UI test — satisfies "current session marked (tested)".)

AC-3. Revoking a single non-current session calls `DELETE /ui/sessions/{id}`
with `X-CSRF-Token`, removes the row on success, and rolls it back on failure.
(MockWebServer + ViewModel test — satisfies "revoke updates list".)

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
