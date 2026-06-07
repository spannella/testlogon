---
id: AND-045
title: Offline/stale baseline for auth-area reads
milestone: M1
epic: E06
priority: P2
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-017, AND-018]
blocks: []
---

# AND-045 — Offline/stale baseline for auth-area reads

## 1. Overview & Goal

The dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and frequently
unreachable. Today, any transient outage in the auth area (the signed-in
session identity from `GET /ui/me` — which returns `{user_sub, session_id, ip}`,
not a rich profile — and the device/session list from `GET /ui/sessions`)
collapses the UI into a blank error screen even when the app already fetched
valid data seconds earlier. This ticket establishes the **offline/stale
baseline** for those auth-area reads: persist the last-known-good `me` and
`sessions` payloads, surface them immediately on a cold or warm start, and
decorate the UI with a clear *stale* + *reconnecting* affordance whenever the
host is flaky.

The goal is a stale-while-revalidate read path scoped to the two auth-area
resources. When the network/backend probe (`AND-017`) reports the host is
reachable, repositories fetch fresh data and update the cache. When the host is
down or a request fails, repositories emit the cached snapshot tagged with its
freshness metadata, and the UI renders that snapshot behind a non-blocking
banner instead of an error. This is read-only resilience — no write, login,
refresh, or MFA flow is changed here.

Out of scope: caching for non-auth resources (owned by their own feature
tickets), encryption-at-rest of the cache (tracked as an open question in §13),
and any change to the cookie/CSRF session lifecycle.

## 2. Context & References

- **Repo:** `spannella/testlogon`, Android app under `android/`, branch
  `android-port`.
- **Namespace:** `com.testlogon.android`. This ticket adds
  `com.testlogon.android.core.data.cache` and entities under
  `com.testlogon.android.core.data.db`.
- **Module layering:** `app -> feature-* -> core-*`. Cache logic lives in
  `core-data`; freshness types live in `core-model`; the stale banner composable
  lives in `core-ui`. The consuming feature is `feature-account` (profile +
  sessions screens).
- **Dependencies:**
  - `AND-017` (Connectivity & backend health probe) — provides
    `Flow<BackendStatus>` used to gate revalidation and drive the reconnecting
    indicator.
  - `AND-018` (Result/ApiResult types) — provides `sealed ApiResult<T>`
    (`Success` / `Failure(ApiError)` / `NetworkError`) returned by repositories.
- **Backend reference:** OpenAPI at `/openapi.json`; web reference for the same
  reads in `frontend/src/api/endpoints/` and shared types in
  `frontend/src/api/types.ts`.
- **Stack anchors:** Room 2.6 (cache), DataStore (small prefs/metadata),
  Coroutines/Flow, Moshi 1.15, Hilt (KSP), MockWebServer for tests.

## 3. Functional Requirements

FR-1. On cold start of the account area, the profile (`me`) and session list
screens MUST render the last-known-good cached payload immediately (before any
network call completes), if a cached payload exists.

FR-2. Each auth-area read MUST be modeled as stale-while-revalidate: emit cache
first, then trigger a background revalidation against the backend when the host
is reachable per `BackendStatus`.

FR-3. When revalidation succeeds, the cache MUST be overwritten atomically and a
fresh `fetchedAt` timestamp recorded; the UI updates to a non-stale state.

FR-4. When revalidation fails (`NetworkError`, timeout, or `BackendStatus`
unreachable) but cached data exists, the UI MUST show the cached data with a
**stale indicator** and a **reconnecting** affordance — never a full-screen
error.

FR-5. When revalidation fails and **no** cached data exists, the screen MUST
fall through to the normal empty/error state (owned by `feature-account`); this
ticket does not suppress first-load errors.

FR-6. Staleness MUST be computed from `fetchedAt` against a configurable
freshness window (default 60s). Data older than the window, or fetched during a
known-unreachable period, is rendered as stale.

FR-7. A manual refresh (pull-to-refresh) MUST force revalidation regardless of
the freshness window and clear the stale indicator on success.

FR-8. Cache is per-authenticated-identity. On logout/session end the auth-area
cache for that identity MUST be cleared so a different signed-in user never sees
the prior user's cached `me`/`sessions`.

## 4. Technical Design

### 4.1 Freshness model (`core-model`)

```kotlin
package com.testlogon.android.core.model.cache

enum class Freshness { FRESH, STALE }

data class Cached<out T>(
    val value: T,
    val fetchedAt: Instant,
    val freshness: Freshness,
)

// Carries cache + live-load status for the UI layer.
data class StaleAware<out T>(
    val data: Cached<T>?,        // last-known-good, may be null on first ever load
    val refreshing: Boolean,     // a revalidation is in flight
    val reachable: Boolean,      // mirrors BackendStatus
    val lastError: ApiError? = null,
)
```

### 4.2 Room cache (`core-data`)

A single tiny table stores serialized JSON snapshots keyed by `(identityKey,
resource)`. Snapshots are stored as the raw response JSON string (Moshi
adapters reused) to avoid one table per DTO and to keep schema migrations
trivial.

```kotlin
@Entity(tableName = "auth_cache", primaryKey = ... )
data class AuthCacheEntity(
    val identityKey: String,   // hash of `user_sub` from GET /ui/me (MeResp.user_sub)
    val resource: String,      // "me" | "sessions"
    val payloadJson: String,
    val fetchedAtEpochMs: Long,
)

@Dao
interface AuthCacheDao {
    @Query("SELECT * FROM auth_cache WHERE identityKey=:id AND resource=:res")
    fun observe(id: String, res: String): Flow<AuthCacheEntity?>

    @Upsert suspend fun upsert(entity: AuthCacheEntity)

    @Query("DELETE FROM auth_cache WHERE identityKey=:id")
    suspend fun clearIdentity(id: String)
}
```

`identityKey` is derived from `MeResp.user_sub` (the only stable identity field
returned by `GET /ui/me`; `MeResp` is `{user_sub, session_id, ip}`) and stored in
DataStore after `GET /ui/me`. Before identity is known (first login), reads use a
provisional `"_pending"` key that is migrated to the real key once `me` resolves.

### 4.3 Repository wiring

The two existing auth-area repositories (`AccountRepository.me()`,
`SessionsRepository.sessions()`) are refactored to return
`Flow<StaleAware<T>>` via a shared helper:

```kotlin
class StaleWhileRevalidate @Inject constructor(
    private val dao: AuthCacheDao,
    private val backendStatus: BackendStatusProvider, // AND-017
    private val freshnessWindow: Duration = 60.seconds,
    private val clock: Clock,
)

inline fun <T> StaleWhileRevalidate.stream(
    identityKey: String,
    resource: String,
    adapter: JsonAdapter<T>,
    crossinline fetch: suspend () -> ApiResult<T>,  // AND-018
): Flow<StaleAware<T>>
```

Behavior of `stream`:
1. Emit cached snapshot (if any) with `refreshing=true` and computed
   `Freshness`.
2. If `backendStatus.current()` is reachable **or** caller forced refresh,
   invoke `fetch()`.
3. On `ApiResult.Success`, `upsert` JSON + `fetchedAt = clock.now()`, emit fresh.
4. On `Failure`/`NetworkError`, emit the existing snapshot as `STALE` with
   `lastError`, `refreshing=false`.
5. Re-trigger revalidation when `BackendStatus` transitions `unreachable ->
   reachable` (collected from the `Flow<BackendStatus>`).

### 4.4 UI (`core-ui` + `feature-account`)

A reusable banner composable:

```kotlin
@Composable
fun StaleBanner(
    freshness: Freshness,
    refreshing: Boolean,
    fetchedAt: Instant,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
)
```

It renders nothing when `FRESH && !refreshing`; shows "Showing data from
{relative time} — reconnecting…" with an indeterminate progress affordance when
`refreshing`; shows "Offline — showing last-known data" with a Retry action when
stale and not refreshing. ViewModels expose `StateFlow<AccountUiState>` /
`StateFlow<SessionsUiState>` where each state embeds the `StaleAware` fields.

## 5. API Contract

This ticket does not add or modify endpoints; it caches responses of two
existing **idempotent GETs**.

**Auth/transport (verified against `src/api/client.ts`).** Both reads go through
the shared `api()` wrapper, which sends three credentials together: an
`Authorization: Bearer <accessToken>` header (from the auth store), the cookies
(`credentials: "include"`), and — when the `ui_csrf` cookie is present — an
`X-CSRF-Token` header carrying that cookie's value. The Android port must
replicate the Bearer + cookie + CSRF combination; the earlier "cookie-only,
CSRF echoed" description was incomplete. Note: the OpenAPI index documents these
endpoints with header params `user_sub, X-SESSION-ID, X-IMPERSONATION-TOKEN`
(server-side context), not a request body.

`GET /ui/me` → 200, shape = `MeResp` (verified against
`src/api/types.ts: MeResp`). The OpenAPI index lists this endpoint with an
**empty 200 response schema** (`resp=200:`), so the authoritative shape is the
frontend DTO:
```json
{
  "user_sub": "usr_123",
  "session_id": "sess_abc",
  "ip": "203.0.113.7"
}
```
There is **no** `username`, `email`, or `factors` field on `/ui/me` — those were
fabricated in the prior draft and have been removed.

`GET /ui/sessions` → 200, shape = `{ "sessions": SessionInfo[] }` (verified
against `src/api/endpoints/auth.ts: getSessions` and `src/api/types.ts:
SessionInfo`). Timestamps are **epoch seconds (integers), not ISO strings** —
the web client renders them with `new Date(s.last_seen_at * 1000)` in
`src/pages/security/Sessions.tsx`. The current-session flag is `is_current`,
not `current`:
```json
{
  "sessions": [
    {
      "session_id": "sess_abc",
      "is_current": true,
      "created_at": 1748779200,
      "last_seen_at": 1749116400,
      "ip": "203.0.113.7",
      "user_agent": "okhttp/4.12",
      "revoked": false,
      "revoked_at": null
    }
  ]
}
```

Both reads are subject to the existing 401 handling (verified against
`src/api/client.ts`): on 401, **only if the user is already authenticated**, the
layer calls `POST /ui/session/refresh` once (which returns `StatusResp =
{status}`, not tokens), then retries the original request; an unauthenticated 401
propagates directly. A second 401 on retry triggers logout. The cache stores the
verbatim response body, so DTO drift does not break caching. A network/offline
failure surfaces from the web client as `ApiError(status=0, "Network error")`;
the Android equivalent is `ApiResult.NetworkError` (AND-018). Error `detail` is
mapped to `ApiError` by the existing layer before reaching
`StaleWhileRevalidate`. The verified `detail` shapes are: a plain string; a 422
`HTTPValidationError` array `[{loc, msg, type}]` (verified against
`components.schemas.HTTPValidationError` / `ValidationError`); or a 403
authorization object `{code, ...}` (e.g. `role_required_scope`,
`geo_blocked`) handled by `normalizeErrorDetail`/`mapAuthorizationError` in
`src/api/client.ts`.

## 6. Data & State Management

- **Persistence:** Room table `auth_cache` (rows ≤ 2 per identity). Snapshots are
  the raw JSON bodies. `fetchedAt` stored as epoch millis. Schema version bumped;
  a destructive migration is acceptable since this is a non-critical cache.
- **Metadata:** `identityKey` and the active freshness window live in DataStore
  (`authCachePrefs`), so identity survives process death before a `me` fetch.
- **State exposure:** `AccountViewModel` and `SessionsViewModel` expose
  `StateFlow<UiState>` produced by `stream(...).map { it.toUiState() }` with
  `stateIn(viewModelScope, SharingStarted.WhileSubscribed(5_000), initial)`.
- **Freshness recompute:** `Freshness` is derived at emit time and also on each
  `BackendStatus` change so a snapshot can flip `FRESH -> STALE` while the screen
  is open without a new fetch.
- **Eviction:** No size cap needed (bounded rows). Identity rows cleared on
  logout (FR-8) via `clearIdentity`.

## 7. Error Handling & Resilience

- Revalidation uses the existing OkHttp client: ~20s timeout, bounded backoff
  retry for idempotent GETs only (consistent with project policy). No retry on
  non-GET (none here).
- `NetworkError` / timeout / `BackendStatus.UNREACHABLE` → serve cache as STALE;
  never throw to the screen when cache exists.
- First-ever load with no cache and a failure → propagate the error/empty state
  to `feature-account` (FR-5); `StaleWhileRevalidate` returns
  `StaleAware(data=null, lastError=…)`.
- Reconnect storm protection: revalidation triggered by `unreachable ->
  reachable` transitions is debounced (≥2s) and de-duplicated per resource to
  avoid hammering the flaky host.
- Corrupt/undeserializable cached JSON is treated as no-cache (logged, row
  dropped), falling through to FR-5.

## 8. Security & Privacy

- The cache holds the authenticated session-identity fields from `MeResp`
  (`user_sub`, `session_id`, **`ip`**) and session metadata from `SessionInfo`
  (`ip`, `user_agent`, epoch timestamps, `is_current`, `revoked`/`revoked_at`).
  Note both responses contain **IP addresses** (a privacy-relevant field) — there
  is no `email`/`username`/`factors` in either payload (corrected from the prior
  draft). It does **not** store passwords, cookies, CSRF tokens, the Bearer
  access token, MFA secrets, or session secrets — only the response bodies of
  `me`/`sessions`.
- Per-identity isolation (FR-8) prevents cross-user leakage on shared devices;
  `identityKey` is a hash of `MeResp.user_sub` (there is no email to hash).
- Cache cleared on logout and on identity mismatch (if `GET /ui/me` returns a
  different `user_sub` than the cached `identityKey`, the old identity is purged
  before upsert).
- At-rest encryption of the Room DB is deferred (see §13). The cache is
  app-private storage (`/data/data/com.testlogon.android`), not world-readable.
- No new network surface; plaintext HTTP risk is unchanged and owned by the
  network ticket.

## 9. Accessibility & i18n

- `StaleBanner` text uses string resources (`R.string.cache_stale_offline`,
  `cache_reconnecting`, `cache_retry`) — no hardcoded copy.
- Relative-time rendering ("2 minutes ago") uses `DateUtils`/ICU formatting and
  is localized; absolute timestamps available via `contentDescription`.
- Banner exposes a `Retry` action with a touch target ≥ 48dp and a
  `contentDescription`; the reconnecting indicator announces
  `stateDescription = "reconnecting"` for TalkBack and is not conveyed by color
  alone (icon + text).
- Banner participates in the live-region semantics so screen readers announce a
  transition into the stale/reconnecting state.

## 10. Telemetry & Logging

- Structured debug logs (no PII): `cache_hit`, `cache_miss`,
  `revalidate_start/success/failure`, `served_stale`, with fields `{resource,
  ageMs, reachable}`. The cached payload's PII — `user_sub`, `session_id`, and
  the IP addresses present in `me`/`sessions` — is never logged.
- Optional analytics counters (if the analytics ticket is present): increment
  `auth_cache.served_stale` and `auth_cache.revalidate_failure` to quantify dev
  host flakiness. Behind the same analytics flag as the rest of the app; no-op if
  absent.
- Logging respects the project log gate (debug builds verbose; release minimal).

## 11. Testing Strategy

Unit (`core-data`, JVM):
- `StaleWhileRevalidate` emits cache-first then fresh on success.
- On `NetworkError`, emits cached snapshot marked `STALE` with `lastError`.
- Freshness boundary: `fetchedAt` at window edge classified correctly using a
  fake `Clock`.
- No-cache + failure → `StaleAware(data=null)` propagates error.
- `unreachable -> reachable` transition triggers a single (debounced)
  revalidation.
- `clearIdentity` removes only the target identity's rows.

Integration (`MockWebServer`, in line with AND-017's harness):
- **Primary acceptance test:** prime cache with a 200 `me`/`sessions`, then make
  the server return errors / enqueue no response (host "down"); assert the
  repository emits cached data with `Freshness.STALE` and the ViewModel state
  carries the stale indicator (FR-4, AC).
- Recovery: server returns 200 again after `BackendStatus` flips reachable;
  assert state transitions back to `FRESH`.
- Identity isolation: cache user A, simulate logout + login as user B; assert B
  never observes A's data.

UI (Compose test):
- `StaleBanner` renders nothing when fresh, shows reconnecting text when
  `refreshing`, shows offline + Retry when stale; Retry invokes callback.

## 12. Dependencies & Sequencing

- **Requires (must merge first):** `AND-017` (`Flow<BackendStatus>` /
  `BackendStatusProvider`) and `AND-018` (`ApiResult<T>`). Both are referenced
  directly by `StaleWhileRevalidate`.
- **Touches:** `core-model` (freshness types), `core-data` (Room table, DAO,
  helper, Hilt module), `core-ui` (`StaleBanner`), `feature-account`
  (ViewModels/screens consume `StaleAware`).
- **Sequencing within ticket:** (1) `core-model` types → (2) Room entity/DAO +
  Hilt → (3) `StaleWhileRevalidate` + repo wiring → (4) `StaleBanner` + screen
  integration → (5) tests. Steps 1–3 are backend-independent and testable with
  MockWebServer.
- Logout cache-clear (FR-8) hooks into the existing session-end path; coordinate
  with the auth/session ticket owning logout so `clearIdentity` is invoked.

## 13. Risks & Open Questions

- **R1 — Encryption at rest:** cache holds email + session metadata in plaintext
  Room. Acceptable for dev? Open question: adopt SQLCipher / `EncryptedFile` for
  the auth cache, or rely on app-private storage. Default: app-private, defer
  encryption to a security ticket.
- **R2 — `identityKey` before first `me`:** the `_pending` → real-id migration
  has a small window where a failed first `me` leaves a pending row. Mitigated by
  clearing `_pending` on identity resolution.
- **R3 — Freshness window value:** 60s default is a guess for the flaky dev host;
  may need tuning or making it remote-config. Configurable via DataStore today.
- **R4 — Schema/DTO drift:** storing raw JSON insulates against field renames,
  but a structural change still requires re-fetch; corrupt-cache handling (§7)
  covers it.
- **Q1:** Should `sessions` show per-row staleness or whole-list staleness?
  Assumed whole-list for M1.

## 14. Acceptance Criteria

AC-1 (source). With the host down, previously cached `me` and `sessions` data is
displayed with a visible **stale indicator**, verified by an automated
MockWebServer test that primes the cache then forces failures (no full-screen
error appears).

AC-2. On cold start with a populated cache, cached data renders before any
network response completes.

AC-3. While the host is unreachable, a **reconnecting** affordance is shown; on
recovery (BackendStatus → reachable) data revalidates and the stale indicator
clears without user action.

AC-4. Pull-to-refresh forces revalidation regardless of the freshness window.

AC-5. With no cache and a failed first load, the screen shows the normal
empty/error state (stale path does not mask first-load errors).

AC-6. After logout, a subsequent login as a different identity never displays the
prior identity's cached `me`/`sessions` (tested).

AC-7. Freshness is computed from `fetchedAt` against the configured window;
boundary classification covered by unit tests.

## 15. Definition of Done

- `core-model` freshness types, `core-data` Room cache + `StaleWhileRevalidate`
  helper + Hilt bindings, `core-ui` `StaleBanner`, and `feature-account`
  integration merged to `android-port` under `com.testlogon.android`.
- All §11 unit, integration, and Compose tests pass in CI; AC-1 acceptance test
  present and green.
- `me` and `sessions` repositories return `Flow<StaleAware<T>>`; ViewModels
  expose `StateFlow<UiState>` carrying stale/reconnecting fields.
- Logout invokes `clearIdentity`; identity-isolation test green.
- No PII in logs; lint/detekt clean; strings externalized and accessibility
  semantics present on the banner.
- Spec referenced in the PR; dependencies `AND-017`/`AND-018` confirmed merged.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and an exact source pointer.

1. **`GET /ui/me` exists as an idempotent GET.** VERIFIED. OpenAPI `GET /ui/me`
   (`op=ui_me_ui_me_get`); frontend `src/api/endpoints/auth.ts: getMe`
   (`api.get<MeResp>("/ui/me")`).
2. **`/ui/me` returns `{id, username, email, factors}`.** CORRECTED → actual
   shape is `MeResp = {user_sub: string, session_id: string, ip: string}`.
   Source: `src/api/types.ts: MeResp`. OpenAPI documents an empty 200 schema for
   this endpoint (`resp=200:`), so the frontend DTO is authoritative.
3. **`GET /ui/sessions` exists and returns `{sessions: [...]}`.** VERIFIED.
   OpenAPI `GET /ui/sessions` (`op=ui_sessions_ui_sessions_get`); frontend
   `src/api/endpoints/auth.ts: getSessions` (`api.get<{ sessions: SessionInfo[]
   }>("/ui/sessions")`).
4. **Session row fields = `{session_id, created_at, last_seen_at, user_agent,
   current}` with ISO-8601 timestamps.** CORRECTED → actual `SessionInfo =
   {session_id, is_current: boolean, created_at: number, last_seen_at: number,
   ip: string, user_agent: string, revoked: boolean, revoked_at?: number}`.
   Current-session flag is `is_current` (not `current`); timestamps are **epoch
   seconds (integers)**, not ISO strings; `ip`, `revoked`, `revoked_at` were
   omitted in the prior draft. Source: `src/api/types.ts: SessionInfo`, and
   `src/pages/security/Sessions.tsx` renders `new Date(s.last_seen_at * 1000)`
   (confirms epoch seconds) and reads `s.is_current`, `s.revoked`, `s.ip`.
5. **Auth is cookie-only with `X-CSRF-Token` echoed.** CORRECTED → the shared
   wrapper sends `Authorization: Bearer <accessToken>` (auth store) **and**
   cookies (`credentials: "include"`) **and** `X-CSRF-Token` set from the
   `ui_csrf` cookie when present. Source: `src/api/client.ts` (lines ~157–171,
   ~183). The Android port must replicate all three.
6. **On 401 the layer calls `POST /ui/session/refresh` once then retries.**
   VERIFIED with nuance: refresh-then-retry happens **only if the user is already
   authenticated**; an unauthenticated 401 propagates directly, and a 401 on
   retry triggers logout. Source: `src/api/client.ts` (lines ~194–237) and
   `refreshSession` (~121–130). OpenAPI `POST /ui/session/refresh`
   (`op=ui_session_refresh_ui_session_refresh_post`).
7. **`/ui/session/refresh` returns tokens.** CORRECTED/clarified → frontend types
   it as `StatusResp = {status: string}` and the wrapper discards the body (it
   relies on refreshed cookies). Source: `src/api/endpoints/auth.ts:
   refreshSession` (`api.post<StatusResp>(...)`); `src/api/types.ts: StatusResp`.
8. **Network/offline failure shape.** VERIFIED → web client throws
   `ApiError(status=0, "Network error")` on fetch failure; mapped to AND-018
   `ApiResult.NetworkError` in the port. Source: `src/api/client.ts` (~185–189).
9. **Error `detail` shapes (string | `[{msg}]` | `{code,...}`).** VERIFIED →
   422 = `HTTPValidationError = {detail: [{loc, msg, type}]}` (OpenAPI
   `components.schemas.HTTPValidationError` + `ValidationError`); plain-string and
   `{code,...}` authorization objects handled by `normalizeErrorDetail` /
   `mapAuthorizationError`. Source: `src/api/client.ts` (~66–102, ~34–64).
10. **Logout endpoint exists for the FR-8 cache-clear hook.** VERIFIED. OpenAPI
    `POST /ui/session/logout` (`op=ui_session_logout_...`); frontend
    `src/api/endpoints/auth.ts: logout`.
11. **Both reads are idempotent GETs safe to cache/replay.** VERIFIED — both are
    `GET` in OpenAPI index and frontend.
12. **Stack choices (Room 2.6, DataStore, Moshi 1.15, Hilt+KSP, MockWebServer).**
    UNVERIFIED-ASSUMPTION — not derivable from backend/frontend sources; standard
    Android persistence/DI/test stack (framework ref:
    https://developer.android.com/training/data-storage/room and
    https://developer.android.com/jetpack/androidx/releases/datastore). Carried
    forward from project conventions / AND-017/AND-018.
13. **Stale-while-revalidate + `BackendStatus` gating + `ApiResult<T>`.**
    UNVERIFIED-ASSUMPTION (cross-ticket) — these types are defined by AND-017 /
    AND-018, not present in this repo snapshot; their signatures here are assumed
    to match those tickets.
14. **TalkBack live-region / 48dp touch target / `stateDescription` semantics.**
    UNVERIFIED-ASSUMPTION (framework ref:
    https://developer.android.com/develop/ui/compose/accessibility and Material
    accessibility guidance). Reasonable Compose accessibility defaults.

### Corrections made

- §1, §5, §8: `/ui/me` payload corrected from the fabricated
  `{id, username, email, factors}` to the real `MeResp = {user_sub, session_id,
  ip}`.
- §5: `/ui/sessions` row corrected — `current` → `is_current`; timestamps from
  ISO strings → epoch seconds; added the real fields `ip`, `revoked`,
  `revoked_at`.
- §5: auth/transport corrected from "cookie-authenticated, CSRF echoed" to the
  verified Bearer + cookies + `X-CSRF-Token`(from `ui_csrf`) combination; added
  the verified 401-refresh precondition (authenticated-only) and the
  `StatusResp` shape of `/ui/session/refresh`; documented the verified error
  `detail` shapes and the `status=0` network-error mapping.
- §4.2: `identityKey` source corrected to `MeResp.user_sub`.
- §8: removed the claim that the cache holds `username`/`email`/`factors`; noted
  that both payloads contain **IP addresses** (privacy-relevant); corrected
  "hash of user id, not raw email" to "hash of `user_sub` (no email exists)".
- §10: telemetry PII list corrected to the fields that actually exist
  (`user_sub`, `session_id`, IPs).

### Open assumptions

- AND-017 (`Flow<BackendStatus>` / `BackendStatusProvider`) and AND-018
  (`ApiResult<T>`) APIs are assumed from their tickets — not verifiable in this
  snapshot.
- The library stack and versions (Room 2.6, Moshi 1.15, DataStore, Hilt/KSP) are
  project conventions, not backend/frontend-derivable.
- Accessibility semantics (live region, 48dp, `stateDescription`) follow Android
  framework guidance, not a verifiable in-repo contract.
- Q1 (per-row vs whole-list session staleness) remains an open product decision
  (assumed whole-list for M1, §13).

## 17. Test Plan

Test target legend: **JVM** = local JVM/Robolectric unit; **MWS** =
contract/integration with MockWebServer; **Emu35** = headless AVD `test35`
(x86_64, API 35); **A15** = physical Samsung Galaxy A15 5G (SM-A156U,
arm64-v8a, API 34). Hardware-independent UI/instrumented cases run on Emu35; ABI/
API-level differences run on A15.

- **TC-AND-045-01** — Type: unit (JVM). Target: `StaleWhileRevalidate`.
  Preconditions: empty cache; fake `Clock`; `BackendStatus.REACHABLE`; `fetch`
  returns `ApiResult.Success(MeResp("usr_1","sess_1","203.0.113.7"))`.
  Steps: collect `stream("usr_1","me", meAdapter, fetch)`. Expected: first
  emission has `data` from cache (null here) with `refreshing=true`; after fetch,
  emission carries the `MeResp`, `Freshness.FRESH`, `fetchedAt = clock.now()`,
  and the row is upserted. Traces: AC-2, AC-7.
- **TC-AND-045-02** — Type: contract/MWS. Target: `AccountRepository.me()` +
  `SessionsRepository.sessions()` against MockWebServer. Preconditions: enqueue
  200 `me` = `{user_sub,session_id,ip}` and 200 `sessions` =
  `{sessions:[{session_id,is_current,created_at,last_seen_at,ip,user_agent,revoked}]}`
  with **epoch-seconds** timestamps. Steps: collect each repo flow once. Expected:
  parsed DTOs match the real field names (`is_current`, not `current`;
  numeric timestamps); state is `FRESH`; verify request carried
  `Authorization: Bearer`, cookie, and `X-CSRF-Token`. Traces: AC-2, AC-7.
- **TC-AND-045-03** — Type: contract/MWS (primary acceptance). Target: repos +
  ViewModels. Preconditions: prime cache via a first 200, then make the server
  return 503 / enqueue no response (host "down") and `BackendStatus.UNREACHABLE`.
  Steps: re-collect after the failed revalidation. Expected: cached `me`/
  `sessions` emitted with `Freshness.STALE`, `lastError` set,
  `refreshing=false`; ViewModel `UiState` exposes the stale indicator; **no
  full-screen error**. Traces: AC-1, AC-3.
- **TC-AND-045-04** — Type: contract/MWS. Target: `StaleWhileRevalidate` recovery
  path. Preconditions: stale cache present; `BackendStatus` flips
  `UNREACHABLE → REACHABLE`; server now returns 200. Steps: emit the transition.
  Expected: a single debounced (≥2s) revalidation fires, cache overwritten
  atomically, state returns to `FRESH`, stale indicator clears without user
  action. Traces: AC-3.
- **TC-AND-045-05** — Type: unit (JVM). Target: freshness boundary. Preconditions:
  fake `Clock`; freshness window = 60s; cached `fetchedAt` exactly at 60s, 59s,
  61s old. Steps: compute `Freshness` at each. Expected: ≤ window → `FRESH`,
  > window → `STALE`; and a snapshot fetched during a known-unreachable period is
  `STALE` regardless of age. Traces: AC-7.
- **TC-AND-045-06** — Type: unit (JVM). Target: no-cache + failure. Preconditions:
  empty cache; `fetch` returns `ApiResult.NetworkError` (the `status=0` web
  equivalent). Steps: collect `stream`. Expected: emits
  `StaleAware(data=null, lastError=…, refreshing=false)`; error propagates to
  `feature-account` (not suppressed). Traces: AC-5.
- **TC-AND-045-07** — Type: unit (JVM). Target: `AuthCacheDao.clearIdentity` +
  identity isolation logic. Preconditions: rows for `identityKey(A)` and
  `identityKey(B)`. Steps: `clearIdentity(A)`. Expected: only A's `me`/`sessions`
  rows removed; B untouched. Traces: AC-6.
- **TC-AND-045-08** — Type: integration (Emu35). Target: logout → relogin as a
  different `user_sub`. Preconditions: cache populated for user A; logout invokes
  `clearIdentity`; then `GET /ui/me` returns a different `user_sub` (user B).
  Steps: complete logout then login-as-B, open account screen. Expected: B never
  sees A's cached `me`/`sessions`; identity-mismatch purge runs before upsert.
  Traces: AC-6, AC-8 (FR-8).
- **TC-AND-045-09** — Type: Compose-UI (Emu35). Target: `StaleBanner`.
  Preconditions: composable under `createComposeRule`. Steps: render with
  (a) `FRESH && !refreshing`, (b) `refreshing=true`, (c) `STALE && !refreshing`;
  tap Retry in (c). Expected: (a) renders nothing; (b) shows reconnecting text +
  indeterminate progress; (c) shows "Offline — showing last-known data" + Retry;
  Retry invokes the callback. Traces: AC-1, AC-3, AC-4.
- **TC-AND-045-10** — Type: Compose-UI / accessibility (Emu35). Target:
  `StaleBanner` semantics. Preconditions: TalkBack-style semantics assertions.
  Steps: assert in stale state. Expected: Retry has `contentDescription` and a
  touch target ≥ 48dp; reconnecting indicator exposes
  `stateDescription="reconnecting"`; banner is a live region (announces the
  fresh→stale transition); state not conveyed by color alone (icon + text);
  strings come from resources. Traces: AC-1, AC-3.
- **TC-AND-045-11** — Type: instrumented/e2e (Emu35). Target: account screen
  pull-to-refresh. Preconditions: `FRESH` cache within the freshness window.
  Steps: trigger pull-to-refresh. Expected: a forced revalidation fires
  regardless of the window; on success the stale indicator is cleared and
  `fetchedAt` updated. Traces: AC-4.
- **TC-AND-045-12** — Type: contract/MWS. Target: corrupt-cache resilience.
  Preconditions: inject an `AuthCacheEntity` whose `payloadJson` is not valid
  `MeResp`/`SessionInfo` JSON. Steps: open the screen. Expected: row treated as
  no-cache (logged, dropped), falls through to FR-5 first-load path; app does not
  crash. Traces: AC-5.
- **TC-AND-045-13** — Type: contract/MWS. Target: 401 refresh-retry pass-through.
  Preconditions: authenticated; cached data present; server returns 401 then 200
  on retry after `POST /ui/session/refresh`. Steps: collect revalidation.
  Expected: refresh called once, original GET retried, fresh data cached; an
  unauthenticated 401 instead propagates (no refresh) and, with cache present,
  serves STALE rather than a hard error. Traces: AC-1, AC-5.
- **TC-AND-045-14** — Type: instrumented/e2e (A15, physical device). Target:
  cold-start render + real flaky-host behavior on arm64/API 34. Preconditions:
  populated `auth_cache`; app killed; toggle device connectivity (airplane mode)
  to simulate the unreachable dev host. Steps: cold-launch into the account area
  offline, then restore connectivity. Expected: cached `me`/`sessions` render
  before any network response; stale + reconnecting affordance shown while
  offline; on reconnect, data revalidates and clears. Must run on **A15** to
  exercise real radio/connectivity transitions and arm64/API-34 vs x86/API-35
  parity. Traces: AC-1, AC-2, AC-3.

### Coverage matrix

| AC | Description | Covered by |
| --- | --- | --- |
| AC-1 | Host down → cached data with stale indicator, no full-screen error | TC-03, TC-09, TC-10, TC-13, TC-14 |
| AC-2 | Cold start renders cache before network completes | TC-01, TC-02, TC-14 |
| AC-3 | Reconnecting affordance + auto-revalidate on recovery | TC-03, TC-04, TC-09, TC-10, TC-14 |
| AC-4 | Pull-to-refresh forces revalidation | TC-09, TC-11 |
| AC-5 | No cache + failed first load shows normal empty/error state | TC-06, TC-12, TC-13 |
| AC-6 | Post-logout relogin never shows prior identity's cache | TC-07, TC-08 |
| AC-7 | Freshness computed from `fetchedAt` vs window (boundary) | TC-01, TC-02, TC-05 |
