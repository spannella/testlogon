---
id: AND-045
title: Offline/stale baseline for auth-area reads
milestone: M1
epic: E06
priority: P2
size: M
status: draft
depends_on: [AND-017, AND-018]
blocks: []
---

# AND-045 — Offline/stale baseline for auth-area reads

## 1. Overview & Goal

The dev backend (`http://18.222.237.167:8000`) is plaintext HTTP and frequently
unreachable. Today, any transient outage in the auth area (the signed-in user
profile from `GET /ui/me` and the device/session list from `GET /ui/sessions`)
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
    val identityKey: String,   // stable id from /ui/me (e.g. user id), hashed
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

`identityKey` is derived from the signed-in user id and stored in DataStore
after `GET /ui/me`. Before identity is known (first login), reads use a
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

`GET /ui/me` → 200 (cookie-authenticated, `X-CSRF-Token` echoed):
```json
{
  "id": "usr_123",
  "username": "alice",
  "email": "alice@example.com",
  "factors": ["totp", "sms"]
}
```

`GET /ui/sessions` → 200:
```json
{
  "sessions": [
    {
      "session_id": "sess_abc",
      "created_at": "2026-06-01T12:00:00Z",
      "last_seen_at": "2026-06-05T09:30:00Z",
      "user_agent": "okhttp/4.12",
      "current": true
    }
  ]
}
```

Both reads are subject to the existing 401 handling: on 401 the network layer
calls `POST /ui/session/refresh` once then retries (unchanged by this ticket).
Exact field names follow `/openapi.json`; the cache stores the verbatim
response body, so DTO drift does not break caching. Error `detail` (string |
`[{msg}]` | `{code,...}`) is mapped to `ApiError` by the existing layer before
reaching `StaleWhileRevalidate`.

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

- The cache holds authenticated profile data (username, email, factor types) and
  session metadata (user agent, timestamps). It does **not** store passwords,
  cookies, CSRF tokens, MFA secrets, or session secrets — only response bodies of
  `me`/`sessions`.
- Per-identity isolation (FR-8) prevents cross-user leakage on shared devices;
  `identityKey` is a hash of the user id, not the raw email.
- Cache cleared on logout and on identity mismatch (if `GET /ui/me` returns a
  different id than the cached `identityKey`, the old identity is purged before
  upsert).
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
  ageMs, reachable}`. Email/username/session ids are never logged.
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
