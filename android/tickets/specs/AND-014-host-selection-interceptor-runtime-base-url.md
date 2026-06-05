---
id: AND-014
title: Host selection interceptor (runtime base URL)
milestone: M1
epic: E02
priority: P0
size: M
status: draft
depends_on: [AND-010]
blocks: [AND-016, AND-017]
---

# AND-014 — Host selection interceptor (runtime base URL)

## 1. Overview & Goal

Retrofit binds a single base URL at build time (AND-010 wires `BuildConfig.API_BASE_URL`
into the `Retrofit.Builder`). For TestLogon that is insufficient: the dev backend
(`http://18.222.237.167:8000`) is a moving, unreliable target, QA needs to point a single
build at staging/prod/local hosts, and a developer settings screen (AND-051, downstream)
must switch hosts on the fly. Re-creating the `Retrofit` instance, the `OkHttpClient`, the
cookie jar (AND-015), and every Hilt-scoped dependency on each host change is invasive and
loses session state mid-flight.

This ticket delivers a single `OkHttp` `Interceptor` — `HostSelectionInterceptor` — that
rewrites the **scheme, host, and port** of every outgoing request URL from a runtime-readable
setting, falling back to the compile-time `BuildConfig` default when no override is stored.
Retrofit keeps its placeholder base URL forever; the interceptor is the sole authority on
where bytes actually go. The goal is: **changing the stored base URL routes all subsequent
requests to the new host with no process restart, no Retrofit rebuild, and no dropped
singletons.** Path, query, and headers of each request are preserved untouched.

## 2. Context & References

- **Depends on AND-010** (Retrofit + Moshi setup): owns `NetworkModule`, the `Retrofit`
  instance, the Moshi converter, and the `BuildConfig.API_BASE_URL` constant. This ticket
  adds an interceptor to that module's `OkHttpClient`.
- **Blocks AND-016 / AND-017** (logging + CSRF/auth interceptors, error mapping): host
  selection must be the outermost rewrite so downstream interceptors and logging observe the
  effective URL.
- **Coordinates with AND-015** (persistent cookie jar): the cookie jar keys on host; §7
  defines clearing behaviour on host change.
- Stack: Kotlin 2.0.21, OkHttp 4.12, Retrofit 2.11, Moshi 1.15, Hilt (KSP), Coroutines/Flow,
  DataStore (preferences). minSdk 24, compileSdk/targetSdk 35, JDK 17.
- Module: `core-network` (`com.testlogon.android.core.network`); the override store lives in
  `core-data` (`com.testlogon.android.core.data`) so it is reusable by the settings feature.
- Web reference: `frontend/src/api/` uses a Vite-injected base URL; Android mirrors this with
  a runtime override layered over the build default.
- Default backend is **plaintext HTTP** — manifest cleartext config (AND-006) must permit the
  dev host and any user-entered host; see §8.

## 3. Functional Requirements

FR-1. Provide `HostSelectionInterceptor : Interceptor`, installed as an **application
interceptor** (not a network interceptor) on the `core-network` `OkHttpClient`.

FR-2. On every request the interceptor reads the **current** override (scheme, host, port). If
an override is present and valid, it rewrites only those three URL components of the outgoing
request; if absent, the request is forwarded unchanged (it already carries the placeholder
base URL, which equals `BuildConfig.API_BASE_URL`).

FR-3. The override value must be readable **synchronously and cheaply** inside `intercept()`
(which runs on OkHttp's dispatcher threads). The interceptor holds a volatile in-memory
snapshot; a coroutine in the providing layer keeps that snapshot in sync with DataStore.

FR-4. Changes take effect **without process restart and without rebuilding Retrofit/OkHttp**.
A request enqueued after the override is updated must hit the new host; in-flight requests are
not retargeted.

FR-5. The override is **persisted** in DataStore so it survives process death, and is exposed
as a `Flow<HostOverride?>` plus suspend mutators for the downstream settings screen.

FR-6. Setting the override to `null` (or "Reset to default") restores `BuildConfig` routing on
the next request.

FR-7. Validation: a candidate base URL string is accepted only if `HttpUrl.parse()` succeeds,
the scheme is `http` or `https`, and a non-empty host is present. Invalid input is rejected by
the mutator (it returns a typed error and does not mutate state).

FR-8. Path, query, fragment, method, body, and all headers of the original request are
preserved byte-for-byte; only `scheme`/`host`/`port` change.

## 4. Technical Design

Package `com.testlogon.android.core.network`.

```kotlin
data class HostOverride(
    val scheme: String,   // "http" | "https"
    val host: String,     // e.g. "18.222.237.167"
    val port: Int,        // explicit; -1 means "use scheme default"
)

class HostSelectionInterceptor @Inject constructor(
    private val provider: HostOverrideProvider,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()
        val override = provider.current() ?: return chain.proceed(original)
        val newUrl = original.url.newBuilder()
            .scheme(override.scheme)
            .host(override.host)
            .apply { if (override.port in 1..65535) port(override.port) }
            .build()
        return chain.proceed(original.newBuilder().url(newUrl).build())
    }
}
```

`HostOverrideProvider` is the synchronous read surface used inside `intercept()`:

```kotlin
@Singleton
class HostOverrideProvider @Inject constructor(
    private val store: HostOverrideStore,
    @ApplicationScope scope: CoroutineScope,
) {
    @Volatile private var snapshot: HostOverride? = null
    init { scope.launch { store.override.collect { snapshot = it } } }
    fun current(): HostOverride? = snapshot
}
```

The persistence + mutation surface lives in `core-data`
(`com.testlogon.android.core.data.host`):

```kotlin
interface HostOverrideStore {
    val override: Flow<HostOverride?>          // null => use BuildConfig default
    suspend fun setFromUrl(url: String): ApiResult<HostOverride>  // validates, persists
    suspend fun clear()                         // restore BuildConfig default
}
```

`DataStoreHostOverrideStore` implements it over `Preferences` DataStore (keys
`host_scheme`, `host_host`, `host_port`). `setFromUrl` parses via
`okhttp3.HttpUrl.parse(url)` (re-using OkHttp already on the classpath), enforces FR-7, and
writes the three fields atomically (`edit { }`). Returning `ApiResult` keeps the typed-result
convention from AND-010.

Hilt wiring (added to AND-010's `NetworkModule`):

```kotlin
@Provides @IntoSet @Singleton
fun provideHostSelectionInterceptor(i: HostSelectionInterceptor): Interceptor = i

@Provides @Singleton
fun provideOkHttpClient(interceptors: Set<@JvmSuppressWildcards Interceptor>): OkHttpClient =
    OkHttpClient.Builder()
        .callTimeout(20, TimeUnit.SECONDS)   // unreliable dev host (project context)
        .apply { interceptors.forEach { addInterceptor(it) } }
        .build()
```

Ordering matters: `HostSelectionInterceptor` must run **before** the CSRF/auth (AND-017) and
logging (AND-016) interceptors so they see the effective host. Because OkHttp invokes
application interceptors in add order, the provider set is materialised into an ordered list in
`NetworkModule` with host-selection first; `@IntoSet` membership alone does not guarantee
order, so the module sorts by a known priority enum or constructs the list explicitly. We
construct the list explicitly to avoid fragility.

Retrofit's base URL stays at `BuildConfig.API_BASE_URL` permanently; it is only a syntactic
seed for relative paths. No Retrofit/OkHttp rebuild ever occurs on host change — only
`snapshot` flips.

## 5. API Contract

This ticket calls **no backend endpoint**; it is transport plumbing. Its "contract" is the URL
transformation applied to every request defined by other tickets.

Transformation, given override `{scheme:"https", host:"api.testlogon.com", port:-1}` and an
outgoing request `POST http://18.222.237.167:8000/ui/session/start`:

```
in : POST http://18.222.237.167:8000/ui/session/start   body {"challenge_context":{...}}
out: POST https://api.testlogon.com/ui/session/start      body {"challenge_context":{...}}
```

Path (`/ui/session/start`), method, body, and headers (e.g. `X-CSRF-Token`) are unchanged.
Port `-1` yields the scheme default (443/80). All downstream endpoints (`/ui/session/start`,
`/ui/mfa/{totp,sms,email}/{begin,verify}`, `/ui/session/finalize`, `/ui/me`,
`/ui/session/refresh`, `/openapi.json`) inherit the rewrite identically. The DataStore record
shape persisted on disk:

```json
{ "host_scheme": "http", "host_host": "18.222.237.167", "host_port": 8000 }
```

## 6. Data & State Management

- **Source of truth:** DataStore preferences in `core-data`. Absence of all three keys ⇒
  `override == null` ⇒ `BuildConfig` default.
- **Hot path snapshot:** `HostOverrideProvider.snapshot` (`@Volatile`) gives lock-free O(1)
  reads inside `intercept()`. It is seeded on app start by collecting `store.override` on
  `@ApplicationScope`. Until the first emission arrives, `snapshot` is `null`, so the very
  first requests use the `BuildConfig` default — which is the correct fallback, so there is no
  cold-start race hazard.
- **State exposed to UI (AND-051):** `store.override: Flow<HostOverride?>` for display; a
  `StateFlow<HostSettingsUiState>` will be built in the feature ViewModel, not here.
- **Atomicity:** writes use a single `edit { }` so a reader never sees a partial override
  (e.g. new host with old port).
- **Cache/session interaction:** host change can orphan host-scoped state. On a successful
  `setFromUrl`/`clear` that changes the effective host, this ticket emits a
  `HostChanged` signal (a `SharedFlow<Unit>` on the store) that AND-015's cookie jar and the
  Room cache layer subscribe to in order to clear per-host state. This ticket owns the signal;
  consumers own their own clearing.

## 7. Error Handling & Resilience

- **Invalid input** (FR-7): `setFromUrl` returns `ApiResult.Error` with a typed
  `HostOverrideError` (`Malformed`, `UnsupportedScheme`, `EmptyHost`); no state mutation. The
  interceptor therefore can never receive a malformed override.
- **Interceptor never throws on rewrite:** `HttpUrl.newBuilder()` mutators take already-valid
  components; defensive `try/catch` around the rewrite falls back to `chain.proceed(original)`
  and logs at WARN rather than crashing a network call.
- **Unreliable host:** unchanged from project policy — `callTimeout(20s)`, bounded backoff
  retry for idempotent GETs only (owned by AND-016/AND-018), offline/stale UI states. Host
  selection does not add retries.
- **Stale session on host change:** switching hosts mid-session would send cookies/CSRF tokens
  to the wrong backend. The `HostChanged` signal (§6) triggers cookie-jar + cache clear so the
  user is effectively logged out of the old host; the auth flow restarts against the new host.
- **In-flight requests:** calls already dispatched complete against the old host (their URL was
  rewritten at dispatch). This is acceptable and documented; only subsequent calls retarget.

## 8. Security & Privacy

- **Cleartext:** the default and likely user-entered hosts are plaintext HTTP. The manifest
  `networkSecurityConfig` (AND-006) must permit cleartext for the dev host; for arbitrary
  runtime hosts, cleartext is allowed only in `debug`/QA build types. **Release builds reject
  `http` overrides** — `setFromUrl` enforces `scheme == "https"` when
  `!BuildConfig.DEBUG`, returning `UnsupportedScheme` otherwise. This prevents a release user
  from being downgraded to plaintext.
- **Credential leakage:** because cookies (AND-015) and the `X-CSRF-Token` header are
  host-bound, a host switch without clearing them would transmit one host's session secrets to
  another. The §6 `HostChanged` clear is a **security requirement**, not just hygiene.
- **No secrets persisted:** the override stores only scheme/host/port — never credentials.
- **Surface restriction:** the override mutators are reachable only from the developer/QA
  settings screen, gated to debug builds or a hidden entry in release (owned by AND-051).

## 9. Accessibility & i18n

No direct UI in this ticket. The downstream host-settings screen (AND-051) owns input fields,
content descriptions, RTL, and TalkBack support. Strings produced here are developer-facing
error identifiers (`HostOverrideError` enum), not localized end-user copy, so no
`strings.xml` entries are required. Validation failure messaging shown to QA in the settings
screen is localized by AND-051.

## 10. Telemetry & Logging

- On host change, log at INFO via the project logger (no PII):
  `host_override_changed from=<old-host> to=<new-host> reset=<bool>`. Hosts are not PII in this
  context but full URLs with query strings are never logged here.
- The interceptor logs at WARN only on the defensive rewrite-failure fallback (§7).
- No analytics event is emitted from `core-network`; if product wants a metric, the settings
  feature (AND-051) emits it. Detailed request/response logging is owned by AND-016 and must
  observe the **rewritten** URL (guaranteed by interceptor ordering, §4).

## 11. Testing Strategy

Unit tests (`core-network`, `core-testing` helpers) with **MockWebServer**:

- **T-1 (primary acceptance):** start two `MockWebServer` instances A and B. With no override,
  a request resolves to the `BuildConfig` default (A, seeded as base URL). Set the override to
  B's `url("/")`. Issue a new request and assert it is received by **B**, not A. Then `clear()`
  and assert routing returns to A. Directly satisfies the acceptance criterion.
- **T-2:** path/query/headers preserved — issue `GET /ui/me?x=1` with header
  `X-CSRF-Token: t`; assert `RecordedRequest.path == "/ui/me?x=1"` and header echoed.
- **T-3:** scheme + port rewrite — override port differs from default; assert request lands on
  the override port.
- **T-4:** `setFromUrl` validation table: valid http/https, malformed string, `ftp://`,
  empty-host → expected `ApiResult` outcomes.
- **T-5:** release-build cleartext rejection — with a test double for `BuildConfig.DEBUG ==
  false`, `http://` override returns `UnsupportedScheme`.
- **T-6:** persistence — write override, recreate `DataStoreHostOverrideStore` over the same
  test DataStore, assert `override.first()` round-trips.
- **T-7:** no-restart semantics — single `OkHttpClient`/`HostSelectionInterceptor` instance;
  flip override; both pre- and post-flip requests routed correctly with the **same** client
  object (assert identity).
- **T-8:** concurrency — flip override while requests are dispatched on a thread pool; assert
  no exception and each request routes to a valid host (no torn read).

Coverage target ≥ 90% lines on `HostSelectionInterceptor`, `HostOverrideProvider`, and
`DataStoreHostOverrideStore`. Tests use Coroutines `runTest` and a `TestDispatcher`-backed
`@ApplicationScope`.

## 12. Dependencies & Sequencing

- **Requires AND-010** (Retrofit + Moshi, `NetworkModule`, `BuildConfig.API_BASE_URL`) merged
  first — this ticket edits that module.
- **Soft-coordinates with AND-015** (cookie jar): the `HostChanged` signal is consumed there;
  AND-014 can merge first by emitting the signal with zero consumers.
- **Blocks AND-016/AND-017:** their interceptors must be added *after* host selection in the
  ordered interceptor list; sequence AND-014 → AND-016/AND-017.
- **Unblocks AND-051** (developer host-settings UI), which consumes `HostOverrideStore`.
- Sequencing: AND-010 → **AND-014** → (AND-015, AND-016, AND-017) → AND-051.

## 13. Risks & Open Questions

- **R-1 Interceptor ordering fragility:** `@IntoSet` does not guarantee order. *Mitigation:*
  build the interceptor list explicitly in `NetworkModule` (§4); add a test asserting host
  selection runs first.
- **R-2 Host-scoped session leakage** if `HostChanged` clearing is not wired (§8). *Mitigation:*
  enforce the clear in AND-015; track as a release-blocker checklist item.
- **R-3 Cleartext in release:** mitigated by the §8 https-only release rule. *Open question:*
  does QA need cleartext in a dedicated `qa` build type? Assumed yes — cleartext permitted in
  `debug` and `qa`, blocked in `release`.
- **OQ-1:** Should the override support a path prefix (e.g. hosts behind `/api`)? Current scope
  rewrites scheme/host/port only. Assumed not needed; revisit if a reverse-proxied host appears.
- **OQ-2:** Multiple named host presets vs. a single free-form override? This ticket implements
  a single override; preset management is deferred to AND-051.

## 14. Acceptance Criteria

- AC-1 (from backlog): changing the stored base URL routes **subsequent** requests to the new
  host, verified by an automated MockWebServer test (T-1).
- AC-2: with no override stored, requests route to `BuildConfig.API_BASE_URL` (T-1, T-6).
- AC-3: a host change takes effect with **no** process restart and **no** rebuild of the
  `Retrofit`/`OkHttpClient` singletons (same-instance assertion, T-7).
- AC-4: path, query, method, body, and headers are preserved across the rewrite (T-2).
- AC-5: `setFromUrl` validates input and rejects malformed/unsupported-scheme/empty-host
  values without mutating state (T-4); release builds reject `http` (T-5).
- AC-6: override persists across process death (T-6).
- AC-7: `clear()` restores `BuildConfig` routing on the next request (T-1).
- AC-8: a `HostChanged` signal is emitted on every effective host change (verified by a
  collector test).

## 15. Definition of Done

- `HostSelectionInterceptor`, `HostOverrideProvider`, `HostOverrideStore` +
  `DataStoreHostOverrideStore`, and `HostOverride`/`HostOverrideError` implemented in
  `com.testlogon.android.core.network` / `...core.data.host`.
- `NetworkModule` (AND-010) updated to install the interceptor first in an explicit ordered
  list; Retrofit base URL left at `BuildConfig.API_BASE_URL`.
- Tests T-1…T-8 implemented and green; coverage target met.
- `HostChanged` signal exposed for AND-015/cache consumers.
- Release-build cleartext rejection enforced and tested.
- KtLint/Detekt clean; KSP/Hilt graph compiles; no new public API outside `core-network`/
  `core-data` boundaries.
- Code reviewed and merged to `android-port`; downstream tickets (AND-016, AND-017, AND-051)
  reference the documented interceptor ordering and store interface.
