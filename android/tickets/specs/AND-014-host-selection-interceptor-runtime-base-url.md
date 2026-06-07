---
id: AND-014
title: Host selection interceptor (runtime base URL)
milestone: M1
epic: E02
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
Port `-1` yields the scheme default (443/80). All downstream endpoints inherit the rewrite
identically — verified against the backend OpenAPI index: `POST /ui/session/start`,
`POST /ui/session/finalize`, `POST /ui/session/refresh` (no request body), `GET /ui/me`, and
the MFA endpoints `POST /ui/mfa/sms/begin`, `POST /ui/mfa/sms/verify`,
`POST /ui/mfa/email/begin`, `POST /ui/mfa/email/verify`, and `POST /ui/mfa/totp/verify`.
**Correction:** TOTP has **no** `begin` endpoint — the backend exposes only
`/ui/mfa/totp/verify` (plus device-management endpoints); only `sms` and `email` have a
`begin` step. The earlier shorthand `/ui/mfa/{totp,sms,email}/{begin,verify}` was inaccurate.
`/openapi.json` is **not** a documented path in the backend spec (it is a plausible FastAPI
default but unverifiable here); it is omitted from the verified list. The DataStore record
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

## 16. Citations & Assumption Audit

Each key technical claim in this spec, its verdict, and the authoritative source pointer.
"OpenAPI" pointers refer to `reference/openapi.index.txt` / `reference/openapi.pretty.json`;
frontend pointers refer to `reference/src/...`.

1. **`POST /ui/session/start` exists and takes `UiSessionStartReq` with a `challenge_context`
   object field; responds `200:UiSessionStartResp` / `422:HTTPValidationError`.** — **Verified.**
   OpenAPI `POST /ui/session/start` (op `ui_session_start_ui_session_start_post`);
   `components.schemas.UiSessionStartReq` has property `challenge_context`
   (`type: object`, `additionalProperties: true`); `UiSessionStartResp` has
   `auth_required`, `challenge_id`, `required_factors`.
2. **`POST /ui/session/finalize` exists (`req=UiSessionFinalizeReq`).** — **Verified.**
   OpenAPI `POST /ui/session/finalize` (op `ui_session_finalize_ui_session_finalize_post`).
3. **`POST /ui/session/refresh` exists and takes no request body.** — **Verified.**
   OpenAPI `POST /ui/session/refresh` shows `req=` (empty) and `resp=200:`. Mirrors frontend
   `src/api/client.ts: refreshSession` (POST, `credentials: "include"`, no body).
4. **`GET /ui/me` exists.** — **Verified.** OpenAPI `GET /ui/me` (op `ui_me_ui_me_get`),
   `resp=200:;422:HTTPValidationError`.
5. **MFA endpoints `/ui/mfa/sms/{begin,verify}`, `/ui/mfa/email/{begin,verify}`, and
   `/ui/mfa/totp/verify` exist.** — **Verified.** OpenAPI: `POST /ui/mfa/sms/begin`,
   `POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/begin`, `POST /ui/mfa/email/verify`,
   `POST /ui/mfa/totp/verify`.
6. **TOTP has a `begin` endpoint (implied by `/ui/mfa/{totp,sms,email}/{begin,verify}`).** —
   **Corrected.** OpenAPI has **no** `/ui/mfa/totp/begin`; TOTP exposes only
   `/ui/mfa/totp/verify` (plus `/ui/mfa/totp/devices/*`). Spec §5 corrected to enumerate real
   paths and call out that only `sms`/`email` have a `begin` step.
7. **`/openapi.json` is a routable endpoint that inherits the rewrite.** —
   **Unverified-assumption.** No such path appears in `reference/openapi.index.txt` and the
   only `openapi` key in `openapi.pretty.json` is the `"openapi": "3.1.0"` version field. It is
   a plausible FastAPI default but cannot be confirmed from the sources; removed from the
   verified endpoint list in §5.
8. **The web client sends `X-CSRF-Token`, sourced from the `ui_csrf` cookie.** — **Verified.**
   `src/api/client.ts:168-170` (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
   This substantiates §5's claim that the rewrite must preserve the `X-CSRF-Token` header and
   §8's host-bound-credential reasoning.
9. **Session/credential transport is cookie-based with credentialed requests
   (`credentials: "include"`), which is why a host switch must clear host-scoped cookies
   (§6/§8 `HostChanged`).** — **Verified.** `src/api/client.ts:124,183,220`
   (`credentials: "include"`); plus `Authorization: Bearer` and `X-IMPERSONATION-TOKEN`
   headers (`client.ts:158-165`). Confirms host-bound session state exists and motivates the
   clear-on-host-change requirement.
10. **The web client layers a runtime/env base URL over relative paths (the model this ticket
    mirrors).** — **Verified.** `src/api/client.ts:7` reads `VITE_API_BASE_URL`; `withApiBase`
    (`client.ts:10-13`) prepends it to each path unless the path is already absolute. Same
    pattern duplicated in `src/api/endpoints/profile.ts:63,71-72`.
11. **OkHttp invokes application interceptors in add-order; `HttpUrl.newBuilder()` can rewrite
    scheme/host/port while preserving path/query/headers.** — **Verified (framework ref).**
    OkHttp interceptors doc: https://square.github.io/okhttp/features/interceptors/ ;
    `HttpUrl.Builder` API: https://square.github.io/okhttp/4.x/okhttp/okhttp3/-http-url/-builder/ .
12. **DataStore (Preferences) provides a `Flow` of values and atomic `edit { }` writes for the
    persisted override.** — **Verified (framework ref).** Jetpack DataStore guide:
    https://developer.android.com/topic/libraries/architecture/datastore .
13. **`@IntoSet` Hilt multibindings do not guarantee element order (motivating the explicit
    ordered list in §4/R-1).** — **Verified (framework ref).** Dagger/Hilt multibindings:
    https://dagger.dev/dev-guide/multibindings (sets are unordered).
14. **Release builds should reject cleartext `http`; manifest cleartext config gates dev/QA
    hosts (§8).** — **Unverified-assumption (project policy).** This is an Android security
    posture choice (network security config / `usesCleartextTraffic`), not derivable from the
    backend or frontend sources. Framework ref:
    https://developer.android.com/privacy-and-security/security-config . The actual default
    backend being plaintext HTTP is consistent with the project context but the release-build
    https-only rule is a decision owned here/AND-006.

### Corrections made

- **§5 endpoint enumeration:** removed the misleading `/ui/mfa/{totp,sms,email}/{begin,verify}`
  shorthand, which implied a nonexistent `/ui/mfa/totp/begin`. Replaced with the exact set of
  verified paths and an explicit note that only `sms`/`email` have a `begin` step (claim #6).
- **§5 `/openapi.json`:** removed from the "verified" endpoint list and reclassified as an
  unverifiable assumption, since it is absent from the backend OpenAPI index (claim #7).
- All other concrete API/header/transport claims were checked and left in place (cited above).

### Open assumptions

- **`/openapi.json` routability** (claim #7): not in the OpenAPI index; cannot be confirmed.
  Low impact — the interceptor rewrites *any* URL uniformly, so correctness does not depend on
  this path existing.
- **Release-build https-only enforcement and QA cleartext build type** (claim #14, §8/R-3): a
  project security decision, not verifiable from backend/frontend sources. OQ-2 (dedicated `qa`
  build type for cleartext) remains open and is assumed-yes pending product/security sign-off.
- **Exact downstream auth-header/cookie names beyond `X-CSRF-Token`/`ui_csrf`** are owned by
  AND-015/AND-017; this ticket only asserts they are host-bound (verified via claim #9) and
  must be cleared on host change.

## 17. Test Plan

Test IDs `TC-AND-014-NN`. Acceptance criteria referenced are from §14 (AC-1…AC-8). Backend
"contract" cases use MockWebServer because this ticket calls no real endpoint; where a real
response/error shape is needed (e.g. session-start validation), the documented OpenAPI shapes
(`UiSessionStartResp`, `422:HTTPValidationError`) are used as fixtures.

- **TC-AND-014-01 — Reroute to new host after override set.**
  Type: contract/MockWebServer.
  Preconditions: two MockWebServer instances A (seeded as `BuildConfig` default base URL) and B;
  single `OkHttpClient` with `HostSelectionInterceptor`; no override stored.
  Steps: (1) issue a request, assert A receives it; (2) `store.setFromUrl(B.url("/").toString())`,
  await snapshot propagation; (3) issue a new request.
  Expected: step 3 request is received by **B**, not A; A records no second request.
  Traces: AC-1, AC-2.

- **TC-AND-014-02 — `clear()` restores BuildConfig routing.**
  Type: contract/MockWebServer.
  Preconditions: continuation of TC-01 state (override → B active).
  Steps: call `store.clear()`, await propagation, issue a request.
  Expected: request routes back to A (the `BuildConfig` default); B receives nothing further.
  Traces: AC-7, AC-2.

- **TC-AND-014-03 — Path, query, method, body, and headers preserved across rewrite.**
  Type: contract/MockWebServer.
  Preconditions: override → B active.
  Steps: issue `GET /ui/me?x=1` with header `X-CSRF-Token: t` and (for a POST variant)
  `POST /ui/session/start` with body `{"challenge_context":{}}`.
  Expected: `RecordedRequest.path == "/ui/me?x=1"`, method preserved, `X-CSRF-Token: t` echoed,
  POST body byte-identical; only scheme/host/port changed to B.
  Traces: AC-4.

- **TC-AND-014-04 — Scheme and explicit port rewrite.**
  Type: contract/MockWebServer.
  Preconditions: override with B's scheme and a port differing from the default.
  Steps: issue a request.
  Expected: request lands on B's host **and** the override port; with `port == -1` the scheme
  default (80/443) is used.
  Traces: AC-1, AC-4.

- **TC-AND-014-05 — `setFromUrl` validation table.**
  Type: unit.
  Preconditions: debug build (`BuildConfig.DEBUG == true`) so http is permitted.
  Steps: call `setFromUrl` with: valid `http://h:8000`, valid `https://h`, malformed `"::::"`,
  `ftp://h`, and empty-host `"http:///path"`.
  Expected: first two → `ApiResult` success with parsed `HostOverride`; malformed → `Malformed`;
  `ftp` → `UnsupportedScheme`; empty host → `EmptyHost`; in every failure case state is **not**
  mutated (subsequent `override.first()` unchanged).
  Traces: AC-5.

- **TC-AND-014-06 — Release build rejects cleartext http.**
  Type: unit.
  Preconditions: test double / injected flag for `BuildConfig.DEBUG == false`.
  Steps: call `setFromUrl("http://h:8000")` and `setFromUrl("https://h")`.
  Expected: http → `ApiResult.Error(UnsupportedScheme)`, no mutation; https → success.
  Traces: AC-5.

- **TC-AND-014-07 — Override persists across store recreation (process-death proxy).**
  Type: integration (DataStore).
  Preconditions: temp Preferences DataStore file.
  Steps: write an override via `setFromUrl`, dispose the `DataStoreHostOverrideStore`, construct
  a new instance over the **same** DataStore file, read `override.first()`.
  Expected: scheme/host/port round-trip exactly from keys `host_scheme`/`host_host`/`host_port`.
  Traces: AC-6, AC-2.

- **TC-AND-014-08 — No-restart / same-singleton semantics.**
  Type: integration.
  Preconditions: single `OkHttpClient` and `HostSelectionInterceptor` obtained once from the
  Hilt graph (or constructed once).
  Steps: capture object identity; route a pre-flip request (to A); flip override to B; route a
  post-flip request; assert the `OkHttpClient`/interceptor references are identical (`===`) before
  and after, and no Retrofit rebuild occurred.
  Expected: pre-flip → A, post-flip → B, same client instance throughout; no rebuild.
  Traces: AC-3, AC-1.

- **TC-AND-014-09 — Concurrency: flip override under load with no torn read.**
  Type: integration.
  Preconditions: thread pool dispatching N concurrent requests; A and B servers.
  Steps: while requests are in flight, flip the override A→B repeatedly.
  Expected: no exception; every request lands on a *valid, whole* host (either fully A or fully
  B — never a mixed host/port); volatile snapshot reads are atomic.
  Traces: AC-1, AC-3.

- **TC-AND-014-10 — `HostChanged` signal emitted on every effective host change.**
  Type: unit (Flow collector).
  Preconditions: collector subscribed to the store's `HostChanged` `SharedFlow`.
  Steps: `setFromUrl(B)` (change), `setFromUrl(B)` again (same effective host), `clear()`.
  Expected: a `HostChanged` emission for the first change and for `clear()`; behavior on a
  no-op same-host set is asserted explicitly (documented: emit only on *effective* change).
  Traces: AC-8.

- **TC-AND-014-11 — Interceptor ordering: host selection runs first.**
  Type: integration.
  Preconditions: `NetworkModule` graph with host-selection + a probe interceptor standing in for
  AND-016/AND-017.
  Steps: send a request with an override active; have the probe interceptor capture the URL it
  observes.
  Expected: the probe (downstream) observes the **rewritten** host/port, proving host selection
  is added before it (R-1 mitigation).
  Traces: AC-4 (effective-URL preservation for downstream), AC-1.

- **TC-AND-014-12 — Flaky/offline host: interceptor adds no retries and surfaces failure.**
  Type: contract/MockWebServer.
  Preconditions: override → B; B configured to not respond / drop the socket.
  Steps: issue a request; observe timeout/IOException behavior.
  Expected: the call fails via the normal OkHttp timeout (`callTimeout(20s)`) or IOException;
  `HostSelectionInterceptor` does **not** swallow, retry, or re-route it. In-flight calls against
  a now-changed host complete against their dispatch-time host.
  Traces: AC-3 (no rebuild/retry side effects), AC-1.

- **TC-AND-014-13 — Defensive rewrite-failure fallback never crashes the call.**
  Type: unit.
  Preconditions: a `HostOverrideProvider` test double returning a snapshot that triggers the
  defensive `try/catch` path (simulated builder failure).
  Steps: invoke `intercept()`.
  Expected: the interceptor falls back to `chain.proceed(original)` (request proceeds unrewritten
  to the `BuildConfig` host), logs at WARN, and does not throw.
  Traces: AC-2 (BuildConfig fallback), AC-1.

- **TC-AND-014-14 — Security: host switch triggers host-scoped credential clearing.**
  Type: integration (security).
  Preconditions: a stubbed cookie-jar/cache consumer subscribed to `HostChanged`; an override
  active with simulated host-bound state (e.g. a `ui_csrf` cookie / session).
  Steps: change the effective host via `setFromUrl`.
  Expected: the `HostChanged` signal fires and the consumer's clear hook is invoked, so old-host
  cookies/CSRF are not carried to the new host (verifies the §8 security requirement at the
  signal boundary; actual jar clearing is owned/tested by AND-015).
  Traces: AC-8.

Note on accessibility: this ticket ships **no UI** (§9); content-description / TalkBack / RTL
checks are owned by the downstream host-settings screen (AND-051) and are intentionally out of
scope here. No Compose-UI or instrumented-a11y case is included for that reason.

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 reroute on override change (MockWebServer) | TC-01, TC-04, TC-08, TC-09, TC-11, TC-12, TC-13 |
| AC-2 no override → BuildConfig default | TC-01, TC-02, TC-07, TC-13 |
| AC-3 no restart / no Retrofit-OkHttp rebuild | TC-08, TC-09, TC-12 |
| AC-4 path/query/method/body/headers preserved | TC-03, TC-04, TC-11 |
| AC-5 `setFromUrl` validation; release rejects http | TC-05, TC-06 |
| AC-6 persists across process death | TC-07 |
| AC-7 `clear()` restores default | TC-02 |
| AC-8 `HostChanged` emitted on effective change | TC-10, TC-14 |
