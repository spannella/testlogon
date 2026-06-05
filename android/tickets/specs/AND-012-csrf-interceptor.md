---
id: AND-012
title: CSRF interceptor
milestone: M1
epic: E02
priority: P0
size: S
status: draft
depends_on: [AND-011, AND-010, AND-009]
blocks: [AND-019, AND-020]
---

# AND-012 — CSRF interceptor

## 1. Overview & Goal

This ticket adds a single OkHttp application interceptor to the TestLogon native
Android port that mirrors the web client's CSRF protection: it reads the
`ui_csrf` cookie from the shared persistent cookie jar and, for state-changing
("mutating") requests, attaches its value as the `X-CSRF-Token` request header.

The FastAPI + DynamoDB backend uses a double-submit-cookie CSRF scheme. On the
web reference app, the server sets a `ui_csrf` cookie alongside the session
cookies during `POST /ui/session/start` / `finalize`, and the browser's JS layer
echoes that cookie value back in the `X-CSRF-Token` header on every mutating
call. The server then compares the cookie value against the header value and
rejects the request (HTTP `403`) if they disagree or the header is absent. The
native client has no browser to perform this echo automatically, so we implement
it as an interceptor on the singleton `OkHttpClient` provided by AND-009.

This is a **narrow, cross-cutting transport** ticket. It does not log in, manage
sessions, refresh tokens, or define any feature endpoint. It depends on the
persistent cookie jar (AND-011) to actually hold the `ui_csrf` cookie, and it
sits next to — but is independent of — the 401-refresh authenticator (AND-013).
Because it attaches to the shared client, it takes effect for **every** Retrofit
(AND-010) call automatically with no per-call wiring.

Scope, in one line from the backlog: *Read `ui_csrf` cookie; set `X-CSRF-Token`
header on requests (mirroring web client).*

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. All code in this ticket lives in module
  **`core-network`**.
- **Canonical package:** `com.testlogon.android` everywhere a package appears.
  Files in this ticket sit under `com.testlogon.android.core.network.csrf`.
- **Stack pins relevant here:** Kotlin 2.0.21, OkHttp **4.12.0**, Retrofit
  **2.11.0**, Hilt DI (KSP), Coroutines/Flow, JDK 17, AGP 8.7.3, Gradle 8.9,
  minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. This interceptor lives in
  `core-network`; no `feature-*` or `app` symbols may leak in.
- **Upstream dependencies:**
  - **AND-011** — the persistent `CookieJar` (EncryptedSharedPreferences/DataStore
    backed) that stores the `ui_csrf` cookie and survives process restart. This
    interceptor reads the CSRF value **from that cookie jar's view of the request
    URL**, not from a private store. Blocking.
  - **AND-009** — the singleton `OkHttpClient`. The interceptor is registered as
    an **application interceptor** (`addInterceptor`, not
    `addNetworkInterceptor`) on that exact client. Blocking.
  - **AND-010** — Retrofit is built on the same shared client, so every typed
    service call passes through this interceptor automatically.
- **Downstream / siblings:**
  - **AND-013** 401-refresh `Authenticator` — runs after this interceptor; the
    retried request is re-issued through the full interceptor chain, so the
    refreshed `ui_csrf` value is re-read and re-attached automatically. No
    coupling beyond ordering, documented here.
  - **AND-019 / AND-020** auth/session feature work (session start, MFA,
    finalize) relies on mutating calls carrying a valid CSRF header to succeed
    against the backend; those tickets are functionally blocked by this one.
- **Web reference:** the echo behavior lives in `frontend/src/api/` (request
  interceptor that copies `ui_csrf` → `X-CSRF-Token`). Header/cookie names here
  must match that source exactly: cookie `ui_csrf`, header `X-CSRF-Token`.
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. CSRF is enforced on mutating routes under `/ui/*`.

## 3. Functional Requirements

FR-1. On every outbound request, the interceptor reads the `ui_csrf` cookie
value applicable to the request URL from the shared cookie jar (AND-011).

FR-2. For **mutating** requests, if a non-blank `ui_csrf` value is available, the
interceptor sets the request header `X-CSRF-Token` to exactly that value.

FR-3. "Mutating" is defined by HTTP method: `POST`, `PUT`, `PATCH`, `DELETE`.
Safe/idempotent-read methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) are **not**
modified (no header added), matching the web client and the backend's
enforcement surface.

FR-4. If the request **already** carries an `X-CSRF-Token` header (set
explicitly by a caller), the interceptor must **not** overwrite it. The
caller-supplied value wins. (Avoids clobbering a deliberately-crafted value, e.g.
in a negative test.)

FR-5. If no `ui_csrf` cookie exists for the request URL (e.g. pre-login, or it
expired), the interceptor proceeds **without** adding the header and without
throwing. It is a pass-through; CSRF absence is the server's concern (it will
`403`), not a client crash.

FR-6. The CSRF value is resolved per request against the **current** cookie jar
state (so a value refreshed mid-session — e.g. after AND-013's refresh — is
picked up on the next call without restarting the app).

FR-7. The header value is sent verbatim — no URL-encoding, trimming beyond
blank-check, or transformation. It must equal the raw cookie value byte-for-byte.

FR-8. The interceptor is registered exactly once on the shared client and is
order-stable relative to the logging interceptor (it must run such that the
attached header is visible to debug logging, i.e. before/above logging in the
application-interceptor chain — see §4.3).

## 4. Technical Design

All production code lands in
`core-network/src/main/kotlin/com/testlogon/android/core/network/csrf/`.

### 4.1 The interceptor

```kotlin
package com.testlogon.android.core.network.csrf

import okhttp3.Cookie
import okhttp3.CookieJar
import okhttp3.Interceptor
import okhttp3.Response
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Mirrors the web client's double-submit CSRF scheme: copies the `ui_csrf`
 * cookie value into the `X-CSRF-Token` header on mutating requests.
 *
 * Registered as an APPLICATION interceptor on the shared OkHttpClient (AND-009).
 * Reads cookies from the shared persistent CookieJar (AND-011) so the value
 * reflects the current session, including post-refresh (AND-013).
 */
@Singleton
class CsrfInterceptor @Inject constructor(
    private val cookieJar: CookieJar,
) : Interceptor {

    override fun intercept(chain: Interceptor.Chain): Response {
        val original = chain.request()

        // Non-mutating, or caller already set the header → pass through untouched.
        if (!isMutating(original.method) || original.header(CSRF_HEADER) != null) {
            return chain.proceed(original)
        }

        val token = currentCsrfToken(original.url)
        if (token.isNullOrBlank()) {
            return chain.proceed(original)
        }

        val withHeader = original.newBuilder()
            .header(CSRF_HEADER, token)
            .build()
        return chain.proceed(withHeader)
    }

    private fun currentCsrfToken(url: okhttp3.HttpUrl): String? =
        cookieJar.loadForRequest(url)
            .firstOrNull { it.name == CSRF_COOKIE }
            ?.value

    private fun isMutating(method: String): Boolean =
        method.uppercase() in MUTATING_METHODS

    companion object {
        const val CSRF_COOKIE = "ui_csrf"
        const val CSRF_HEADER = "X-CSRF-Token"
        private val MUTATING_METHODS = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
```

Design notes:
- The interceptor reads cookies via the **same `CookieJar`** the client uses
  (`cookieJar.loadForRequest(url)`), so it sees exactly the cookies that will be
  sent on this request, with correct domain/path/expiry matching done by AND-011.
  This avoids re-implementing cookie matching and guarantees the header value
  matches the `Cookie` header value that goes out on the same request.
- Reading via `loadForRequest` is synchronous and cheap; AND-011's jar holds an
  in-memory mirror, so this is not a disk hit per request.

### 4.2 Hilt wiring

The interceptor is bound and contributed to the client builder in `core-network`.
AND-009 owns the `OkHttpClient` provider; this ticket adds the interceptor to the
set of application interceptors it installs. The seam is a multibinding so neither
ticket needs to know the full interceptor list.

```kotlin
package com.testlogon.android.core.network.csrf

import dagger.Binds
import dagger.Module
import dagger.hilt.InstallIn
import dagger.hilt.components.SingletonComponent
import dagger.multibindings.IntoSet
import okhttp3.Interceptor

@Module
@InstallIn(SingletonComponent::class)
abstract class CsrfModule {

    /** Contributes CsrfInterceptor to the shared client's application interceptors. */
    @Binds
    @IntoSet
    @AppInterceptor
    abstract fun bindCsrfInterceptor(impl: CsrfInterceptor): Interceptor
}
```

AND-009's `OkHttpClient` provider consumes `@AppInterceptor Set<@JvmSuppressWildcards Interceptor>`
and adds each via `addInterceptor`. If AND-009 has not yet introduced the
multibinding seam, this ticket adds the `@AppInterceptor` qualifier (in
`core-network`) and updates AND-009's provider to fold the set in; the change is
additive and order is enforced per §4.3.

### 4.3 Interceptor ordering

OkHttp application interceptors execute in registration order, outermost first.
Required order on the shared client:

1. `CsrfInterceptor` (this ticket) — attaches `X-CSRF-Token`.
2. Any other future app interceptors.
3. `HttpLoggingInterceptor` (AND-009, debug only) — last, so it logs the
   **final** outgoing request including the attached (redacted) CSRF header.

If the registration is set-based, ordering is enforced by sorting the contributed
set on an explicit priority, or by AND-009 appending the logging interceptor
**after** the contributed set. The 401-refresh `Authenticator` (AND-013) is **not**
an interceptor; it is wired via `OkHttpClient.Builder.authenticator(...)` and runs
on a `401`, re-issuing the request through this interceptor chain again — so the
refreshed CSRF value is re-attached on retry with no special handling.

### 4.4 Gradle wiring

No new third-party dependencies. `core-network/build.gradle.kts` already pulls
OkHttp (AND-009/010) and Hilt; this ticket adds only Kotlin source files and uses
the existing `dagger.multibindings` API. Test deps (`okhttp-mockwebserver`,
`junit`, `kotlinx-coroutines-test`) are already present from AND-010.

## 5. API Contract

This ticket defines **no application endpoints**. The contract it participates in
is the backend's double-submit CSRF expectation on mutating `/ui/*` routes:

- **Cookie set by server** (during session start/finalize), example
  `Set-Cookie` on `POST /ui/session/start` `200`:
  ```
  Set-Cookie: ui_csrf=8f3a1c2e-7b40-4d6e-9a11-0c2f6b9d4e55; Path=/; HttpOnly=false; SameSite=Lax
  ```
  (Native client persists this via AND-011's jar regardless of attribute parsing
  nuances; `HttpOnly` is irrelevant on Android since there is no JS boundary.)

- **Outgoing mutating request after this ticket**, example
  `POST /ui/mfa/totp/verify`:
  ```
  POST /ui/mfa/totp/verify HTTP/1.1
  Cookie: ui_session=...; ui_csrf=8f3a1c2e-7b40-4d6e-9a11-0c2f6b9d4e55
  X-CSRF-Token: 8f3a1c2e-7b40-4d6e-9a11-0c2f6b9d4e55
  Content-Type: application/json

  {"challenge_id":"chal_123","code":"492013"}
  ```
  The `X-CSRF-Token` header value **equals** the `ui_csrf` cookie value.

- **Server rejection contract** (informational): a mutating request with a
  missing or mismatched `X-CSRF-Token` yields `403` with a FastAPI `detail` body
  (`string | [{msg}] | {code,...}`). Mapping that error is owned by AND-015
  (error model); this ticket's job is to ensure the header is present and correct
  so the legitimate path does not `403`.

- **Outgoing GET** (e.g. `GET /ui/me`): **no** `X-CSRF-Token` header is added.

## 6. Data & State Management

- **No new state.** The interceptor is stateless; it derives the token per
  request from the shared `CookieJar` (AND-011), which is the single source of
  truth for the `ui_csrf` value.
- **No Room / DataStore / persistence** added here. Persistence of the cookie is
  AND-011's responsibility; this ticket only reads.
- **Threading:** `intercept` runs on OkHttp's dispatcher threads (the call's
  network thread). `cookieJar.loadForRequest` must be non-blocking-safe; AND-011
  guarantees an in-memory mirror so no suspension/disk I/O happens on the
  interceptor thread. No coroutine scope is introduced.
- **No UI state.** No `StateFlow`/`UiState` is produced; the interceptor is
  invisible to the presentation layer. The downstream effect (a successful
  mutating call) flows through `core-data`/`ApiResult` (AND-018) as usual.
- **Concurrency:** the interceptor reads but never mutates the cookie jar, so it
  is safe under concurrent calls. If AND-013 refreshes cookies concurrently, the
  next request simply reads the updated value; there is no shared mutable field
  in this class.

## 7. Error Handling & Resilience

- **Missing token:** if `ui_csrf` is absent/blank for the URL, the interceptor
  does **not** throw and does **not** add the header (FR-5). The request proceeds;
  if the server requires CSRF it returns `403`, surfaced by AND-015/AND-018.
- **No retries here.** This interceptor performs no retry or backoff; bounded
  backoff for idempotent GETs and the single 401 refresh+retry are owned by the
  shared client config (AND-009) and AND-013 respectively. A `403` from CSRF
  mismatch is **not** retried by this layer (retrying would not change the token).
- **Refresh interplay:** after AND-013 performs `POST /ui/session/refresh` and
  the server rotates `ui_csrf`, the **retried** request runs through this
  interceptor again and reads the rotated value, so the retry carries the correct
  header automatically. This is the resilience seam and is covered by a test.
- **Exception safety:** the interceptor never wraps or swallows downstream
  exceptions; it calls `chain.proceed(...)` exactly once on the (possibly
  modified) request and returns its result, preserving `IOException` /
  `HttpException` propagation for the error layer.
- **Unreliable dev host:** timeouts (~20s) are inherited from AND-009; this
  ticket adds no timeout behavior.

## 8. Security & Privacy

- **CSRF protection is the entire point** of this ticket: the double-submit echo
  prevents a forged cross-origin/cross-app request from including the secret token
  (which lives only in the cookie jar) in the header.
- **Token handling:** the `ui_csrf` value is read from the encrypted cookie jar
  (AND-011 uses EncryptedSharedPreferences/DataStore) and attached only to
  outbound requests to the configured backend. It is never logged in plaintext,
  persisted elsewhere, broadcast, or exposed to other apps.
- **Log redaction:** the `X-CSRF-Token` header (and `Cookie`/`Set-Cookie`) must be
  redacted by AND-009's `HttpLoggingInterceptor` configuration. This ticket adds
  no logging and asserts (via review/test) the header is not emitted in clear in
  debug logs.
- **No header injection risk:** the value comes from a server-set cookie parsed by
  OkHttp's cookie machinery; it is a single header field set via the typed
  `Request.Builder.header(...)`, so CRLF injection is not possible from this code.
- **Cleartext dev host:** the token does ride over plaintext HTTP on the `dev`
  flavor (`http://18.222.237.167:8000`), an accepted dev-only risk owned by
  AND-006; `staging`/`prod` are HTTPS. Documented as a known limitation, not
  introduced by this ticket.
- **Scope limiting:** because the token is attached only to mutating methods and
  only when present, it is not leaked on unrelated reads.

## 9. Accessibility & i18n

Not applicable — this is a headless transport interceptor with no UI surface, no
user-facing strings, and no rendered content. Any user-facing message resulting
from a CSRF `403` is produced by the error-mapping ticket (AND-015) and localized
by the consuming `feature-*` screen, not here.

## 10. Telemetry & Logging

- **No new analytics events.** A successful mutating request is not itself a
  telemetry event at the transport layer.
- **Debug logging** is inherited from AND-009's redacting `HttpLoggingInterceptor`;
  the `X-CSRF-Token` header appears redacted. This ticket adds no `Log`/`Timber`
  calls.
- **Diagnostic seam (optional, debug-only):** if needed during bring-up, a
  debug-only counter of "mutating request without available `ui_csrf`" could be
  added later to catch session/cookie-jar misconfiguration; it is **not** in scope
  now and would be additive. No PII (token value) may ever be included in such a
  signal.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network/src/test/...` using `MockWebServer`
and a fake/real `CookieJar`. No instrumentation required.

**T-1 (acceptance) — Mutating request carries the cookie value as the header.**
```kotlin
@Test
fun postRequest_attachesCsrfHeaderEqualToCookie() {
    val server = MockWebServer().apply { enqueue(MockResponse()); start() }
    val jar = InMemoryCookieJar()                  // or AND-011's jar under test
    val csrf = "8f3a1c2e-7b40-4d6e"
    jar.store(server.url("/"), "ui_csrf", csrf)     // seed cookie

    val client = OkHttpClient.Builder()
        .cookieJar(jar)
        .addInterceptor(CsrfInterceptor(jar))
        .build()

    client.newCall(
        Request.Builder()
            .url(server.url("/ui/session/finalize"))
            .post("{}".toRequestBody("application/json".toMediaType()))
            .build()
    ).execute().close()

    val recorded = server.takeRequest()
    assertEquals(csrf, recorded.getHeader("X-CSRF-Token"))
    server.shutdown()
}
```

**T-2 — GET request gets no CSRF header.** Same setup, a `GET /ui/me` call →
`recorded.getHeader("X-CSRF-Token")` is `null`.

**T-3 — Each mutating method is covered.** Parameterized over
`POST/PUT/PATCH/DELETE` → header present; over `GET/HEAD/OPTIONS` → header absent.

**T-4 — No cookie → no header, no crash.** Empty jar, `POST` request → request
succeeds and `X-CSRF-Token` is `null`.

**T-5 — Caller-set header is not overwritten.** A `POST` with an explicit
`.header("X-CSRF-Token","caller-value")` → recorded header equals `"caller-value"`,
not the cookie value (FR-4).

**T-6 — Value sent verbatim.** Seed a token containing URL-sensitive characters
(e.g. `a+b/c=`) → recorded header equals the raw value byte-for-byte (FR-7).

**T-7 — Reflects current jar state (post-rotation).** First `POST` sees token A;
update the jar to token B; second `POST` → header equals B (FR-6), proving
per-request resolution.

**T-8 — Hilt multibinding smoke test.** A `@HiltAndroidTest` harness asserts
`CsrfInterceptor` is contributed to `@AppInterceptor Set<Interceptor>` and that
the provided `OkHttpClient.interceptors()` contains exactly one `CsrfInterceptor`.

**T-9 — Ordering vs logging.** Assert `CsrfInterceptor` precedes
`HttpLoggingInterceptor` in `client.interceptors()` (so the logged request
includes the header) (§4.3).

Coverage target: the small surface (`CsrfInterceptor`, `CsrfModule`,
`isMutating`) ≥ 95% line-covered.

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-011** — persistent `CookieJar` must exist and hold `ui_csrf`. The
  interceptor reads from it. Blocking.
- **AND-009** — singleton `OkHttpClient` and the application-interceptor
  registration seam (`@AppInterceptor` multibinding) must accept contributed
  interceptors. Blocking.
- **AND-010** — Retrofit on the shared client (so interceptor applies to typed
  calls). Effectively required for end-to-end value, transitively present.

**Sibling (no hard order, document interplay):**
- **AND-013** 401-refresh authenticator — independent; ordering note in §4.3/§7.
  Either can merge first; if AND-013 lands first, T-7's "rotation on retry"
  behavior should be added/verified once both are present.

**Downstream (this ticket unblocks):**
- **AND-019 / AND-020** auth + session feature flows — their mutating calls
  (`session/start`, `mfa/*/begin|verify`, `session/finalize`,
  `session/refresh`) need the CSRF header to succeed.

**Sequencing within the ticket:** (1) add `@AppInterceptor` qualifier +
multibinding seam if absent; (2) implement `CsrfInterceptor`; (3) bind in
`CsrfModule` and fold into AND-009's client provider; (4) tests T-1..T-9. No
parallelizable subtasks of note.

## 13. Risks & Open Questions

- **R-1 Cookie name/header mismatch with web.** If the backend uses a different
  cookie name (`csrf_token`, `XSRF-TOKEN`) or header (`X-XSRF-TOKEN`), the header
  will be ignored and mutating calls `403`. *Mitigation:* names taken from the web
  reference and the project auth notes (`ui_csrf` / `X-CSRF-Token`); verify against
  `/openapi.json` and `frontend/src/api/` before merge. Constants are centralized
  for a one-line fix.
- **R-2 `loadForRequest` blocking on disk.** If AND-011's jar performs synchronous
  disk/crypto reads inside `loadForRequest`, this runs on the network thread.
  *Mitigation:* AND-011 must keep an in-memory mirror (its own requirement); a
  test/asserted contract that `loadForRequest` is non-blocking.
- **R-3 Interceptor ordering / double registration.** A set-based binding could
  register the interceptor twice or out of order relative to logging.
  *Mitigation:* T-8 (exactly one), T-9 (order), and explicit priority in AND-009's
  fold.
- **R-4 SameSite / path scoping.** If `ui_csrf` is scoped to a path that does not
  match `/ui/*` requests, `loadForRequest` returns nothing and no header is added.
  *Mitigation:* the interceptor uses the same jar/URL OkHttp uses for the `Cookie`
  header, so scoping is consistent; covered indirectly by integration testing in
  AND-019.
- **R-5 Method-case / custom verbs.** A lowercase or nonstandard method could slip
  past the set check. *Mitigation:* `method.uppercase()` normalization (§4.1) and
  T-3.
- **Q-1** Does the backend rotate `ui_csrf` on `session/refresh`? *Proposed:*
  assume it may; per-request resolution (FR-6) handles either case. Confirm with
  backend owners; no code change needed either way.
- **Q-2** Should non-`/ui/*` hosts (e.g. a future media/HLS host) ever receive the
  CSRF header? *Proposed:* no — gate by host if a second host is introduced; for
  now `loadForRequest` naturally returns the cookie only for the backend host, so
  cross-host leakage cannot occur.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Mutating requests (`POST/PUT/PATCH/DELETE`) include an
  `X-CSRF-Token` header whose value equals the current `ui_csrf` cookie value,
  proven by a `MockWebServer` test asserting the recorded header equals the seeded
  cookie (T-1, T-3, T-6).
- **AC-2.** Non-mutating requests (`GET/HEAD/OPTIONS`) carry **no**
  `X-CSRF-Token` header (T-2, T-3).
- **AC-3.** When no `ui_csrf` cookie applies to the request URL, the request
  proceeds with no header added and no exception thrown (T-4).
- **AC-4.** A caller-supplied `X-CSRF-Token` header is preserved and not
  overwritten by the interceptor (T-5).
- **AC-5.** The header value reflects the **current** cookie jar state on each
  request, including after the value is rotated mid-session (T-7).
- **AC-6.** The interceptor is registered exactly once on the shared
  `OkHttpClient` via Hilt and runs before the logging interceptor (T-8, T-9).
- **AC-7.** `X-CSRF-Token` is redacted in debug HTTP logs (inherited AND-009
  config; verified in review/test).
- **AC-8.** All listed unit tests pass in CI; `core-network` builds clean under
  AGP 8.7.3 / Gradle 8.9 / JDK 17 with no new lint/detekt violations.

## 15. Definition of Done

- `CsrfInterceptor` and `CsrfModule` (and the `@AppInterceptor` qualifier if not
  already added by AND-009) are implemented in `core-network` under
  `com.testlogon.android.core.network.csrf`, using cookie name `ui_csrf` and
  header `X-CSRF-Token` from shared constants.
- The interceptor is folded into AND-009's singleton `OkHttpClient` builder as an
  application interceptor, ordered before `HttpLoggingInterceptor`, registered
  exactly once; Retrofit (AND-010) calls inherit it automatically.
- Tests T-1 through T-9 are implemented and green in CI; coverage on the new
  surface ≥ 95%.
- The `X-CSRF-Token` header is confirmed redacted in debug logging; no new
  plaintext logging of the token exists.
- `./gradlew :core-network:assemble :core-network:testDebugUnitTest` passes
  locally and in CI with no new lint/detekt violations (AND-005 config).
- Cookie/header names verified against the web reference (`frontend/src/api/`) and
  `/openapi.json` before merge.
- Code reviewed and merged to `android-port`; downstream auth/session tickets
  (AND-019/AND-020) are unblocked for mutating calls.
- A one-line note in the `core-network` README (owned by AND-007) documents the
  CSRF double-submit policy (which methods get the header, and that the value is
  sourced from the shared cookie jar).
