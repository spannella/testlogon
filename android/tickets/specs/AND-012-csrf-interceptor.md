---
id: AND-012
title: CSRF interceptor
milestone: M1
epic: E02
priority: P0
size: S
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference:** the echo behavior lives in the reference app's `src/api/`
  layer — specifically the `api<T>()` fetch wrapper in `src/api/client.ts`
  (lines 167-171: `getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`).
  **Verified (review):** cookie name `ui_csrf` and header `X-CSRF-Token` match the
  web source exactly. Note the wrapper sets the header on *all* methods, not just
  mutating ones (see FR-3 correction and §16).
- **Backend:** FastAPI dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. CSRF is enforced on mutating routes under `/ui/*`.

## 3. Functional Requirements

FR-1. On every outbound request, the interceptor reads the `ui_csrf` cookie
value applicable to the request URL from the shared cookie jar (AND-011).

FR-2. For **mutating** requests, if a non-blank `ui_csrf` value is available, the
interceptor sets the request header `X-CSRF-Token` to exactly that value.

FR-3. "Mutating" is defined by HTTP method: `POST`, `PUT`, `PATCH`, `DELETE`.
Safe/idempotent-read methods (`GET`, `HEAD`, `OPTIONS`, `TRACE`) are **not**
modified (no header added). **Correction (review):** this is *not* a mirror of
the web client. The web reference (`src/api/client.ts:167-171`) sets
`X-CSRF-Token` on **every** request whenever the `ui_csrf` cookie is present,
regardless of HTTP method — it does **not** gate on method. The Android client
deliberately narrows this to mutating methods because the backend only enforces
CSRF on mutating routes; sending the header on safe reads is harmless on the web
but provides no value and is an intentional, defensible deviation here. See §16.

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
blank-check, or transformation. It equals the raw cookie value as OkHttp exposes
it via `Cookie.value`. **Correction (review):** the web client does **not** send
the value byte-for-byte — `src/api/client.ts:16-19` reads the cookie through a
`getCookie` helper that applies `decodeURIComponent`, so a percent-encoded cookie
is URL-*decoded* before being placed in the header. For the UUID-style tokens the
backend issues this is a no-op, so the practical contract is identical; but the
"byte-for-byte mirrors the web client" framing is inaccurate for tokens
containing `%`-escapes. OkHttp's `CookieJar`/`Cookie.value` already returns the
decoded cookie value, so reading via `loadForRequest(...).value` (as in §4.1)
matches the web client's *effective* (decoded) value. See §16.

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
  (Attributes shown are **illustrative/unverified** — `Set-Cookie` headers are not
  described by OpenAPI; the web client reads `ui_csrf` via plain `document.cookie`
  in JS (`src/api/client.ts:16`), which proves the cookie is **not** `HttpOnly`,
  but the exact `Path`/`SameSite`/`Max-Age` are assumptions. The native client
  persists whatever the server sends via AND-011's jar regardless of attribute
  nuances; `HttpOnly` is irrelevant on Android since there is no JS boundary.)

- **Outgoing mutating request after this ticket**, example
  `POST /ui/mfa/totp/verify`:
  ```
  POST /ui/mfa/totp/verify HTTP/1.1
  Cookie: ui_session=...; ui_csrf=8f3a1c2e-7b40-4d6e-9a11-0c2f6b9d4e55
  X-CSRF-Token: 8f3a1c2e-7b40-4d6e-9a11-0c2f6b9d4e55
  Content-Type: application/json

  {"challenge_id":"chal_123","totp_code":"492013"}
  ```
  The `X-CSRF-Token` header value **equals** the `ui_csrf` cookie value.
  **Correction (review):** the body field is `totp_code`, not `code`. Per
  OpenAPI `POST /ui/mfa/totp/verify` (req schema `TotpVerifyReq`), the required
  fields are `challenge_id: string` and `totp_code: string`. The body shape is
  illustrative only — this ticket never constructs it (owned by AND-019/AND-020).

- **Server rejection contract** (informational, **unverified**): a mutating
  request with a missing or mismatched `X-CSRF-Token` is expected to yield `403`.
  **Review note:** the OpenAPI spec documents **no** `403` response for any `/ui/*`
  route (mutating routes list only `200` and `422:HTTPValidationError`), so the
  exact `403` body shape cannot be confirmed from the sources — CSRF enforcement
  is FastAPI middleware that is not reflected in the per-route schema. The
  *documented* error envelope for these routes is `422` →
  `HTTPValidationError = { detail: ValidationError[] }`, where
  `ValidationError = { loc: (string|int)[], msg: string, type: string }`. Any
  `403`/`detail` mapping is owned by AND-015; this ticket's job is only to ensure
  the header is present and correct so the legitimate path does not get rejected.

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
  will be ignored and mutating calls `403`. **Resolved (review):** names verified
  against `src/api/client.ts:168-170` (`getCookie("ui_csrf")` →
  `X-CSRF-Token`); `ui_csrf` / `X-CSRF-Token` are correct. Constants are
  centralized for a one-line fix should the backend ever change them.
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
- Cookie/header names verified against the web reference (`src/api/client.ts`) and
  the OpenAPI spec before merge (done in this review — see §16).
- Code reviewed and merged to `android-port`; downstream auth/session tickets
  (AND-019/AND-020) are unblocked for mutating calls.
- A one-line note in the `core-network` README (owned by AND-007) documents the
  CSRF double-submit policy (which methods get the header, and that the value is
  sourced from the shared cookie jar).

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer.

1. **Cookie name is `ui_csrf`.** VERDICT: **Verified.** SOURCE:
   `src/api/client.ts:168` (`const csrf = getCookie("ui_csrf")`); also
   `src/api/endpoints/kycCompliance.ts:65`, `src/api/endpoints/profile.ts:157`,
   `src/stores/offlineStore.ts:48`.
2. **Echo header name is `X-CSRF-Token`.** VERDICT: **Verified.** SOURCE:
   `src/api/client.ts:170` (`headers.set("X-CSRF-Token", csrf)`); also
   `kycCompliance.ts:67`, `profile.ts:159`. (Not `X-XSRF-TOKEN`/`XSRF-TOKEN`.)
3. **Backend uses a double-submit CSRF scheme: server-set `ui_csrf` cookie is
   echoed into `X-CSRF-Token` on requests.** VERDICT: **Verified** (client side).
   SOURCE: `src/api/client.ts:167-171`. The server-side comparison itself is not
   in the sources (middleware), but the client contract — cookie value copied to
   header — is confirmed.
4. **The web client adds the CSRF header ONLY on mutating requests.** VERDICT:
   **Corrected.** SOURCE: `src/api/client.ts:167-171` adds the header on **every**
   request when the cookie is present, with **no** method check. The Android
   method-gating (POST/PUT/PATCH/DELETE only) is an intentional deviation, not a
   mirror. (Spec §1, FR-2/FR-3 amended.)
5. **The CSRF value is sent byte-for-byte verbatim, mirroring the web client.**
   VERDICT: **Corrected.** SOURCE: web `getCookie` applies `decodeURIComponent`
   (`src/api/client.ts:16-19`), so the web header is the URL-*decoded* cookie
   value, not raw bytes. OkHttp's `Cookie.value` likewise returns the decoded
   value, so reading via `loadForRequest(...).value` matches the web *effective*
   value; the "byte-for-byte" wording was inaccurate for `%`-encoded tokens.
   (FR-7 amended.) Note `kycCompliance.ts:67` also `decodeURIComponent`s.
6. **`POST /ui/session/start` returns `UiSessionStartResp` and sets cookies.**
   VERDICT: **Verified** (endpoint/response). SOURCE: OpenAPI
   `POST /ui/session/start | req=UiSessionStartReq | resp=200:UiSessionStartResp`.
   The specific `Set-Cookie` for `ui_csrf` on this route is **not** in OpenAPI
   (see #11).
7. **`POST /ui/session/finalize` exists and is a mutating `/ui/*` route.**
   VERDICT: **Verified.** SOURCE: OpenAPI
   `POST /ui/session/finalize | op=ui_session_finalize_... | req=UiSessionFinalizeReq | resp=200:`.
8. **`POST /ui/session/refresh` is the refresh route (no body), used by AND-013.**
   VERDICT: **Verified.** SOURCE: OpenAPI
   `POST /ui/session/refresh | req= | resp=200:`; frontend `refreshSession()`
   (`src/api/client.ts:121-130`) calls it with `method:"POST"`, no body,
   `credentials:"include"`.
9. **`GET /ui/me` is a non-mutating route that must NOT carry the CSRF header.**
   VERDICT: **Verified** (endpoint + method). SOURCE: OpenAPI
   `GET /ui/me | resp=200:;422:HTTPValidationError`. (Web client *does* send the
   header even here — see #4 — but the Android design correctly omits it.)
10. **`POST /ui/mfa/totp/verify` body fields.** VERDICT: **Corrected.** The spec's
    example used `code`; the real required field is `totp_code`. SOURCE: OpenAPI
    `POST /ui/mfa/totp/verify | req=TotpVerifyReq`; schema `TotpVerifyReq` =
    `{ challenge_id: string (req), totp_code: string (req) }`
    (components.schemas.TotpVerifyReq). (§5 amended.)
11. **A CSRF failure returns HTTP `403` with a FastAPI `detail` body
    (`string | [{msg}] | {code,...}`).** VERDICT: **Unverified-assumption.**
    SOURCE: no `403` response is documented for any route in
    `openapi.index.txt` (mutating `/ui/*` routes declare only `200` and
    `422:HTTPValidationError`); CSRF rejection is middleware-level and not in the
    schema. The *documented* error envelope is `422` →
    `HTTPValidationError = { detail: ValidationError[] }`,
    `ValidationError = { loc, msg, type }` (components.schemas.HTTPValidationError,
    components.schemas.ValidationError). (§5 amended to flag this.)
12. **`Set-Cookie: ui_csrf=...; Path=/; SameSite=Lax; HttpOnly=false` attributes.**
    VERDICT: **Unverified-assumption** (except non-HttpOnly). `Set-Cookie` is not
    in OpenAPI. The cookie being readable by JS via `document.cookie`
    (`src/api/client.ts:16`) proves it is **not** `HttpOnly`; `Path`/`SameSite`/
    `Max-Age` are assumptions. (§5 amended.)
13. **The interceptor must be an APPLICATION interceptor (`addInterceptor`) on the
    AND-009 singleton client, before the logging interceptor.** VERDICT:
    **Unverified-assumption** (internal cross-ticket design; AND-009 source not in
    this repo snapshot). Reasonable per OkHttp's interceptor model. SOURCE:
    framework ref — OkHttp interceptors guide
    (https://square.github.io/okhttp/features/interceptors/).
14. **`CookieJar.loadForRequest(url)` returns the cookies (with decoded values)
    that will be sent for that URL; reading it avoids re-implementing matching.**
    VERDICT: **Verified** (framework). SOURCE: framework ref — OkHttp `CookieJar`
    / `Cookie` API
    (https://square.github.io/okhttp/4.x/okhttp/okhttp3/-cookie-jar/).
15. **AND-013 401-refresh is wired via `OkHttpClient.Builder.authenticator(...)`,
    not as an interceptor, and its retry re-runs the interceptor chain.** VERDICT:
    **Unverified-assumption** for the AND-013 wiring (sibling ticket), but the
    retry-re-runs-interceptors behavior is **Verified** (framework). SOURCE:
    framework ref — OkHttp `Authenticator`
    (https://square.github.io/okhttp/4.x/okhttp/okhttp3/-authenticator/). The web
    analog (refresh-once-on-401) is at `src/api/client.ts:194-209`.
16. **`HTTPValidationError`/`ValidationError` 422 shape used in tests.** VERDICT:
    **Verified.** SOURCE: components.schemas.HTTPValidationError
    (`{ detail: ValidationError[] }`) and components.schemas.ValidationError
    (`{ loc: (string|int)[], msg: string, type: string }`, all required).

### Corrections made

- **§1 / FR-2 / FR-3:** Removed the false "matching the web client" claim about
  method gating. The web client sends `X-CSRF-Token` on **all** methods; Android's
  mutating-only gating is now documented as a deliberate deviation. (Citation #4.)
- **FR-7:** Corrected "byte-for-byte verbatim, mirrors web client" — the web
  client `decodeURIComponent`s the cookie; OkHttp `Cookie.value` is likewise
  decoded, so the design still matches the *effective* value, but the wording was
  fixed. (Citation #5.)
- **§5 example body:** `"code"` → `"totp_code"` per `TotpVerifyReq`. (Citation #10.)
- **§5 server-rejection contract:** flagged the `403`/`detail` body as unverified
  (no `403` in OpenAPI) and documented the verified `422` envelope. (Citation #11.)
- **§5 Set-Cookie example:** flagged attributes as illustrative/unverified; kept
  only the verified "not HttpOnly" fact. (Citation #12.)
- **§2 + §15 + R-1:** Fixed the web-reference path from `frontend/src/api/` to the
  actual `src/api/client.ts` and recorded that the name verification is now done.

### Open assumptions

- **CSRF-failure HTTP status/body** (Citation #11): no `403` is documented in the
  OpenAPI; the status and `detail` shape on CSRF rejection cannot be confirmed
  from the provided sources. Owned/mapped by AND-015. Confirm with backend owners.
- **`ui_csrf` cookie attributes** (Citation #12): `Path`/`SameSite`/`Max-Age` not
  observable from the sources; only "non-HttpOnly" is proven.
- **Does the backend rotate `ui_csrf` on `session/refresh`?** (spec Q-1): not
  observable from OpenAPI/frontend. Design is rotation-safe either way via
  per-request resolution (FR-6); no code change needed.
- **AND-009 / AND-011 / AND-013 internal seams** (Citations #13, #15, and the
  in-memory-mirror assumption in §6/R-2): these depend on sibling-ticket source
  not present in this snapshot. Treated as contracts to be confirmed when those
  tickets land.

## 17. Test Plan

All cases live in `core-network/src/test/...` unless marked instrumented.
IDs trace to the §14 Acceptance Criteria (AC-1..AC-8).

- **TC-AND-012-01** — Type: contract/MockWebServer. Preconditions: `MockWebServer`
  started with one enqueued `200`; cookie jar seeded with `ui_csrf=<uuid>` for the
  server URL; client built with the jar + `CsrfInterceptor`. Steps: issue
  `POST /ui/session/finalize` with a JSON body. Expected: `server.takeRequest()
  .getHeader("X-CSRF-Token") == <uuid>` (equals the seeded cookie value); request
  also carries the `ui_csrf` cookie. Traces: AC-1.

- **TC-AND-012-02** — Type: unit (parameterized). Preconditions: jar seeded with a
  token. Steps: issue one request per method in
  `{POST, PUT, PATCH, DELETE, GET, HEAD, OPTIONS}` (lower- and upper-case variants
  for at least one mutating + one safe method). Expected: header present and equal
  to token for POST/PUT/PATCH/DELETE; header `null` for GET/HEAD/OPTIONS;
  case-insensitivity confirmed (`post` treated as mutating). Traces: AC-1, AC-2.

- **TC-AND-012-03** — Type: contract/MockWebServer. Preconditions: jar seeded.
  Steps: issue `GET /ui/me`. Expected: recorded `X-CSRF-Token` is `null`; response
  passes through unmodified. Traces: AC-2.

- **TC-AND-012-04** — Type: unit. Preconditions: **empty** cookie jar (no
  `ui_csrf`), e.g. pre-login. Steps: issue `POST /ui/session/start`. Expected: no
  `X-CSRF-Token` header added; no exception thrown; `chain.proceed` invoked exactly
  once; request completes normally. Traces: AC-3.

- **TC-AND-012-05** — Type: unit. Preconditions: jar holds a blank/whitespace-only
  `ui_csrf` value. Steps: issue a `POST`. Expected: header is **not** added
  (blank-check), no crash. Traces: AC-3.

- **TC-AND-012-06** — Type: unit. Preconditions: jar seeded with cookie value
  `cookie-val`. Steps: issue a `POST` whose builder already sets
  `.header("X-CSRF-Token","caller-value")`. Expected: recorded header ==
  `caller-value` (caller wins; interceptor does not overwrite). Traces: AC-4.
  (Validates FR-4 and supports negative-test crafting.)

- **TC-AND-012-07** — Type: unit. Preconditions: jar seeded with a token containing
  characters that survive cookie storage but would change under URL transforms
  (e.g. an opaque token); also a UUID token. Steps: issue a `POST`. Expected:
  recorded header equals `Cookie.value` as returned by the jar (no extra encoding,
  no trimming beyond blank-check). Traces: AC-1, AC-5.
  (Guards FR-7 against accidental re-encoding; see §16 #5.)

- **TC-AND-012-08** — Type: unit (rotation). Preconditions: jar seeded with token
  `A`. Steps: issue `POST` #1; update the jar to token `B`; issue `POST` #2.
  Expected: request #1 header == `A`, request #2 header == `B` (per-request
  resolution against current jar state). Traces: AC-5.

- **TC-AND-012-09** — Type: integration (MockWebServer + Authenticator). 
  Preconditions: client configured with `CsrfInterceptor` **and** a stub
  `Authenticator`; jar seeded with token `A`; server enqueues `401` then `200`.
  Steps: issue a `POST`; the authenticator rotates the jar cookie to `B` and
  returns the retried request. Expected: first attempt carries `A`; the retried
  attempt re-runs the interceptor chain and carries `B`. Traces: AC-5.
  (Note: depends on AND-013; mark `@Ignore`/pending until AND-013 lands, per §12.)

- **TC-AND-012-10** — Type: integration (Hilt). Preconditions: `@HiltAndroidTest`
  harness wiring `core-network`. Steps: resolve the
  `@AppInterceptor Set<Interceptor>` and the provided `OkHttpClient`. Expected: the
  set contains **exactly one** `CsrfInterceptor`; `client.interceptors()` contains
  exactly one instance (no double registration). Traces: AC-6.

- **TC-AND-012-11** — Type: unit (ordering). Preconditions: built client.
  Steps: inspect `client.interceptors()`. Expected: index of `CsrfInterceptor` is
  **before** `HttpLoggingInterceptor`, so the logged request includes the attached
  header. Traces: AC-6.

- **TC-AND-012-12** — Type: integration (security/log redaction). Preconditions:
  `HttpLoggingInterceptor` configured with AND-009's redaction; a test log sink
  capturing emitted lines; jar seeded with a known token. Steps: issue a `POST`
  and capture debug logs. Expected: log contains an `X-CSRF-Token` line but its
  value is redacted (e.g. `██`); the raw token string never appears in any log
  line (also assert raw token absent from `Cookie`/`Set-Cookie` log lines).
  Traces: AC-7. (Security case.)

- **TC-AND-012-13** — Type: contract/MockWebServer (error path). Preconditions:
  jar seeded; server enqueues a `422` body
  `{"detail":[{"loc":["body","totp_code"],"msg":"field required","type":"missing"}]}`.
  Steps: issue `POST /ui/mfa/totp/verify`. Expected: the interceptor still
  attaches the correct `X-CSRF-Token` (it does not inspect/alter the response); the
  `422` body propagates unchanged for the error layer (AND-015) to map. Traces:
  AC-1. (Uses the real verified `HTTPValidationError` shape; see §16 #16.)

- **TC-AND-012-14** — Type: integration (offline / flaky dev host). Preconditions:
  jar seeded; `MockWebServer` configured to drop the connection / return a socket
  failure (or point client at an unreachable host). Steps: issue a `POST`.
  Expected: the interceptor adds the header before failure, calls `chain.proceed`
  exactly once, and propagates the `IOException` without wrapping or swallowing; no
  retry is performed by this layer. Traces: AC-3 (no-crash/pass-through resilience).

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 (mutating carries header == cookie) | TC-01, TC-02, TC-07, TC-13 |
| AC-2 (non-mutating: no header) | TC-02, TC-03 |
| AC-3 (no cookie → no header, no throw) | TC-04, TC-05, TC-14 |
| AC-4 (caller header preserved) | TC-06 |
| AC-5 (current jar state / rotation) | TC-07, TC-08, TC-09 |
| AC-6 (registered once, before logging) | TC-10, TC-11 |
| AC-7 (header redacted in debug logs) | TC-12 |
| AC-8 (tests pass / clean build) | all TC-01..TC-14 in CI |
