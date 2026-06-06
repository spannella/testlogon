---
id: AND-018
title: Result/ApiResult types
milestone: M1
epic: E02
priority: P0
size: S
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-003]
blocks: [AND-015]
---

# AND-018 — Result/ApiResult types

## 1. Overview & Goal

This ticket defines the canonical result-carrying type used by every repository, data
source, and ViewModel in the TestLogon native Android app. The goal is a single,
exhaustive `sealed interface ApiResult<out T>` living in `core-model` that lets the data
layer return *typed* outcomes — a domain success value, a structured server-side failure,
or a transport/connectivity failure — without ever throwing across the
repository → ViewModel boundary.

`ApiResult<T>` is deliberately the *lowest common denominator* of the data layer. It is
introduced early (M1, before any feature repository exists) so that AND-015 (the
`ApiError` detail-mapping work) and every downstream `feature-*` repository build on one
agreed shape. Because the dev backend (`http://18.222.237.167:8000`) is plaintext and
flaky, the type must cleanly distinguish "the server answered with an error" from "we
never reached the server" — those two cases drive very different UI affordances (a toast
vs. an offline/retry banner) and very different retry policy (AND-016 retries
`NetworkError` on idempotent GETs only).

Scope is intentionally narrow: the sealed hierarchy, a small set of pure functional
helpers (`map`, `flatMap`, `fold`, `getOrNull`, `onSuccess`, `onFailure`, etc.), and
exhaustive unit tests. No Retrofit adapter, no error-body parsing, and no UI mapping live
here — those belong to AND-010, AND-015, and `core-ui` respectively.

## 2. Context & References

- **Module:** `core-model` (created in AND-003). This module has *no* Android framework,
  Retrofit, OkHttp, or Hilt dependencies — it is a pure Kotlin/JVM-friendly library so the
  type is trivially unit-testable and reusable by every layer.
- **Depends on:** AND-003 (Core module structure) — `core-model` must exist and be
  consumable by `app` and `core-*`.
- **Blocks:** AND-015 (API error model & detail mapping) consumes `ApiError`, which is the
  payload of `ApiResult.Failure`. Also blocks all `feature-*` repositories that return
  `ApiResult<T>`.
- **Related (not blocking):** AND-010 (Retrofit/Moshi) and a `Call`/`suspend` adapter will
  later *produce* `ApiResult` from network responses; AND-016 (retry/backoff) keys its
  retry decision off `ApiResult.NetworkError`.
- **Stack:** Kotlin 2.0.21, JDK 17. Pure Kotlin module; `kotlin-stdlib` and Coroutines
  (`kotlinx-coroutines-core`) only.
- **Web reference:** the FastAPI `detail` union (`string | [{msg}] | {code,...}`) drives
  the `ApiError` shape consumed here; full normalization is AND-015. *(Verified: the web
  client's `normalizeErrorDetail` in `src/api/client.ts` handles exactly these three forms;
  the array form items are `ValidationError {loc, msg, type}` and the object form is
  `{code, message, ...}`. See §16.)*
- **Project rule:** package base `com.testlogon.android`. All types here live under
  `com.testlogon.android.core.model.result`.

## 3. Functional Requirements

1. Provide `sealed interface ApiResult<out T>` with exactly three variants:
   - `Success<T>(data: T)` — a successful domain value.
   - `Failure(error: ApiError)` — the server responded but the response represents a
     business/HTTP error (4xx/5xx with a parseable or unparseable body).
   - `NetworkError(cause: Throwable, isTimeout: Boolean)` — the request never produced an
     HTTP response (DNS, connect, read timeout, TLS, socket closed, offline).
2. Provide `data class ApiError` as the failure payload: HTTP status, raw detail/body, and
   an optional machine-readable code (populated later by AND-015). The class must be
   constructable in this ticket with sensible defaults so tests and stubs can build it.
3. Provide pure, allocation-light transformation helpers that preserve the failure variant
   unchanged: `map`, `mapCatching`, `flatMap`, `fold`, `getOrNull`, `getOrElse`,
   `getOrDefault`, `exceptionOrNull`, `errorOrNull`, `onSuccess`, `onFailure`,
   `onNetworkError`, and boolean predicates `isSuccess` / `isFailure` /
   `isNetworkError`.
4. Provide a single `suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T>` that
   runs a block and folds thrown exceptions into the correct variant: `IOException`
   subtypes → `NetworkError` (with `isTimeout` true for `SocketTimeoutException` /
   `InterruptedIOException`); `CancellationException` is **re-thrown**, never swallowed.
   (HTTP-error → `Failure` mapping from `HttpException`-like types is wired in AND-010/015;
   this ticket provides the seam.)
5. All helpers must be `inline` where they take a lambda, and must not catch
   `CancellationException`.
6. Variants must be exhaustively matchable with `when` (no `else` branch required) — i.e.
   a `sealed interface`, not an open class.

## 4. Technical Design

Package: `com.testlogon.android.core.model.result`.

```kotlin
package com.testlogon.android.core.model.result

import kotlinx.coroutines.CancellationException
import java.io.IOException
import java.io.InterruptedIOException
import java.net.SocketTimeoutException

sealed interface ApiResult<out T> {
    data class Success<out T>(val data: T) : ApiResult<T>
    data class Failure(val error: ApiError) : ApiResult<Nothing>
    data class NetworkError(
        val cause: Throwable,
        val isTimeout: Boolean = false,
    ) : ApiResult<Nothing>
}
```

`ApiError` lives alongside it (AND-015 enriches the parsing, but the shape is fixed here):

```kotlin
package com.testlogon.android.core.model.result

/**
 * Structured representation of a server-side error response.
 *
 * @param status   HTTP status code (e.g. 401, 422, 500); 0 if unknown.
 * @param message  Best-effort user-facing message. Raw in this ticket; AND-015 normalizes.
 * @param code     Machine-readable code from FastAPI `detail.{code}` (e.g. "role_required",
 *                 "geo_blocked"); null until AND-015 populates it.
 * @param rawBody  Unparsed response body, retained for logging/diagnostics.
 */
data class ApiError(
    val status: Int = 0,
    val message: String? = null,
    val code: String? = null,
    val rawBody: String? = null,
)
```

Helpers as top-level extension functions (one file, `ApiResultExt.kt`):

```kotlin
inline fun <T, R> ApiResult<T>.map(transform: (T) -> R): ApiResult<R> = when (this) {
    is ApiResult.Success -> ApiResult.Success(transform(data))
    is ApiResult.Failure -> this
    is ApiResult.NetworkError -> this
}

inline fun <T, R> ApiResult<T>.flatMap(transform: (T) -> ApiResult<R>): ApiResult<R> =
    when (this) {
        is ApiResult.Success -> transform(data)
        is ApiResult.Failure -> this
        is ApiResult.NetworkError -> this
    }

inline fun <T> ApiResult<T>.mapCatching(transform: (T) -> T): ApiResult<T> = when (this) {
    is ApiResult.Success -> try {
        ApiResult.Success(transform(data))
    } catch (e: CancellationException) {
        throw e
    } catch (e: Throwable) {
        ApiResult.NetworkError(e, isTimeout = e.isTimeout())
    }
    else -> this
}

inline fun <T, R> ApiResult<T>.fold(
    onSuccess: (T) -> R,
    onFailure: (ApiError) -> R,
    onNetworkError: (ApiResult.NetworkError) -> R,
): R = when (this) {
    is ApiResult.Success -> onSuccess(data)
    is ApiResult.Failure -> onFailure(error)
    is ApiResult.NetworkError -> onNetworkError(this)
}

fun <T> ApiResult<T>.getOrNull(): T? = (this as? ApiResult.Success)?.data
inline fun <T> ApiResult<T>.getOrElse(default: (ApiResult<T>) -> T): T =
    if (this is ApiResult.Success) data else default(this)
fun <T> ApiResult<T>.getOrDefault(default: @UnsafeVariance T): T = getOrNull() ?: default
fun ApiResult<*>.errorOrNull(): ApiError? = (this as? ApiResult.Failure)?.error
fun ApiResult<*>.exceptionOrNull(): Throwable? = (this as? ApiResult.NetworkError)?.cause

val ApiResult<*>.isSuccess get() = this is ApiResult.Success
val ApiResult<*>.isFailure get() = this is ApiResult.Failure
val ApiResult<*>.isNetworkError get() = this is ApiResult.NetworkError

inline fun <T> ApiResult<T>.onSuccess(action: (T) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.Success) action(data) }
inline fun <T> ApiResult<T>.onFailure(action: (ApiError) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.Failure) action(error) }
inline fun <T> ApiResult<T>.onNetworkError(action: (ApiResult.NetworkError) -> Unit): ApiResult<T> =
    apply { if (this is ApiResult.NetworkError) action(this) }
```

The `apiCall` seam:

```kotlin
@PublishedApi
internal fun Throwable.isTimeout(): Boolean =
    this is SocketTimeoutException || this is InterruptedIOException

suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
    ApiResult.Success(block())
} catch (e: CancellationException) {
    throw e
} catch (e: IOException) {
    ApiResult.NetworkError(e, isTimeout = e.isTimeout())
}
// NOTE: HttpException -> ApiResult.Failure(ApiError(...)) mapping is added in AND-010/AND-015
// once Retrofit/Moshi and detail parsing exist. This ticket leaves IOException handling final.
```

**Variance:** `out T` lets `ApiResult<Cat>` be assignable to `ApiResult<Animal>`.
`Failure` and `NetworkError` carry no `T`, so they are typed `ApiResult<Nothing>`, making
them valid for any `ApiResult<T>` — the reason `map`/`flatMap` can return `this`
unchanged.

## 5. API Contract

N/A — no network endpoint is introduced or consumed by this ticket. `ApiResult` is the
*envelope* later wrapped around endpoint responses. The FastAPI `detail` contract
(`string | [{msg}] | {code,...}`) that populates `ApiError.code`/`ApiError.message` is
owned by **AND-015**; the Retrofit `suspend` call adapter that emits `ApiResult` from real
HTTP responses is owned by **AND-010**.

## 6. Data & State Management

- `ApiResult` and `ApiError` are immutable value types (`data class`), safe to pass across
  coroutine boundaries and hold in `StateFlow`.
- No persistence, Room, or DataStore involvement.
- **Usage contract (documented in KDoc, enforced by convention):**
  - Repositories return `ApiResult<DomainModel>` from `suspend` functions; they never throw
    for expected failures.
  - ViewModels typically `fold` an `ApiResult` into their `sealed interface UiState`
    (defined per-feature), e.g. `NetworkError` → `UiState.Offline`, `Failure` →
    `UiState.Error(message)`, `Success` → `UiState.Content`.
  - `map`/`flatMap` chain transformations inside repositories while preserving the original
    failure, so the failure cause/code reaches the ViewModel intact.

## 7. Error Handling & Resilience

This ticket *defines the vocabulary* used by the resilience features rather than
implementing retries.

- **Failure vs. NetworkError split** is the core resilience decision: `NetworkError`
  (no HTTP response) is the only variant AND-016 retries (idempotent GETs, bounded backoff,
  ~20s timeout). `Failure` (server answered) is never blindly retried here.
- `isTimeout` on `NetworkError` lets callers tell "host unreachable" from "host slow",
  enabling distinct copy ("You're offline" vs. "The server is taking too long").
- `CancellationException` MUST propagate (structured-concurrency correctness): it is
  re-thrown in `apiCall` and never caught by `mapCatching`. A unit test asserts this.
- Helpers never throw for the failure variants; `map` over a `Failure` returns the same
  `Failure`. Only `mapCatching` may convert a thrown transform exception into
  `NetworkError`.

## 8. Security & Privacy

- `ApiError.rawBody` may contain server diagnostics; it is retained for logging only and
  MUST NOT be surfaced verbatim in UI (AND-015 produces the user-facing message).
- `NetworkError.cause` may carry a `Throwable` whose message includes the host/IP
  (`18.222.237.167`); telemetry (Section 10) must log the exception *type* and a redacted
  message, not the full stack with URLs/cookies.
- No credentials, cookies, CSRF tokens, or PII are stored in these types. Auth state lives
  in the cookie jar (AND-011), not in `ApiResult`.
- Pure module — no permissions, no I/O, no reflection-based serialization.

## 9. Accessibility & i18n

N/A for this ticket — no UI is produced. Note for downstream owners: `ApiError.message`
created here is a raw, non-localized string; user-facing localized copy is the
responsibility of AND-015 (message normalization) and `core-ui` (string resources). The
`code` field exists precisely so the UI layer can choose a localized string by code rather
than displaying server English.

## 10. Telemetry & Logging

- No logging dependency is added to `core-model` (it stays Android-free). Instead, the type
  is designed to be *loggable by callers*: `ApiError.status`/`code` and
  `NetworkError.cause::class.simpleName` + `isTimeout` are the recommended fields for the
  data-layer interceptor/Timber tree introduced in AND-009 to emit.
- Recommended structured log keys for downstream use:
  `result_variant` (`success|failure|network_error`), `http_status`, `error_code`,
  `is_timeout`, `exception_type`. Documented in KDoc; not implemented here.

## 11. Testing Strategy

Unit tests in `core-model/src/test` (JUnit + kotlin-test/Truth; coroutines-test for
`apiCall`). Target ~100% line coverage of `ApiResultExt.kt` and `apiCall`.

- `map` over `Success` transforms data; over `Failure` and `NetworkError` returns the same
  instance unchanged (identity-asserted).
- `flatMap` chains on `Success`; short-circuits on `Failure`/`NetworkError`.
- `fold` dispatches to the correct branch for all three variants.
- `getOrNull` / `getOrElse` / `getOrDefault` return data on `Success`, fallback otherwise.
- `errorOrNull` returns the `ApiError` only on `Failure`; `exceptionOrNull` returns the
  cause only on `NetworkError`.
- `onSuccess`/`onFailure`/`onNetworkError` invoke the action only for the matching variant
  and return the receiver.
- `mapCatching` converts a thrown `RuntimeException` to `NetworkError`, but **re-throws**
  `CancellationException`.
- `apiCall`:
  - returns `Success` for a normal block;
  - returns `NetworkError(isTimeout = true)` for a thrown `SocketTimeoutException`;
  - returns `NetworkError(isTimeout = false)` for a generic `IOException`;
  - re-throws `CancellationException` (asserted via `assertFailsWith`).
- Variance compile test: `val a: ApiResult<Animal> = ApiResult.Success(Cat())` compiles;
  a `Failure` is assignable to `ApiResult<String>` and `ApiResult<Int>`.
- `when` exhaustiveness: a test `fun` matches all three variants with no `else` and
  compiles (regression guard against a fourth variant being added without test updates).

## 12. Dependencies & Sequencing

- **Requires (blocking):** AND-003 — `core-model` module must exist with namespace
  `com.testlogon.android.core.model` and a build file declaring `kotlin-stdlib` and
  `kotlinx-coroutines-core`.
- **Enables:** AND-015 (consumes `ApiError`), AND-010 (Retrofit `suspend`/`Call` adapter
  emitting `ApiResult`), AND-016 (keys retry off `NetworkError`), and all `feature-*`
  repositories.
- **Sequencing:** Must land before AND-015 and before the first feature repository. No
  changes to `app` build are required beyond what AND-003 already wires.

## 13. Risks & Open Questions

- **R1 — Premature lock-in of `ApiError`.** AND-015 may want extra fields (field-level
  validation errors from `[{msg}]`). Mitigation: `ApiError` is a `data class` with
  defaulted params; adding fields is source-compatible. Keep `rawBody` so nothing is lost.
- **R2 — Two error notions colliding.** Teams sometimes also want a `Loading` state.
  Decision: `ApiResult` models *completed* outcomes only; `Loading` belongs to per-feature
  `UiState`, not here. Documented in KDoc.
- **Q1 — Should `HttpException`→`Failure` mapping live in `apiCall` now?** No: `core-model`
  must stay Retrofit-free. The mapping is added in AND-010/AND-015 via a separate adapter.
  Open: confirm the adapter package (`core-network`) with the AND-010 owner.
- **Q2 — Expose `Result`-style `Throwable` wrapping for `Failure`?** Decided no; `Failure`
  carries structured `ApiError`, not a `Throwable`, to keep error data first-class.

## 14. Acceptance Criteria

1. `sealed interface ApiResult<out T>` exists in `com.testlogon.android.core.model.result`
   with exactly `Success<T>`, `Failure(ApiError)`, and `NetworkError(cause, isTimeout)`.
2. `data class ApiError(status, message, code, rawBody)` exists with defaulted params.
3. All helpers from Section 4 are implemented, lambda-taking helpers are `inline`, and none
   catch `CancellationException`.
4. `apiCall` folds `IOException` into `NetworkError` (timeout flag correct) and re-throws
   `CancellationException`.
5. A repository can declare `suspend fun foo(): ApiResult<DomainModel>` and return any
   variant — demonstrated by a sample/test stub that compiles in `core-model`.
6. Unit tests cover every helper and every `apiCall` branch (per Section 11), and the suite
   passes via `./gradlew :core-model:test`.
7. `when (result) { ... }` over `ApiResult` is exhaustive without an `else` branch.

## 15. Definition of Done

- `core-model` compiles; `./gradlew :core-model:test` is green with coverage of
  `ApiResultExt.kt` and `apiCall`.
- Public types/functions have KDoc, including the usage contract (Section 6) and the
  "completed outcomes only — no Loading" note (R2).
- No Android, Retrofit, OkHttp, Moshi, or Hilt dependency is added to `core-model`
  (verified by inspecting the module build file's dependency block).
- ktlint/detekt (AND-005) pass on the new files.
- Code reviewed and merged to `android-port`; AND-015 and AND-010 owners notified that the
  `ApiResult`/`ApiError` shape is frozen for their consumption.

## 16. Citations & Assumption Audit

This ticket introduces a pure-Kotlin envelope type and consumes **no** network endpoint, so
most claims are framework/design decisions rather than API-contract claims. The few external
claims (the FastAPI `detail` union and the error-code examples that shape `ApiError`) were
verified against the OpenAPI spec and the web client.

1. **Claim:** The FastAPI error `detail` is a union `string | [{msg}] | {code,...}`.
   **VERDICT:** Verified.
   **SOURCE:** `src/api/client.ts: normalizeErrorDetail` (handles `typeof detail === "string"`,
   `Array.isArray(detail)` with item `.msg`, and `detail && typeof detail === "object"` with
   `.code`); OpenAPI schemas `HTTPValidationError` (`detail: ValidationError[]`) and
   `ValidationError` (`{loc, msg, type}`, all required). The object/`{code,...}` form is
   confirmed by inline response examples (e.g. `detail: {code: "invalid_payload", message: ...}`)
   and `MessageControlsErrorOut {detail: string, error_code?}`.

2. **Claim:** The structured object form carries a machine-readable `code` and a human
   `message` (mapped to `ApiError.code` / `ApiError.message`).
   **VERDICT:** Verified.
   **SOURCE:** `src/api/client.ts` line ~245 reads `rawDetail.code === "geo_blocked"` then
   `rawDetail.message`; OpenAPI examples consistently use `{code, message}`. The KDoc example
   codes are real.

3. **Claim:** `role_required` is a real authorization error code.
   **VERDICT:** Corrected (clarified). The code family exists, but `role_required` is one of
   several siblings.
   **SOURCE:** `src/api/client.ts: mapAuthorizationError` matches `role_required_scope`,
   `role_required_admin_profile_type`, and `role_required` (lines 38–47);
   `src/api/client.errorMapping.test.ts` exercises the first two. The KDoc lists `role_required`
   as an *example* code, which is accurate as a representative; `ApiError.code` is a free-form
   `String?`, so no schema change is needed.

4. **Claim:** `geo_blocked` is a real error code surfaced via the `detail` object.
   **VERDICT:** Verified.
   **SOURCE:** `src/api/client.ts` line ~245 (`(rawDetail).code === "geo_blocked"`, then
   renders `rawDetail.message` and throws `ApiError(403, ...)`).

5. **Claim:** The data layer should distinguish "server answered with an error" from "we
   never reached the server."
   **VERDICT:** Verified (design corroborated by the web client).
   **SOURCE:** `src/api/client.ts` line ~185–188 — the `fetch` `catch` block emits
   `new ApiError(0, "Network error", err)` with the comment "Network error (offline, DNS
   failure, etc.)". The web client collapses this into status `0`; the Android `ApiResult`
   intentionally promotes it to a first-class `NetworkError` variant (a deliberate divergence,
   not a contradiction — see Corrections).

6. **Claim:** The web `ApiError` shape is `(status, detail, body)`, analogous to the Android
   `ApiError(status, message, code, rawBody)`.
   **VERDICT:** Verified (analogy, not identity).
   **SOURCE:** `src/api/client.ts: class ApiError extends Error` (ctor `status, detail, body`,
   line ~106–113). Android adds an explicit `code` field (web derives it ad hoc from
   `detail.code` at the call site); `rawBody` corresponds to web's `body`.

7. **Claim:** `core-model` is a pure Kotlin/JVM module with no Android/Retrofit/OkHttp/Hilt
   deps; `ApiResult` is unit-testable in isolation.
   **VERDICT:** Unverified-assumption (depends on AND-003, not on the API sources).
   **SOURCE:** AND-003 (not present in the authoritative API/frontend sources). Treated as a
   dependency contract; enforced by the §15 DoD build-file inspection.

8. **Claim:** `CancellationException` must propagate and `IOException` subtypes map to
   `NetworkError` (timeout flag for `SocketTimeoutException` / `InterruptedIOException`).
   **VERDICT:** Verified (framework ref).
   **SOURCE:** framework ref — Kotlin structured concurrency requires re-throwing
   `CancellationException` (https://kotlinlang.org/docs/cancellation-and-timeouts.html);
   `java.net.SocketTimeoutException` extends `java.io.InterruptedIOException` extends
   `java.io.IOException` (https://docs.oracle.com/javase/8/docs/api/java/net/SocketTimeoutException.html).

9. **Claim:** `out T` variance lets `Failure`/`NetworkError` be typed `ApiResult<Nothing>`
   and reused across any `ApiResult<T>`.
   **VERDICT:** Verified (framework ref).
   **SOURCE:** framework ref — Kotlin declaration-site variance and `Nothing`
   (https://kotlinlang.org/docs/generics.html#declaration-site-variance).

10. **Claim:** HTTP-error→`Failure` mapping and `detail` normalization are out of scope here
    (owned by AND-010 / AND-015).
    **VERDICT:** Unverified-assumption (cross-ticket scoping; not checkable against API sources).
    **SOURCE:** AND-010 / AND-015 ticket scope. Internally consistent with §3.4 and §5.

### Corrections made

- **§2 (Web reference):** added an inline verification note confirming the three `detail` forms
  against `src/api/client.ts: normalizeErrorDetail`, the `ValidationError {loc, msg, type}`
  schema, and the `{code, message}` object form.
- **Citation #3 / KDoc codes:** clarified that `role_required` is one member of a family
  (`role_required`, `role_required_scope`, `role_required_admin_profile_type`). No code change —
  `ApiError.code` is `String?`, so the example remains valid; this is a documentation precision
  fix, not a contract fix.
- **Citation #5 (network/server split):** noted that the web client collapses unreachable-host
  failures into `ApiError(status = 0)`, whereas this ticket promotes them to a distinct
  `NetworkError` variant. Recorded as an intentional, documented divergence so reviewers do not
  mistake it for a contract mismatch.
- No factual errors were found in the type design, helper list, or `apiCall` semantics; those
  edits were limited to the notes above.

### Open assumptions

- **AND-003 module shape** (namespace `com.testlogon.android.core.model`, Kotlin-stdlib +
  coroutines-core only, no Android deps): not verifiable from the OpenAPI/frontend sources;
  it is an upstream-ticket contract. Risk is low and is gated by the §15 DoD build-file check.
- **AND-010 / AND-015 ownership** of the `HttpException`→`Failure` adapter and `detail`
  normalization: cross-ticket scoping decision, not checkable against API sources. The `apiCall`
  seam is deliberately left final on the `IOException` branch (§3.4, §4).
- **Exact set of FastAPI error codes** that AND-015 will key on: only a representative sample
  (`role_required*`, `geo_blocked`, `invalid_payload`, `invalid_signature`, …) is observable in
  the spec/frontend; the full enumeration is owned by AND-015 and is not frozen here. `ApiError.code`
  stays a free-form `String?` precisely to avoid premature lock-in (§13 R1).

## 17. Test Plan

All tests run in `core-model/src/test` (JVM unit tests; JUnit + Truth/kotlin-test, with
`kotlinx-coroutines-test` for `apiCall`). No MockWebServer/instrumented/Compose-UI tests apply:
this module has no network transport and no UI (so accessibility cases are N/A and explicitly
noted). The "flaky-dev-host/offline" path is exercised at the type level by simulating thrown
`IOException`s through `apiCall`/`mapCatching`, since the real transport (AND-010) is out of scope.

- **TC-AND-018-01 — `map` over `Success` transforms; over failures is identity**
  - Type: unit
  - Preconditions: none.
  - Steps: (a) `ApiResult.Success(2).map { it * 3 }`; (b) take a `Failure(err)` instance `f`
    and call `f.map { it }`; (c) take a `NetworkError(e)` instance `n` and call `n.map { it }`.
  - Expected: (a) `Success(6)`; (b) returns the *same* `f` instance (assert reference equality);
    (c) returns the *same* `n` instance.
  - Traces: AC-1, AC-3.

- **TC-AND-018-02 — `flatMap` chains on `Success`, short-circuits on failures**
  - Type: unit
  - Preconditions: none.
  - Steps: (a) `Success(2).flatMap { Success(it+1) }`; (b) `Success(2).flatMap { Failure(err) }`;
    (c) `Failure(err).flatMap { Success(1) }`; (d) `NetworkError(e).flatMap { Success(1) }`.
  - Expected: (a) `Success(3)`; (b) `Failure(err)`; (c) original `Failure` unchanged (identity);
    (d) original `NetworkError` unchanged (identity); transform not invoked in (c)/(d).
  - Traces: AC-3.

- **TC-AND-018-03 — `fold` dispatches to the correct branch for all three variants**
  - Type: unit
  - Preconditions: none.
  - Steps: call `fold(onSuccess, onFailure, onNetworkError)` on a `Success`, a `Failure`, and a
    `NetworkError`, each returning a distinct sentinel.
  - Expected: each variant routes to exactly its branch (other branches not invoked); `onFailure`
    receives the `ApiError`, `onNetworkError` receives the `NetworkError` instance.
  - Traces: AC-3, AC-7.

- **TC-AND-018-04 — getters: `getOrNull` / `getOrElse` / `getOrDefault`**
  - Type: unit
  - Preconditions: none.
  - Steps: on `Success("x")`, `Failure(err)`, `NetworkError(e)` call each getter (with a fallback
    value/lambda for the latter two).
  - Expected: `Success` returns its data; `Failure`/`NetworkError` return the supplied fallback;
    `getOrElse` lambda receives the original receiver.
  - Traces: AC-3.

- **TC-AND-018-05 — `errorOrNull` / `exceptionOrNull` selectivity**
  - Type: unit
  - Preconditions: none.
  - Steps: call both accessors on each of the three variants.
  - Expected: `errorOrNull` returns the `ApiError` only on `Failure` (null otherwise);
    `exceptionOrNull` returns `cause` only on `NetworkError` (null otherwise).
  - Traces: AC-3.

- **TC-AND-018-06 — side-effect helpers fire only on matching variant and return receiver**
  - Type: unit
  - Preconditions: none.
  - Steps: chain `.onSuccess{}.onFailure{}.onNetworkError{}` on each variant, recording which
    actions ran; assert the returned value.
  - Expected: only the matching action runs; the original receiver is returned unchanged
    (enables fluent chaining).
  - Traces: AC-3.

- **TC-AND-018-07 — boolean predicates `isSuccess` / `isFailure` / `isNetworkError`**
  - Type: unit
  - Preconditions: none.
  - Steps: evaluate all three predicates against all three variants.
  - Expected: exactly one predicate is `true` per variant; the other two are `false`.
  - Traces: AC-3.

- **TC-AND-018-08 — `mapCatching` converts a thrown transform exception to `NetworkError`**
  - Type: unit
  - Preconditions: none.
  - Steps: `Success(1).mapCatching { throw RuntimeException("boom") }`; also
    `Failure(err).mapCatching { it }` and `NetworkError(e).mapCatching { it }`.
  - Expected: first yields `NetworkError(cause=RuntimeException, isTimeout=false)`; the failure
    inputs pass through unchanged (transform not invoked).
  - Traces: AC-3.

- **TC-AND-018-09 — `mapCatching` re-throws `CancellationException`**
  - Type: unit
  - Preconditions: none.
  - Steps: `assertFailsWith<CancellationException> { Success(1).mapCatching { throw CancellationException() } }`.
  - Expected: the `CancellationException` propagates (is NOT converted to `NetworkError`).
  - Traces: AC-3.

- **TC-AND-018-10 — `apiCall` happy path returns `Success`**
  - Type: unit (coroutines-test)
  - Preconditions: `runTest` scope.
  - Steps: `apiCall { 42 }`.
  - Expected: `ApiResult.Success(42)`.
  - Traces: AC-4, AC-5.

- **TC-AND-018-11 — `apiCall` maps `IOException` subtypes to `NetworkError` with correct timeout flag (flaky-dev-host/offline path)**
  - Type: unit (coroutines-test)
  - Preconditions: `runTest` scope.
  - Steps: (a) `apiCall { throw SocketTimeoutException() }`; (b)
    `apiCall { throw InterruptedIOException() }`; (c) `apiCall { throw IOException("connreset") }`
    (simulates the flaky plaintext dev host `18.222.237.167:8000` being slow/unreachable).
  - Expected: (a) and (b) → `NetworkError(isTimeout = true)`; (c) → `NetworkError(isTimeout = false)`;
    `cause` is the thrown instance in each case.
  - Traces: AC-4.

- **TC-AND-018-12 — `apiCall` re-throws `CancellationException`**
  - Type: unit (coroutines-test)
  - Preconditions: `runTest` scope.
  - Steps: `assertFailsWith<CancellationException> { apiCall { throw CancellationException() } }`.
  - Expected: propagates; never returned as `NetworkError`/`Failure`.
  - Traces: AC-4.

- **TC-AND-018-13 — `ApiError` defaults + repository return-type stub compiles**
  - Type: contract (compile/usage)
  - Preconditions: none.
  - Steps: (a) construct `ApiError()` (all defaults: `status=0`, others null); construct
    `ApiError(status=422, message="bad", code="role_required", rawBody="{...}")`. (b) define a
    sample `suspend fun foo(): ApiResult<String>` in test source that returns each of the three
    variants on different paths and compiles.
  - Expected: both constructions compile and hold the given values; the stub compiles and can
    return `Success`/`Failure`/`NetworkError`. (Mirrors the web `detail.{code, message}` /
    `ValidationError` shapes verified in §16.)
  - Traces: AC-2, AC-5.

- **TC-AND-018-14 — `when` over `ApiResult` is exhaustive without `else`; variance assignability**
  - Type: unit (compile-time regression guard)
  - Preconditions: a `sealed interface` with exactly three variants.
  - Steps: (a) a `when (result)` covering `Success`/`Failure`/`NetworkError` with no `else`
    compiles and returns a value; (b) `val a: ApiResult<Animal> = ApiResult.Success(Cat())`
    compiles; (c) a `Failure`/`NetworkError` value is assignable to both `ApiResult<String>` and
    `ApiResult<Int>` (typed `ApiResult<Nothing>`).
  - Expected: all compile; adding a 4th variant would break (a) at compile time (the intended
    regression guard).
  - Traces: AC-1, AC-7.

- **TC-AND-018-15 — security: failure types carry no credentials/PII and full suite is green**
  - Type: unit + manual review
  - Preconditions: none.
  - Steps: (a) unit-assert `ApiError`/`NetworkError` expose only `status/message/code/rawBody` and
    `cause/isTimeout` (no token/cookie/CSRF fields) via property checks; (b) manual: confirm
    `core-model` build file adds no Android/Retrofit/OkHttp/Moshi/Hilt dep and no logging dep;
    run `./gradlew :core-model:test` and confirm green with `ApiResultExt.kt` + `apiCall` covered.
  - Expected: (a) only the documented fields exist; (b) build file is clean and the suite passes.
  - Traces: AC-1, AC-2, AC-6. (Accessibility: N/A — no UI in this module.)

### Coverage matrix

| Acceptance criterion (§14) | Covered by |
| --- | --- |
| AC-1 — `ApiResult` sealed interface, 3 variants | TC-01, TC-14, TC-15 |
| AC-2 — `ApiError` with defaulted params | TC-13, TC-15 |
| AC-3 — all helpers implemented, `inline`, no `CancellationException` catch | TC-01, TC-02, TC-03, TC-04, TC-05, TC-06, TC-07, TC-08, TC-09 |
| AC-4 — `apiCall` folds `IOException`→`NetworkError` (timeout flag), re-throws `CancellationException` | TC-10, TC-11, TC-12 |
| AC-5 — repository can declare/return `ApiResult<T>` (compiling stub) | TC-10, TC-13 |
| AC-6 — unit tests cover every helper + `apiCall` branch; suite passes | TC-01..TC-12, TC-15 |
| AC-7 — exhaustive `when` without `else` | TC-03, TC-14 |
