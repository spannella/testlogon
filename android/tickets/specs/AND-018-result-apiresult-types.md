---
id: AND-018
title: Result/ApiResult types
milestone: M1
epic: E02
priority: P0
size: S
status: draft
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
  the `ApiError` shape consumed here; full normalization is AND-015.
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
