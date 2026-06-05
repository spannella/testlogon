---
id: AND-015
title: API error model & detail mapping
milestone: M1
epic: E02
priority: P0
size: M
status: draft
depends_on: [AND-010]
blocks: [AND-018]
---

# AND-015 — API error model & detail mapping

## 1. Overview & Goal

This ticket defines the **canonical error model** for the TestLogon native Android port and the
pure-function pipeline that turns a FastAPI HTTP failure into a stable, user-facing message. The
deliverable is a small, side-effect-free library in `core-network`/`core-model`:

- A typed `ApiError(status, detail, body)` value that captures the HTTP status code, a parsed
  structured `detail`, and the raw response body.
- A Moshi-aware parser that decodes the FastAPI `detail` union — which is one of
  `string`, `[{msg}, ...]` (Pydantic validation errors), or `{code, ...}` (application error
  objects) — into a discriminated `ErrorDetail` sealed type.
- A port of the web reference's `normalizeErrorDetail` that collapses any of those shapes into a
  single human-readable string.
- A mapping of **auth/application error codes** (`role_required`, `geo_blocked`, and the helpdesk
  code family) to specific, localized, user-facing messages.

The goal is that every repository and ViewModel in the app converts a non-2xx response (or a
deserialization failure) into the **same** `ApiError`, and renders the **same** message for the
same backend condition, with unit tests proving representative error bodies map to expected
strings. This ticket is the single source of truth for "what does the user see when the API
fails."

This is a **headless, transport-adjacent** ticket. It defines the error types and mapping
functions and a Moshi adapter; it does **not** implement the `ApiResult<T>` wrapper that callers
use (AND-018), nor the retry/refresh/offline behavior (AND-009/AND-013), nor any UI rendering.
Those consume the model defined here.

Scope, in one line from the backlog: *`ApiError(status, detail, body)`; parse FastAPI `detail`
(string | `[{msg}]` | `{code,...}`); port `normalizeErrorDetail` + auth-code messages
(`role_required`, `geo_blocked`, helpdesk codes).*

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`, branch
  `android-port`. Code in this ticket lives in **`core-model`** (the pure types and mapping
  functions, so `core-data` and `feature-*` can depend on it without pulling Retrofit) and in
  **`core-network`** (the Moshi adapter and the `Response`/`HttpException` → `ApiError`
  extraction, which needs `retrofit2`/`okhttp3`/`moshi`).
- **Canonical package:** `com.testlogon.android` everywhere. Error types live under
  `com.testlogon.android.core.model.error`; the extractor/adapter under
  `com.testlogon.android.core.network.error`.
- **Stack pins relevant here:** Kotlin 2.0.21, Moshi **1.15.x** (codegen via KSP — no reflection
  factory, per AND-010), Retrofit **2.11.0**, OkHttp **4.12.0**, Hilt (KSP), JDK 17.
- **Upstream dependency:**
  - **AND-010** — supplies the shared `Retrofit`/`Moshi` pair and the policy that non-2xx
    surfaces as `retrofit2.HttpException` and decode errors as `JsonDataException`. This ticket
    consumes that `Moshi` to decode `detail` and wraps those exceptions into `ApiError`.
- **Downstream consumers (not implemented here):**
  - **AND-018** — `ApiResult<T>` (`Success`/`Failure(ApiError)`) in `core-model`; wraps service
    calls and embeds the `ApiError` produced here.
  - **AND-013** — the 401-refresh `Authenticator`; on terminal 401 it produces an `ApiError`
    with `status = 401` using this model.
  - All `feature-*` ViewModels render `ApiError.userMessage` into `UiState`.
- **Backend:** FastAPI + DynamoDB; dev host `http://18.222.237.167:8000` (plaintext, unreliable).
  OpenAPI at `/openapi.json`. FastAPI's default validation error envelope is
  `{"detail": [{"loc": [...], "msg": "...", "type": "..."}]}`; `HTTPException` raises produce
  `{"detail": "<string>"}`; the app's custom auth/business errors produce
  `{"detail": {"code": "...", "message": "...", ...}}`.
- **Web reference:** `frontend/src/api/types.ts` (the `ApiError` / `ErrorDetail` types) and the
  `normalizeErrorDetail` helper plus the auth-code message map in
  `frontend/src/api/endpoints/*.ts`. This ticket is a faithful Kotlin port of that behavior; the
  TS strings are the authority for message text.

## 3. Functional Requirements

FR-1. `ApiError(status: Int, detail: ErrorDetail, body: String?)` is a data class in
`core-model`. `status` is the HTTP code (or a sentinel for transport/parse failures, see FR-7),
`detail` is the parsed union, `body` is the raw response body string (for diagnostics/logging),
nullable when unavailable.

FR-2. `ErrorDetail` is a sealed interface with three variants modeling the FastAPI union:
- `ErrorDetail.Message(text: String)` — `detail` was a JSON string.
- `ErrorDetail.Validation(items: List<ValidationItem>)` — `detail` was an array of objects, each
  with at least `msg` (and optional `loc`, `type`).
- `ErrorDetail.Coded(code: String, message: String?, extra: Map<String, Any?>)` — `detail` was an
  object with a `code` field.
- Plus `ErrorDetail.Empty` for an absent/unparseable `detail` (defensive default).

FR-3. `parseErrorDetail(json: String?): ErrorDetail` decodes a raw response body's `detail`
field into the correct variant, using the injected Moshi. It must be **total** (never throws):
any malformed input yields `ErrorDetail.Empty` rather than propagating.

FR-4. `normalizeErrorDetail(detail: ErrorDetail): String` collapses any variant into one
human-readable string, porting the web logic:
- `Message` → the string itself.
- `Validation` → the **first** item's `msg` if present; if multiple, join with `"; "` (matching
  the web reference's behavior of surfacing the leading validation message).
- `Coded` → the code's mapped user message (FR-5) when known; else `message` if present; else a
  generic fallback.
- `Empty` → a generic fallback string (resource-backed, FR-6 in §9).

FR-5. `mapAuthCode(code: String): String?` maps known application codes to specific messages.
Required codes from the backlog: `role_required`, `geo_blocked`, and the **helpdesk** code family
(any code beginning with `helpdesk_`, e.g. `helpdesk_locked`, `helpdesk_review`,
`helpdesk_contact`). Unknown codes return `null` so the caller falls back per FR-4.

FR-6. `ApiError.userMessage: String` is a computed property that returns
`normalizeErrorDetail(detail)`, i.e. the single string a UI should display.

FR-7. A factory builds `ApiError` from the transport layer:
- `ApiError.from(http: HttpException): ApiError` — reads `http.code()` and
  `http.response()?.errorBody()?.string()` and parses `detail`.
- `ApiError.fromTransport(t: Throwable): ApiError` — for `IOException`
  (`SocketTimeoutException`, `UnknownHostException`) and `JsonDataException`, returning a sentinel
  status (`0` for transport, `-1` for parse) and a generic offline/parse message.

FR-8. The mapping must be deterministic and locale-aware: all final user-facing strings are
sourced from Android string resources (see §9), keyed by an enum, so the function returns a
**resolved** string given a resource resolver. Pure-Kotlin overloads return a **string key /
enum** for JVM unit tests that don't have an Android `Context`.

## 4. Technical Design

Production code lands in two modules. Pure types + key mapping in `core-model`
(`core-model/src/main/kotlin/com/testlogon/android/core/model/error/`); Moshi/Retrofit glue in
`core-network` (`com/testlogon/android/core/network/error/`).

### 4.1 Error types (`core-model`)

```kotlin
package com.testlogon.android.core.model.error

sealed interface ErrorDetail {
    data class Message(val text: String) : ErrorDetail
    data class Validation(val items: List<ValidationItem>) : ErrorDetail
    data class Coded(
        val code: String,
        val message: String? = null,
        val extra: Map<String, Any?> = emptyMap(),
    ) : ErrorDetail
    data object Empty : ErrorDetail
}

data class ValidationItem(
    val msg: String,
    val loc: List<String> = emptyList(),
    val type: String? = null,
)

data class ApiError(
    val status: Int,
    val detail: ErrorDetail,
    val body: String? = null,
) {
    val isTransport: Boolean get() = status == STATUS_TRANSPORT
    val isParse: Boolean get() = status == STATUS_PARSE
    val isAuth: Boolean get() = status == 401 || status == 403

    companion object {
        const val STATUS_TRANSPORT = 0
        const val STATUS_PARSE = -1
    }
}
```

### 4.2 Message keys & resolver (`core-model`)

To keep `core-model` free of an Android `Context` while still being localizable, the mapping
yields an `ErrorMessageKey` enum; a thin resolver (provided in `core-ui`/`app`, out of scope
here) turns a key into a localized string. For convenience and tests, a default English string
table is included.

```kotlin
package com.testlogon.android.core.model.error

enum class ErrorMessageKey {
    GENERIC,            // R.string.error_generic
    OFFLINE,            // R.string.error_offline
    PARSE,              // R.string.error_unexpected
    ROLE_REQUIRED,      // R.string.error_role_required
    GEO_BLOCKED,        // R.string.error_geo_blocked
    HELPDESK_LOCKED,    // R.string.error_helpdesk_locked
    HELPDESK_REVIEW,    // R.string.error_helpdesk_review
    HELPDESK_CONTACT,   // R.string.error_helpdesk_generic
}

/** Maps a backend `code` to a message key, or null if unrecognized. */
fun mapAuthCode(code: String): ErrorMessageKey? = when (code) {
    "role_required" -> ErrorMessageKey.ROLE_REQUIRED
    "geo_blocked" -> ErrorMessageKey.GEO_BLOCKED
    "helpdesk_locked" -> ErrorMessageKey.HELPDESK_LOCKED
    "helpdesk_review" -> ErrorMessageKey.HELPDESK_REVIEW
    else -> if (code.startsWith("helpdesk_")) ErrorMessageKey.HELPDESK_CONTACT else null
}
```

### 4.3 Normalization (`core-model`)

`normalizeErrorDetail` returns a `NormalizedMessage`: either a literal backend string (for
`Message`/`Validation`/`Coded.message`) or a resource key (for mapped codes and fallbacks). The
UI resolves keys; literals pass through.

```kotlin
package com.testlogon.android.core.model.error

sealed interface NormalizedMessage {
    data class Literal(val text: String) : NormalizedMessage
    data class Keyed(val key: ErrorMessageKey) : NormalizedMessage
}

fun normalizeErrorDetail(detail: ErrorDetail): NormalizedMessage = when (detail) {
    is ErrorDetail.Message ->
        NormalizedMessage.Literal(detail.text)

    is ErrorDetail.Validation ->
        detail.items.takeIf { it.isNotEmpty() }
            ?.joinToString("; ") { it.msg }
            ?.let { NormalizedMessage.Literal(it) }
            ?: NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)

    is ErrorDetail.Coded ->
        mapAuthCode(detail.code)?.let { NormalizedMessage.Keyed(it) }
            ?: detail.message?.let { NormalizedMessage.Literal(it) }
            ?: NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)

    ErrorDetail.Empty ->
        NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)
}
```

A default English string table backs JVM tests and serves as the canonical source for
`strings.xml` (§9):

```kotlin
val DefaultErrorStrings: Map<ErrorMessageKey, String> = mapOf(
    ErrorMessageKey.GENERIC to "Something went wrong. Please try again.",
    ErrorMessageKey.OFFLINE to "You appear to be offline. Check your connection and retry.",
    ErrorMessageKey.PARSE to "We received an unexpected response. Please try again.",
    ErrorMessageKey.ROLE_REQUIRED to "You don't have permission to access this.",
    ErrorMessageKey.GEO_BLOCKED to "This content isn't available in your region.",
    ErrorMessageKey.HELPDESK_LOCKED to "Your account is locked. Contact the help desk.",
    ErrorMessageKey.HELPDESK_REVIEW to "Your account is under review. Contact the help desk.",
    ErrorMessageKey.HELPDESK_CONTACT to "Please contact the help desk to continue.",
)

fun NormalizedMessage.resolveWith(strings: Map<ErrorMessageKey, String>): String = when (this) {
    is NormalizedMessage.Literal -> text
    is NormalizedMessage.Keyed -> strings[key] ?: strings.getValue(ErrorMessageKey.GENERIC)
}
```

`ApiError.userMessage` resolves against `DefaultErrorStrings` for non-UI callers; UI callers pass
a `Context`-backed resolver.

### 4.4 Detail parsing & transport extraction (`core-network`)

Parsing inspects the JSON token type of `detail` and dispatches to the right Moshi adapter. It is
total — every failure path returns `ErrorDetail.Empty`.

```kotlin
package com.testlogon.android.core.network.error

import com.squareup.moshi.JsonClass
import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.error.ApiError
import com.testlogon.android.core.model.error.ErrorDetail
import com.testlogon.android.core.model.error.ValidationItem
import okio.Buffer
import retrofit2.HttpException
import java.io.IOException
import javax.inject.Inject
import javax.inject.Singleton

@JsonClass(generateAdapter = true)
internal data class DetailEnvelope(val detail: Any?)   // Any? → String | List | Map | null

@JsonClass(generateAdapter = true)
internal data class CodedDto(
    val code: String,
    val message: String? = null,
)

@Singleton
class ApiErrorParser @Inject constructor(private val moshi: Moshi) {

    fun parseDetail(body: String?): ErrorDetail {
        if (body.isNullOrBlank()) return ErrorDetail.Empty
        return try {
            val env = moshi.adapter(DetailEnvelope::class.java).fromJson(body)
            when (val d = env?.detail) {
                is String -> ErrorDetail.Message(d)
                is List<*> -> ErrorDetail.Validation(
                    d.filterIsInstance<Map<*, *>>().mapNotNull { it.toValidationItem() }
                )
                is Map<*, *> -> {
                    val code = d["code"] as? String
                    if (code != null) {
                        ErrorDetail.Coded(
                            code = code,
                            message = d["message"] as? String,
                            extra = d.entries.associate { (k, v) -> k.toString() to v },
                        )
                    } else ErrorDetail.Empty
                }
                else -> ErrorDetail.Empty
            }
        } catch (_: Exception) {
            ErrorDetail.Empty
        }
    }

    fun from(http: HttpException): ApiError {
        val raw = runCatching { http.response()?.errorBody()?.string() }.getOrNull()
        return ApiError(status = http.code(), detail = parseDetail(raw), body = raw)
    }

    fun fromTransport(t: Throwable): ApiError = when (t) {
        is HttpException -> from(t)
        is IOException -> ApiError(ApiError.STATUS_TRANSPORT, ErrorDetail.Empty, null)
        else -> ApiError(ApiError.STATUS_PARSE, ErrorDetail.Empty, t.message)
    }
}

private fun Map<*, *>.toValidationItem(): ValidationItem? {
    val msg = this["msg"] as? String ?: return null
    return ValidationItem(
        msg = msg,
        loc = (this["loc"] as? List<*>)?.map { it.toString() } ?: emptyList(),
        type = this["type"] as? String,
    )
}
```

`DetailEnvelope.detail: Any?` relies on Moshi's default handling of `Any` (string → `String`,
array → `List<Any?>`, object → `Map<String, Any?>`, number → `Double`), which lets one decode
distinguish all three union arms by Kotlin type.

### 4.5 Hilt wiring

`ApiErrorParser` is `@Singleton @Inject`-constructed; it needs only the AND-010 `Moshi`, already
in the `SingletonComponent`. No new module is required beyond ensuring `core-network` depends on
`core-model`.

### 4.6 Gradle

`core-model`: pure Kotlin/Android-library, depends on Moshi annotations only if it hosts DTOs (it
does not — keep it dependency-light; `ErrorDetail`/`ApiError` are plain Kotlin). `core-network`
already has Moshi/Retrofit/Hilt from AND-010; add `implementation(project(":core-model"))` if not
present. Add `testImplementation(libs.okhttp.mockwebserver)` for the extraction tests.

## 5. API Contract

This ticket consumes error response **bodies** rather than defining endpoints. The three FastAPI
`detail` shapes it must handle, with their canonical decode targets:

**Shape A — string `detail`** (e.g. `HTTPException(status_code=400, detail="Invalid challenge")`):

```json
{ "detail": "Invalid challenge" }
```
→ `ErrorDetail.Message("Invalid challenge")` → message `"Invalid challenge"`.

**Shape B — validation array** (FastAPI 422 default):

```json
{ "detail": [
  { "loc": ["body", "challenge_context", "username"], "msg": "field required", "type": "value_error.missing" }
] }
```
→ `ErrorDetail.Validation([ValidationItem(msg="field required", ...)])` → message
`"field required"`.

**Shape C — coded object** (app auth/business errors):

```json
{ "detail": { "code": "role_required", "message": "Manager role required", "required_role": "manager" } }
```
→ `ErrorDetail.Coded(code="role_required", message="Manager role required",
extra={required_role=manager})` → mapped message for `ROLE_REQUIRED`
(`"You don't have permission to access this."`, the code map wins over the backend `message`).

```json
{ "detail": { "code": "geo_blocked", "country": "XX" } }
```
→ `ErrorDetail.Coded("geo_blocked", null, {country=XX})` → `"This content isn't available in
your region."`

```json
{ "detail": { "code": "helpdesk_locked" } }
```
→ `HELPDESK_LOCKED`; any `helpdesk_*` not explicitly mapped → `HELPDESK_CONTACT`.

These bodies arise from the auth flow endpoints (`POST /ui/session/start`,
`/ui/mfa/{totp|sms|email}/verify`, `POST /ui/session/finalize`, `GET /ui/me`) but the parser is
endpoint-agnostic. Authoritative code/message text is cross-checked against
`frontend/src/api/types.ts` and the web `normalizeErrorDetail` map.

## 6. Data & State Management

- **Statelessness:** all functions here are pure (given Moshi); `ApiErrorParser` holds only the
  injected singleton `Moshi`. No Room, no DataStore, no in-memory cache.
- **No `StateFlow`/`UiState`:** this ticket produces values consumed by AND-018's `ApiResult` and
  by ViewModels; it exposes no observable state itself.
- **Immutability:** `ApiError`, `ErrorDetail`, `ValidationItem`, `NormalizedMessage` are
  immutable data classes / sealed types; `extra` is an immutable `Map`.
- **Determinism:** for a given body + locale, `userMessage` is deterministic, enabling exact-match
  unit assertions (the backlog's "representative error bodies map to expected messages").

## 7. Error Handling & Resilience

The whole ticket is error handling, but it must itself be failure-proof:

- **Total parsing:** `parseDetail` never throws; malformed JSON, unexpected types, empty bodies,
  and non-JSON (e.g. an HTML 502 from the unreliable dev host) all yield `ErrorDetail.Empty` →
  `GENERIC` message. Verified by tests T-7/T-8.
- **Transport vs. HTTP distinction:** `fromTransport` separates `IOException`
  (offline/timeout — sentinel status `0`, `OFFLINE` message) from HTTP errors (real status +
  parsed detail) and from `JsonDataException`/other (parse sentinel `-1`, `PARSE` message). This
  lets UI show "you're offline / retry" distinctly from "access denied," and lets AND-013 detect
  401s by status.
- **Idempotency / retry interplay:** retry+backoff for idempotent GETs and the single 401-refresh
  retry are owned by AND-009/AND-013; this ticket only ensures the resulting terminal failure
  carries the right `status` so those layers can branch. A 401 that survives refresh becomes
  `ApiError(status=401, ...)`.
- **Code-map fallback chain:** mapped code → backend `message` → `GENERIC`, so an unknown future
  code still degrades to a sane message instead of blank.

## 8. Security & Privacy

- **No secrets / no PII amplification:** error mapping must not surface raw stack traces, internal
  identifiers, or backend implementation detail to the UI. Coded errors render curated app strings;
  free-form `Message`/`Validation` text comes straight from the backend and is assumed
  user-safe (FastAPI validation `msg` and deliberate `HTTPException` detail). If a backend string
  is ever shown that should not be, that is a backend contract issue tracked separately.
- **Raw `body` retention:** `ApiError.body` holds the raw response for diagnostics. It must
  **never** be rendered in UI and must be redacted/omitted from any persisted logs that could
  contain tokens or PII (see §10). It exists for debug logging only.
- **Cleartext transport** and **cookie/CSRF** concerns are owned upstream (AND-009/011/012); no
  credentials pass through this layer.
- **Helpdesk codes** intentionally avoid leaking *why* an account is locked (fraud-sensitive);
  messages direct the user to the help desk without exposing internal reason codes beyond the
  curated text.

## 9. Accessibility & i18n

- **All user-facing strings are localizable.** Every `ErrorMessageKey` maps to a string resource
  in `core-ui` (or `core-model`'s resources if it carries an Android resource module). The
  `DefaultErrorStrings` table in §4.3 is the canonical English source and must be mirrored in
  `res/values/strings.xml`:
  `error_generic`, `error_offline`, `error_unexpected`, `error_role_required`,
  `error_geo_blocked`, `error_helpdesk_locked`, `error_helpdesk_review`,
  `error_helpdesk_generic`.
- **Backend literal strings** (Shapes A/B) are passed through as-is and are **not** translatable on
  the client; this is a known limitation noted for product (Q-2).
- **Accessibility:** these strings are surfaced by UI tickets via standard Compose `Text` /
  snackbars/dialogs, which carry semantics automatically; no special handling here. Messages are
  written as full sentences (screen-reader friendly), avoid codes/jargon, and avoid relying on
  color or punctuation alone.

## 10. Telemetry & Logging

- **Debug logging:** `ApiErrorParser` may log (debug builds only) `status` + `detail` variant +
  mapped key. The raw `body` is logged only in debug and is routed through the same redaction the
  AND-009 logging interceptor uses (no `Set-Cookie`/`X-CSRF-Token`/token leakage).
- **Analytics seam (not implemented here):** a counter of `ApiError` by `status` and by
  `ErrorDetail`/code would be valuable for spotting backend regressions; emitting it is a
  cross-cutting concern for a later observability ticket. This ticket exposes enough structure
  (`status`, `code`) to make that trivial.
- **No PII in events:** if telemetry is later added, it must key on `status` and `code` only —
  never on validation `msg` or `body`, which can contain user input.

## 11. Testing Strategy

All tests are JVM unit tests in `core-model/src/test/...` (pure mapping) and
`core-network/src/test/...` (parser/extraction). No instrumentation required.

**T-1 (acceptance) — string detail.** `parseDetail("""{"detail":"Invalid challenge"}""")` →
`ErrorDetail.Message("Invalid challenge")`; `userMessage == "Invalid challenge"`.

**T-2 (acceptance) — validation array.** A 422 body decodes to `Validation` with one item;
`normalizeErrorDetail` → literal `"field required"`. Multi-item joins with `"; "`.

**T-3 (acceptance) — coded `role_required`.** Shape C decodes to `Coded("role_required", ...)`;
`userMessage` (resolved via `DefaultErrorStrings`) equals
`"You don't have permission to access this."`, asserting the code map overrides backend `message`.

**T-4 (acceptance) — `geo_blocked`.** → `"This content isn't available in your region."`

**T-5 (acceptance) — helpdesk family.** `helpdesk_locked` → `HELPDESK_LOCKED` string;
`helpdesk_review` → review string; an unmapped `helpdesk_xyz` → `HELPDESK_CONTACT` string.

**T-6 — unknown code fallback.** `Coded("widget_exploded", message="boom")` → literal `"boom"`;
`Coded("widget_exploded", message=null)` → `GENERIC` string.

**T-7 — malformed / empty bodies are total.** `parseDetail(null)`, `parseDetail("")`,
`parseDetail("not json")`, `parseDetail("<html>502</html>")`, `parseDetail("""{"detail":42}""")`,
`parseDetail("""{"detail":[]}""")` all yield `ErrorDetail.Empty` (or empty `Validation`) and a
`GENERIC` message; none throw.

**T-8 — `HttpException` extraction via MockWebServer.** Enqueue a 403 with a coded body, make a
Retrofit call that throws `HttpException`, run `ApiErrorParser.from(ex)`; assert
`status == 403`, parsed `Coded`, and `userMessage`. Asserts `errorBody().string()` is read
exactly once safely.

**T-9 — transport classification.** `fromTransport(SocketTimeoutException())` →
`status == 0`, `OFFLINE`; `fromTransport(UnknownHostException())` → `OFFLINE`;
`fromTransport(JsonDataException("x"))` → `status == -1`, `PARSE`.

**T-10 — `extra` preserved.** `geo_blocked` body's `country` is retained in
`Coded.extra["country"]` for downstream use.

**T-11 — resource parity (lint-style).** A test asserts every `ErrorMessageKey` has an entry in
`DefaultErrorStrings` (no missing keys) so additions can't silently fall through.

Coverage target ≥95% on the mapping/parsing surface (small, pure, high-value).

## 12. Dependencies & Sequencing

**Hard upstream (must merge first):**
- **AND-010** — provides the singleton `Moshi` and the policy that non-2xx → `HttpException`,
  decode error → `JsonDataException`. `ApiErrorParser` injects that `Moshi`.

**Implicit upstream:** AND-003 (module structure incl. `core-model`, `core-network`,
`core-testing`) and AND-004 (Hilt baseline). AND-009 (shared client/logging) is not a hard build
dep but its redaction policy is referenced by §10.

**Downstream (this ticket blocks):**
- **AND-018** — `ApiResult<T>` embeds `ApiError`; cannot be finalized without this model.
- **AND-013** — terminal 401 produces an `ApiError` via this model.
- All `feature-*` auth/content ViewModels render `ApiError.userMessage`.

**Sequencing within the ticket:** (1) `core-model` types + `mapAuthCode` + `normalizeErrorDetail`
+ default strings; (2) `core-network` `ApiErrorParser` (`parseDetail`, `from`, `fromTransport`);
(3) `strings.xml` entries + resolver seam; (4) tests T-1…T-11. Steps 1 and 4 (pure) can proceed in
parallel with step 2.

## 13. Risks & Open Questions

- **R-1 `detail` polymorphism via `Any?`.** Relying on Moshi's `Any` mapping (object→`Map`,
  array→`List`, number→`Double`) is robust but couples to Moshi defaults; a number `detail`
  (`{"detail":42}`) lands in the `else` arm → `Empty`. Mitigation: T-7 covers it; behavior is
  intentional (numbers aren't user messages).
- **R-2 Backend message text drift.** Coded errors may also carry a backend `message`; we
  intentionally prefer the client code-map for known codes for consistency/localization. If
  product wants the backend message verbatim, flip the precedence in `normalizeErrorDetail`.
  (Q-1.)
- **R-3 Helpdesk code expansion.** New `helpdesk_*` codes auto-route to a generic message; if any
  needs bespoke copy, add an explicit `when` branch + key + string. Low risk, easy change.
- **R-4 Non-JSON error bodies from the unreliable dev host** (HTML 5xx, empty 502). Handled by the
  total parser (T-7); message degrades to `GENERIC`/`OFFLINE` appropriately.
- **Q-1 (open)** Code-map vs. backend `message` precedence — confirm with product/web team that
  client copy should win for `role_required`/`geo_blocked`. *Proposed:* client wins (current
  design), matching the web `normalizeErrorDetail` behavior.
- **Q-2 (open)** Should backend free-form strings (Shape A/B) be localized client-side? *Proposed:*
  no for v1; pass through and track if QA finds untranslated strings.
- **Q-3 (open)** Confirm the exact helpdesk code set and any `geo_blocked`/`role_required` extra
  fields from `/openapi.json`; fold the authoritative list into `mapAuthCode` before merge.

## 14. Acceptance Criteria

- **AC-1 (backlog).** Representative error bodies map to expected user-facing messages, proven by
  unit tests: Shape A string (T-1), Shape B validation (T-2), and Shape C coded
  `role_required`/`geo_blocked`/`helpdesk_*` (T-3, T-4, T-5).
- **AC-2.** `ApiError(status, detail, body)` exists in `core-model` with the documented fields and
  `userMessage`/`isTransport`/`isAuth` helpers.
- **AC-3.** `parseErrorDetail`/`parseDetail` correctly discriminates the FastAPI `detail` union
  (`string | [{msg}] | {code,...}`) into `Message`/`Validation`/`Coded`, and is **total** (no
  body, malformed, wrong-type, non-JSON all → `Empty`, never throws) (T-7).
- **AC-4.** `normalizeErrorDetail` ports the web behavior: string→itself, validation→first/joined
  `msg`, coded→mapped message with backend-message and generic fallbacks (T-2, T-3, T-6).
- **AC-5.** `mapAuthCode` maps `role_required`, `geo_blocked`, and the `helpdesk_*` family
  (explicit + prefix fallback) to the specified message keys; unknown codes return `null` (T-3…T-6).
- **AC-6.** Transport vs. HTTP vs. parse failures are classified by sentinel status with distinct
  messages (`OFFLINE`/`PARSE`/`GENERIC`) (T-9).
- **AC-7.** `HttpException` extraction reads the error body safely and yields the right
  `status`+`detail` (T-8); `extra` fields preserved (T-10).
- **AC-8.** Every `ErrorMessageKey` has a `DefaultErrorStrings` entry and a corresponding
  `strings.xml` resource (T-11); messages are localizable.
- **AC-9.** All tests T-1…T-11 pass in CI; modules build clean under AGP 8.7.3 / Gradle 8.9 /
  JDK 17 with no new lint/detekt violations.

## 15. Definition of Done

- `ApiError`, `ErrorDetail` (+ `ValidationItem`), `NormalizedMessage`, `ErrorMessageKey`,
  `mapAuthCode`, `normalizeErrorDetail`, `DefaultErrorStrings`, and `resolveWith` are implemented
  in `core-model` under `com.testlogon.android.core.model.error`.
- `ApiErrorParser` (`parseDetail`, `from(HttpException)`, `fromTransport(Throwable)`) and its
  Moshi `DetailEnvelope`/`CodedDto` helpers are implemented in `core-network` under
  `com.testlogon.android.core.network.error`, `@Singleton @Inject`-constructed against the AND-010
  `Moshi`.
- `strings.xml` entries for all eight `ErrorMessageKey`s are added (English values matching
  `DefaultErrorStrings`); the key→string parity test passes.
- Tests T-1 through T-11 implemented and green in CI; coverage on the new surface ≥95%.
- Message text and code map cross-checked against `frontend/src/api/types.ts` and the web
  `normalizeErrorDetail`; the authoritative helpdesk code set confirmed from `/openapi.json`
  (Q-3 resolved or explicitly deferred with a follow-up).
- `./gradlew :core-model:testDebugUnitTest :core-network:testDebugUnitTest` passes locally and in
  CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-018 (`ApiResult<T>`) and AND-013 (401 handling)
  are unblocked — they can construct/embed `ApiError` and branch on its `status`.
