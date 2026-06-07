---
id: AND-015
title: API error model & detail mapping
milestone: M1
epic: E02
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
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
- **Web reference (verified):** the authoritative error logic lives in **`src/api/client.ts`**,
  not `types.ts`. `client.ts` defines the `ApiError` *class* (`status: number, detail: string,
  body?: unknown`), the `normalizeErrorDetail(detail, fallback)` helper, and the
  `mapAuthorizationError(detail)` code map. `src/api/types.ts` does **not** export an `ApiError` or
  `ErrorDetail` type (correction: the original draft mis-cited `types.ts`). The web `ApiError` is a
  *flat string* `detail` produced by `normalizeErrorDetail`; this Android port intentionally
  preserves the *structured* `ErrorDetail` and normalizes lazily — a deliberate divergence. The TS
  strings in `client.ts` are the authority for message text.

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
human-readable string, porting the web logic (VERIFIED against `src/api/client.ts`):
- `Message` → the string itself.
- `Validation` → **all** items' non-empty `msg` joined with `", "` (comma-space). CORRECTED: the
  earlier draft said "first item, join with `; `"; the web maps every item and joins with `", "`.
- `Coded` → the code's mapped user message (FR-5) when known; else, for `geo_blocked`, the backend
  `message` (fallback `GEO_BLOCKED`); else the caller's generic fallback. CORRECTED: the web does
  **not** use a coded object's `message` field as a generic fallback for arbitrary codes.
- `Empty` → a generic fallback string (resource-backed, FR-6 in §9).

FR-5. `mapAuthCode(code: String): ErrorMessageKey?` maps known application codes to specific
messages. CORRECTED — the verified web codes (`src/api/client.ts: mapAuthorizationError`) are:
`role_required`, `role_required_scope`, `role_required_admin_profile_type`,
`helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`. The
backlog's shorthand "`role_required`, `geo_blocked`, helpdesk code family" was imprecise:
`geo_blocked` is handled on the 403 path (not in this map), and there is **no** `helpdesk_*`
prefix fallback — each helpdesk code is mapped explicitly. Unknown codes return `null` so the
caller falls back per FR-4.

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

> **CORRECTED against `src/api/client.ts: mapAuthorizationError`.** The earlier draft invented
> codes (`helpdesk_locked`/`helpdesk_review`/`helpdesk_contact`) and a generic-message
> `geo_blocked`. The real web code map keys are: `role_required`, `role_required_scope`,
> `role_required_admin_profile_type`, `helpdesk_claim_required`, `helpdesk_assignee_required`,
> `helpdesk_claim_not_available`. `geo_blocked` is **not** handled in `mapAuthorizationError`; the
> web handles it in a dedicated 403 branch using the backend `message` (fallback "This content is
> not available in your region."). There is **no** `helpdesk_*` prefix fallback in the web — an
> unmapped code returns `null` → caller fallback. The enum/map below mirrors the verified web copy
> verbatim.

```kotlin
package com.testlogon.android.core.model.error

enum class ErrorMessageKey {
    GENERIC,                        // R.string.error_generic
    OFFLINE,                        // R.string.error_offline
    PARSE,                          // R.string.error_unexpected
    ROLE_REQUIRED,                  // R.string.error_role_required
    ROLE_REQUIRED_SCOPE,            // R.string.error_role_required_scope (takes {scope} arg)
    ROLE_REQUIRED_ADMIN_PROFILE,    // R.string.error_role_required_admin_profile
    GEO_BLOCKED,                    // R.string.error_geo_blocked (403 special-path fallback)
    HELPDESK_CLAIM_REQUIRED,        // R.string.error_helpdesk_claim_required
    HELPDESK_ASSIGNEE_REQUIRED,     // R.string.error_helpdesk_assignee_required
    HELPDESK_CLAIM_NOT_AVAILABLE,   // R.string.error_helpdesk_claim_not_available
}

/**
 * Maps a backend `code` to a message key, or null if unrecognized.
 * Verbatim port of `mapAuthorizationError` in `src/api/client.ts`.
 * NOTE: `role_required_scope` is parameterized by `required_scope` in the web; callers that need
 * the scope-interpolated copy should read `Coded.extra["required_scope"]` and format the resource.
 * NOTE: `geo_blocked` is intentionally NOT mapped here — see normalizeErrorDetail / §5 geo path.
 */
fun mapAuthCode(code: String): ErrorMessageKey? = when (code) {
    "role_required" -> ErrorMessageKey.ROLE_REQUIRED
    "role_required_scope" -> ErrorMessageKey.ROLE_REQUIRED_SCOPE
    "role_required_admin_profile_type" -> ErrorMessageKey.ROLE_REQUIRED_ADMIN_PROFILE
    "helpdesk_claim_required" -> ErrorMessageKey.HELPDESK_CLAIM_REQUIRED
    "helpdesk_assignee_required" -> ErrorMessageKey.HELPDESK_ASSIGNEE_REQUIRED
    "helpdesk_claim_not_available" -> ErrorMessageKey.HELPDESK_CLAIM_NOT_AVAILABLE
    else -> null   // no prefix fallback in web; unknown codes degrade per FR-4
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

    // CORRECTED: web joins ALL items' msg with ", " (comma-space), not first-only with "; ".
    // See `normalizeErrorDetail` in src/api/client.ts (messages.join(", ")).
    is ErrorDetail.Validation ->
        detail.items.mapNotNull { it.msg.takeIf { m -> m.isNotEmpty() } }
            .takeIf { it.isNotEmpty() }
            ?.joinToString(", ")
            ?.let { NormalizedMessage.Literal(it) }
            ?: NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)

    // CORRECTED: the web does NOT fall back to a coded object's `message` field for unmapped
    // codes (the only object-`msg` fallback is the FastAPI-style `{msg}` shape, not `{code,...}`).
    // Mapped code wins; geo_blocked is handled on the 403 path (§5) using its backend `message`;
    // any other unmapped code degrades to the caller fallback (GENERIC here).
    is ErrorDetail.Coded ->
        mapAuthCode(detail.code)?.let { NormalizedMessage.Keyed(it) }
            ?: if (detail.code == "geo_blocked")
                   detail.message?.let { NormalizedMessage.Literal(it) }
                       ?: NormalizedMessage.Keyed(ErrorMessageKey.GEO_BLOCKED)
               else NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)

    ErrorDetail.Empty ->
        NormalizedMessage.Keyed(ErrorMessageKey.GENERIC)
}
```

A default English string table backs JVM tests and serves as the canonical source for
`strings.xml` (§9):

```kotlin
// Copy CORRECTED to match `mapAuthorizationError` / the 403 geo path in src/api/client.ts
// verbatim. OFFLINE/PARSE/GENERIC are client-only (no exact web equivalent; see Open assumptions).
// The web network-error toast text is "Network error — check your connection and try again".
val DefaultErrorStrings: Map<ErrorMessageKey, String> = mapOf(
    ErrorMessageKey.GENERIC to "Permission denied.", // web 403 fallback; see note re per-call fallback
    ErrorMessageKey.OFFLINE to "Network error — check your connection and try again.",
    ErrorMessageKey.PARSE to "We received an unexpected response. Please try again.",
    ErrorMessageKey.ROLE_REQUIRED to
        "You don't currently have permission for this action. Request temporary elevation or contact a general admin/root operator.",
    ErrorMessageKey.ROLE_REQUIRED_SCOPE to
        // {scope} is humanized from required_scope, e.g. "billing support"
        "You don't currently have %1\$s permission for this action. Request temporary elevation or ask a general admin/root operator to perform it.",
    ErrorMessageKey.ROLE_REQUIRED_ADMIN_PROFILE to
        "This action requires general admin access. Request temporary elevation or ask a general admin/root operator to perform it.",
    ErrorMessageKey.GEO_BLOCKED to "This content is not available in your region.",
    ErrorMessageKey.HELPDESK_CLAIM_REQUIRED to "Claim this helpdesk conversation before replying.",
    ErrorMessageKey.HELPDESK_ASSIGNEE_REQUIRED to
        "Only the currently assigned helpdesk agent can reply in this conversation.",
    ErrorMessageKey.HELPDESK_CLAIM_NOT_AVAILABLE to
        "You need to be online and available before you can claim and reply.",
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
`"field required"`. Multiple items join with `", "` (per verified web `messages.join(", ")`).
Note: `loc` items are `string | integer` in the `ValidationError` schema; the Kotlin model
stringifies them (`ValidationItem.loc: List<String>`).

**Shape C — coded object** (app auth/business errors):

```json
{ "detail": { "code": "role_required", "required_scope": "billing_support" } }
```
→ `ErrorDetail.Coded(code="role_required", message=null, extra={required_scope=billing_support})`
→ mapped message for `ROLE_REQUIRED`
(`"You don't currently have permission for this action. Request temporary elevation or contact a
general admin/root operator."`). **CORRECTED:** the original draft used a fabricated
`"Manager role required"` body and the wrong target string; the verified web copy is in
`src/api/client.ts: mapAuthorizationError`. When the code is `role_required_scope`, the web
humanizes `required_scope` into the message (`ROLE_REQUIRED_SCOPE`, `%1$s` = humanized scope).
For a known code, the client copy wins over any backend `message`.

```json
{ "detail": { "code": "geo_blocked", "message": "...", "country": "XX" } }
```
→ `ErrorDetail.Coded("geo_blocked", message=<backend or null>, {country=XX})`.
**CORRECTED:** `geo_blocked` is **not** in the auth-code map. The web handles it on a dedicated
403 branch that prefers the **backend `message`**, falling back to
`"This content is not available in your region."` (apostrophe/wording corrected from the draft's
`"isn't"`/`"your region"`). Port: prefer `Coded.message`, else `GEO_BLOCKED` key. The `country`
field is retained in `extra` for a GeoBlocked screen (web stores `window.__geoBlocked`).

```json
{ "detail": { "code": "helpdesk_claim_required" } }
```
→ `HELPDESK_CLAIM_REQUIRED`. **CORRECTED:** the real helpdesk codes are
`helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available` (the
draft's `helpdesk_locked`/`helpdesk_review`/`helpdesk_contact` do not exist in the web). There is
**no** `helpdesk_*` prefix fallback; an unmapped helpdesk code degrades to the caller fallback.

These bodies arise from auth/business endpoints (e.g. `POST /ui/session/start`,
`POST /ui/mfa/totp/verify`, `POST /ui/mfa/sms/verify`, `POST /ui/mfa/email/verify`,
`POST /ui/session/finalize`, `GET /ui/me` — all VERIFIED in the OpenAPI index; note these are
three distinct verify paths, not a single `{totp|sms|email}` route) but the parser is
endpoint-agnostic. The `422` validation envelope (Shape B) is the documented
`HTTPValidationError`/`ValidationError` schema; coded `detail` objects (Shape C) are **runtime**
responses not present in the OpenAPI schema, so their authoritative source is
`src/api/client.ts` (not `types.ts`, which has no `ApiError`/`ErrorDetail` type).

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
  `res/values/strings.xml` (keys CORRECTED to match the verified web codes):
  `error_generic`, `error_offline`, `error_unexpected`, `error_role_required`,
  `error_role_required_scope` (with a `%1$s` scope placeholder), `error_role_required_admin_profile`,
  `error_geo_blocked`, `error_helpdesk_claim_required`, `error_helpdesk_assignee_required`,
  `error_helpdesk_claim_not_available`.
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
`normalizeErrorDetail` → literal `"field required"`. Multi-item joins with `", "` (CORRECTED).

**T-3 (acceptance) — coded `role_required`.** Shape C decodes to `Coded("role_required", ...)`;
`userMessage` (resolved via `DefaultErrorStrings`) equals the verified web copy
`"You don't currently have permission for this action. Request temporary elevation or contact a
general admin/root operator."`, asserting the code map wins over backend `message`.

**T-4 (acceptance) — `geo_blocked`.** With a backend `message`, `userMessage` == that message;
without one → `"This content is not available in your region."` (CORRECTED text + behavior).

**T-5 (acceptance) — helpdesk family.** `helpdesk_claim_required` → claim-required copy;
`helpdesk_assignee_required` → assignee copy; `helpdesk_claim_not_available` → availability copy;
an unmapped `helpdesk_xyz` → caller fallback (`GENERIC`), since there is no prefix fallback
(CORRECTED).

**T-6 — unknown code fallback.** `Coded("widget_exploded", message="boom")` → `GENERIC` string
(CORRECTED: the web does NOT surface a coded object's `message` for arbitrary codes; only
`geo_blocked` uses its `message`). `Coded("widget_exploded", message=null)` → `GENERIC`.

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
- **Q-3 (RESOLVED via review)** The coded `detail` objects (`role_required*`, `geo_blocked`,
  `helpdesk_*`) are **runtime** responses and are **not** present in `/openapi.json` (verified: a
  grep of the OpenAPI spec finds none of these codes). The authoritative set is therefore
  `src/api/client.ts: mapAuthorizationError` + the 403 geo branch, now folded into `mapAuthCode`
  and §5. If the backend later adds a documented error-code schema, reconcile then.

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
- Message text and code map cross-checked against `src/api/client.ts` (`normalizeErrorDetail` +
  `mapAuthorizationError` + the 403 geo path), not `types.ts`; the helpdesk/role/geo code set is
  confirmed from `client.ts` (NOT `/openapi.json`, which omits these runtime codes — Q-3 resolved).
- `./gradlew :core-model:testDebugUnitTest :core-network:testDebugUnitTest` passes locally and in
  CI with no new lint/detekt violations (AND-005 config).
- Code reviewed and merged to `android-port`; AND-018 (`ApiResult<T>`) and AND-013 (401 handling)
  are unblocked — they can construct/embed `ApiError` and branch on its `status`.

## 16. Citations & Assumption Audit

Each key technical claim, its verdict, and the exact source pointer. "OpenAPI" pointers are
`METHOD /path` / schema names from `reference/openapi.index.txt` + `openapi.pretty.json`;
frontend pointers are `src/...` paths under `reference/src/`.

1. **FastAPI 422 validation envelope is `{"detail":[{loc,msg,type}]}`.** VERIFIED.
   OpenAPI schema `HTTPValidationError` (`detail: array<ValidationError>`) and `ValidationError`
   (`loc: array<string|integer>`, `msg: string`, `type: string`; all required). Endpoints carry
   `resp=...;422:HTTPValidationError`.
2. **`loc` items are `string | integer`, modeled as `List<String>`.** VERIFIED (schema) /
   Corrected note added in §5 (the draft modeled only strings; stringification is the chosen port).
3. **Auth endpoints exist: `POST /ui/session/start`, `POST /ui/session/finalize`, `GET /ui/me`,
   and three verify routes `POST /ui/mfa/totp/verify`, `/ui/mfa/sms/verify`, `/ui/mfa/email/verify`.**
   VERIFIED. OpenAPI index `POST /ui/session/start` (`req=UiSessionStartReq`,
   `resp=200:UiSessionStartResp;422:HTTPValidationError`), `POST /ui/session/finalize`
   (`req=UiSessionFinalizeReq`), `GET /ui/me`, `POST /ui/mfa/totp/verify` (`TotpVerifyReq`),
   `POST /ui/mfa/sms/verify` (`SmsVerifyReq`), `POST /ui/mfa/email/verify` (`EmailVerifyReq`).
   CORRECTED: the draft wrote a single `/ui/mfa/{totp|sms|email}/verify` route.
4. **`normalizeErrorDetail` collapses string / array / object detail.** VERIFIED.
   `src/api/client.ts: normalizeErrorDetail` (string→itself; array→map each item's `msg`,
   `filter(Boolean)`, `join(", ")`; object→`mapAuthorizationError` then `{msg}` fallback else the
   passed `fallback`).
5. **Validation array joins with `", "` over ALL items.** CORRECTED (was `"; "`, first-only).
   `src/api/client.ts: normalizeErrorDetail` → `messages.join(", ")`.
6. **Auth code map keys.** CORRECTED. `src/api/client.ts: mapAuthorizationError` defines exactly:
   `role_required_scope`, `role_required_admin_profile_type`, `role_required`,
   `helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`. The
   draft's `helpdesk_locked`/`helpdesk_review`/`helpdesk_contact` and a `helpdesk_*` prefix
   fallback do not exist.
7. **`role_required` message text.** CORRECTED. `src/api/client.ts: mapAuthorizationError`:
   "You don't currently have permission for this action. Request temporary elevation or contact a
   general admin/root operator." (draft had "You don't have permission to access this.")
8. **`geo_blocked` handling.** CORRECTED. `src/api/client.ts` 403 branch (the `rawDetail.code ===
   "geo_blocked"` block): NOT in the auth-code map; prefers backend `message`, fallback
   "This content is not available in your region.", and stashes the detail for a GeoBlocked screen.
   Draft had it in the code map with text "This content isn't available in your region."
9. **Unmapped coded objects do NOT use their `message` field as a generic fallback.** CORRECTED.
   `src/api/client.ts: normalizeErrorDetail` only has a `{msg}` (validation-style) object fallback
   and otherwise returns the caller `fallback`; there is no `{code,message}` → `message` path.
10. **Network/transport error → status 0.** VERIFIED. `src/api/client.ts` catch block:
    `throw new ApiError(0, "Network error", err)` with toast "Network error — check your
    connection and try again". (Android adds a `STATUS_PARSE = -1` sentinel — see assumptions.)
11. **401 handling reads `detail` via `normalizeErrorDetail` with fallback "Authentication
    required".** VERIFIED. `src/api/client.ts` 401 branch. (AND-013 owns the refresh retry; this
    ticket only sets `status=401`.)
12. **The web `ApiError` carries `(status: number, detail: string, body?: unknown)` and lives in
    `client.ts`, not `types.ts`.** VERIFIED/CORRECTED. `src/api/client.ts: class ApiError`;
    `src/api/types.ts` has no `ApiError`/`ErrorDetail` export (the draft mis-cited `types.ts`).
13. **Coded `detail` codes are absent from `/openapi.json`.** VERIFIED (negative). A grep of
    `openapi.pretty.json` for `role_required|geo_blocked|helpdesk_*` returns no hits — they are
    runtime-only. Resolves Q-3.
14. **Moshi `Any?` decoding of `detail` distinguishes the union (String/List/Map/Double).**
    UNVERIFIED-ASSUMPTION (framework ref). Standard Moshi behavior for `Any`; not provable from
    these sources. See Open assumptions.
15. **Kotlin/Moshi/Retrofit/OkHttp/AGP/Gradle/JDK pins.** UNVERIFIED-ASSUMPTION here (inherited
    from AND-010); not re-checked against build files in this review (out of scope for this ticket's
    sources). Treat as AND-010's responsibility.

### Corrections made

- §2: web error types live in `src/api/client.ts` (class `ApiError`, `normalizeErrorDetail`,
  `mapAuthorizationError`), not `types.ts`.
- §4.2: replaced fabricated `helpdesk_locked/review/contact` codes and generic `geo_blocked`
  mapping with the verified six-code map; removed the nonexistent `helpdesk_*` prefix fallback;
  added `role_required_scope` / `role_required_admin_profile_type`.
- §4.3: validation join corrected to `", "` over all items; coded fallback corrected so only
  `geo_blocked` consumes a backend `message`; `DefaultErrorStrings` updated to verbatim web copy.
- §5: corrected Shape C examples (role_required body/text, geo_blocked message-first behavior,
  real helpdesk codes), the MFA path notation (three distinct verify routes), and the source
  citation (client.ts vs types.ts; coded objects absent from OpenAPI).
- FR-4 / FR-5: corrected join behavior, coded fallback, and the code set.
- §9: corrected `strings.xml` key list to match the new keys.
- §11: T-2/T-3/T-4/T-5/T-6 expectations corrected to verified strings/behavior.
- §13 Q-3 and §15 DoD: corrected the authoritative source (client.ts, not `/openapi.json`).

### Open assumptions

- **OFFLINE / PARSE / GENERIC default copy** (`error_offline`, `error_unexpected`,
  `error_generic`): UNVERIFIED. The web has no exact one-to-one resource; `OFFLINE` mirrors the web
  toast text, but `PARSE` ("We received an unexpected response…") and the `GENERIC` default are
  client-authored. `GENERIC` stands in for the web's *per-call* `fallback` argument
  (`res.statusText` / "Permission denied" / "Authentication required"), which Android cannot
  reproduce 1:1 since it normalizes lazily — product sign-off on a single generic string is needed.
- **`STATUS_PARSE = -1` sentinel and the `JsonDataException` → PARSE classification:** Android-only;
  the web has no parse-sentinel (it does `res.json().catch(() => null)` and normalizes). Reasonable
  but unverifiable against the web.
- **Moshi `Any?` union decoding** (claim 14): relies on Moshi defaults; framework ref only.
- **`required_scope` humanization** (`auth_support`/`billing_support`/`content_moderation` →
  friendly text): VERIFIED in `src/api/client.ts: humanizeScope`, but the Android resource form
  (`%1$s` interpolation) is an assumed implementation detail.

## 17. Test Plan

Test cases for the error model/mapping. JVM unit + MockWebServer contract tests dominate; a couple
of instrumented/Compose cases verify resource resolution and accessibility at the seam this ticket
defines (UI rendering itself is owned downstream). Each case traces to §14 AC(s).

- **TC-AND-015-01 — String detail happy path.** Type: unit. Preconditions: `ApiErrorParser` with
  AND-010 Moshi. Steps: `parseDetail("""{"detail":"Invalid challenge"}""")`; normalize. Expected:
  `ErrorDetail.Message("Invalid challenge")`; `userMessage == "Invalid challenge"`. Traces: AC-1,
  AC-3, AC-4.
- **TC-AND-015-02 — Validation array, single + multi item join.** Type: unit. Preconditions: as
  above. Steps: parse a 422 `HTTPValidationError` body with one `{loc,msg,type}` item, then a
  two-item body. Expected: single → literal `"field required"`; multi → both `msg` joined with
  `", "` (NOT `"; "`); `loc` integers stringified. Traces: AC-1, AC-3, AC-4.
- **TC-AND-015-03 — Coded `role_required` maps and overrides backend message.** Type: unit.
  Steps: parse `{"detail":{"code":"role_required","message":"ignored"}}`; resolve via
  `DefaultErrorStrings`. Expected: equals the verified ROLE_REQUIRED copy ("You don't currently
  have permission…contact a general admin/root operator."); backend `message` ignored. Traces:
  AC-1, AC-4, AC-5.
- **TC-AND-015-04 — Coded `role_required_scope` interpolates humanized scope.** Type: unit. Steps:
  parse `{"detail":{"code":"role_required_scope","required_scope":"billing_support"}}`. Expected:
  key `ROLE_REQUIRED_SCOPE`; resolved string contains "billing support" and "Request temporary
  elevation". Traces: AC-4, AC-5.
- **TC-AND-015-05 — `geo_blocked` prefers backend message, falls back otherwise.** Type: unit.
  Steps: (a) `{"detail":{"code":"geo_blocked","message":"Blocked in XX","country":"XX"}}`; (b)
  same without `message`. Expected: (a) `userMessage == "Blocked in XX"`; (b) == "This content is
  not available in your region."; `extra["country"] == "XX"` in both. Traces: AC-1, AC-4, AC-5,
  AC-7.
- **TC-AND-015-06 — Helpdesk family + no prefix fallback.** Type: unit. Steps: parse each of
  `helpdesk_claim_required`, `helpdesk_assignee_required`, `helpdesk_claim_not_available`, then an
  unmapped `helpdesk_unknown`. Expected: first three resolve to their verified copy; the unmapped
  one → `GENERIC` (no prefix fallback). Traces: AC-4, AC-5.
- **TC-AND-015-07 — Unknown coded object → generic, message not surfaced.** Type: unit. Steps:
  `Coded("widget_exploded", message="boom")` and `message=null`. Expected: both → `GENERIC`
  string (the web never surfaces a `{code,message}` message for arbitrary codes). Traces: AC-4,
  AC-5.
- **TC-AND-015-08 — Totality on malformed / hostile bodies.** Type: unit. Preconditions: includes
  flaky-dev-host shapes. Steps: `parseDetail` over `null`, `""`, `"not json"`,
  `"<html>502 Bad Gateway</html>"`, `{"detail":42}`, `{"detail":[]}`, `{"detail":{}}`. Expected:
  each → `ErrorDetail.Empty` (or empty `Validation`) → `GENERIC`; no exception thrown. Traces:
  AC-3.
- **TC-AND-015-09 — HttpException extraction via MockWebServer.** Type: contract/MockWebServer.
  Preconditions: Retrofit pointed at MockWebServer; AND-010 Moshi. Steps: enqueue HTTP 403 with a
  coded `geo_blocked` body; make a call that throws `retrofit2.HttpException`; run
  `ApiErrorParser.from(ex)`. Expected: `status == 403`, parsed `Coded("geo_blocked", ...)`, correct
  `userMessage`, raw `body` captured, `errorBody().string()` read exactly once without
  `IllegalStateException`. Traces: AC-7.
- **TC-AND-015-10 — Transport vs parse classification.** Type: unit. Steps:
  `fromTransport(SocketTimeoutException())`, `fromTransport(UnknownHostException())`,
  `fromTransport(JsonDataException("x"))`. Expected: first two → `status == 0` + `OFFLINE`; third →
  `status == -1` + `PARSE`. Traces: AC-6.
- **TC-AND-015-11 — Flaky-dev-host non-JSON 5xx end to end.** Type: contract/MockWebServer.
  Preconditions: simulate the unreliable plaintext dev host. Steps: enqueue 502 with an HTML body
  and `Content-Type: text/html`; trigger `HttpException`; run `from(ex)`. Expected: `status == 502`,
  `detail == Empty`, `userMessage == GENERIC`; no crash. Traces: AC-3, AC-6.
- **TC-AND-015-12 — Security: raw body / PII not leaked into user message.** Type: unit. Steps:
  parse a coded body containing an internal field (e.g. `{"code":"role_required","stack":"..."}`);
  inspect `userMessage`. Expected: message is the curated ROLE_REQUIRED string only; no `stack`,
  `body`, or `extra` content appears in `userMessage` (raw kept only in `ApiError.body`). Traces:
  AC-5, AC-7 (supports §8).
- **TC-AND-015-13 — Resource parity (key→string + strings.xml).** Type: unit (+ lint-style).
  Steps: assert every `ErrorMessageKey` has a `DefaultErrorStrings` entry; assert each maps to a
  declared `R.string.*` id (parity test against `strings.xml`). Expected: no missing keys; the
  `%1$s` placeholder present for `error_role_required_scope`. Traces: AC-8.
- **TC-AND-015-14 — Accessibility/i18n of resolved messages (instrumented).** Type:
  instrumented/Compose-UI. Preconditions: a minimal Compose `Text` rendering a resolved
  `userMessage`; `Context`-backed resolver. Steps: render ROLE_REQUIRED and GEO_BLOCKED; switch
  locale; run TalkBack/semantics assertions. Expected: strings resolve from resources (localizable),
  carry text semantics for screen readers, are full sentences, and contain no raw codes/jargon.
  Traces: AC-8 (supports §9).

### Coverage matrix

| §14 AC | Covered by |
| --- | --- |
| AC-1 (representative bodies → expected messages) | TC-01, TC-02, TC-03, TC-05 |
| AC-2 (`ApiError` shape + helpers) | TC-09, TC-10 (construct + `isTransport`/`isAuth`/`status`) |
| AC-3 (union discrimination + totality) | TC-01, TC-02, TC-08, TC-11 |
| AC-4 (`normalizeErrorDetail` web parity) | TC-01, TC-02, TC-03, TC-05, TC-06, TC-07 |
| AC-5 (`mapAuthCode` codes + null) | TC-03, TC-04, TC-05, TC-06, TC-07, TC-12 |
| AC-6 (transport/HTTP/parse classification) | TC-10, TC-11 |
| AC-7 (`HttpException` extraction + `extra`) | TC-05, TC-09, TC-12 |
| AC-8 (key/string parity + localizable) | TC-13, TC-14 |
| AC-9 (all tests green, clean build) | All TC-01…TC-14 (CI gate) |
