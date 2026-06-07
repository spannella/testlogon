---
id: AND-251
title: Earnings API + DTOs
milestone: M6
epic: E34
priority: P0
size: M
status: reviewed
reviewed_on: 2026-06-06
depends_on: [AND-027]
blocks: [AND-252, AND-253, AND-254]
---

# AND-251 — Earnings API + DTOs

## 1. Overview & Goal

This ticket defines the typed HTTP transport seam for the Creator **Earnings**
domain: the Retrofit service interface `EarningsApi` plus the Moshi DTOs and
domain-model adapters that decode the backend's earnings payloads. It is the
Android counterpart of the web reference module
`frontend/src/api/endpoints/earnings.ts` and its shared types in
`frontend/src/api/types.ts`.

Scope, verbatim from the backlog: *`earnings.ts` endpoints/DTOs (summary,
series).* The single acceptance criterion is: *Earnings payloads map (tested).*

This is a **transport + model-mapping** ticket. It owns:

- the `EarningsApi` Retrofit interface (method, path, query params, response
  type) for the `/ui/earnings/*` endpoints — primarily `summary` (which carries
  the time **series**) plus the companion `quick-stats` and `transactions`
  endpoints that the dashboard (E34) needs;
- the wire DTOs (`@JsonClass(generateAdapter = true)`), placed in `core-model`;
- pure mapping functions from DTO → `core-model` domain types, including the
  cents→currency normalisation the UI relies on;
- a `MockWebServer` test suite proving each payload decodes and maps exactly.

It explicitly does **not** own: the repository that caches/sequences these calls
and exposes `Flow`s (AND-252, `EarningsRepository`), the Paging 3 source for
transactions (folded into AND-252/AND-254), the ViewModel/UiState (AND-253), or
any Compose UI / charts (E34 screen tickets). Cross-cutting concerns — the
persistent cookie jar (AND-011), CSRF header injection (AND-012), the
401→refresh `Authenticator` (AND-013), `ApiResult<T>` wrapping (AND-018),
`detail` error mapping (AND-015), and idempotent-GET retry/backoff (AND-016) —
already attach to the shared `OkHttpClient`/`Retrofit` and apply to
`EarningsApi` calls without changes here.

## 2. Context & References

- **Repo / location:** `spannella/testlogon`, monorepo subfolder `android/`,
  branch `android-port`. Wire DTOs and domain models land in module
  **`core-model`** under package
  `com.testlogon.android.core.model.earnings`; the Retrofit interface and its
  Hilt provider land in **`core-network`** under
  `com.testlogon.android.core.network.earnings`.
- **Canonical package:** `com.testlogon.android` everywhere.
- **Stack pins relevant here:** Kotlin 2.0.21, Retrofit **2.11.0**, OkHttp
  **4.12.0**, Moshi **1.15.x** (codegen via KSP), Hilt (KSP), Coroutines, JDK 17,
  minSdk 24 / compileSdk 35.
- **Module layering:** `app -> feature-* -> core-*`. `EarningsApi` lives in
  `core-network`, references DTOs in `core-model`, and is consumed by
  `core-data` (AND-252). No `feature-*`/`app` symbols leak into `core-*`.
- **Upstream dependency — AND-027 (AuthApi / session endpoints):** establishes
  the shared Retrofit, the cookie-based session, and the Hilt provider pattern
  this ticket mirrors. All `/ui/earnings/*` calls are session-gated (cookies +
  `X-CSRF-Token`) and require an authenticated principal; the dependency
  guarantees that machinery exists before earnings calls are made.
- **Backend contract:** FastAPI + DynamoDB, OpenAPI at
  `http://18.222.237.167:8000/openapi.json` (dev, **plaintext HTTP**,
  unreliable). Relevant operations: `earnings_summary_ui_earnings_summary_get`,
  `earnings_quick_stats_ui_earnings_quick_stats_get`,
  `earnings_transactions_ui_earnings_transactions_get`. Response schemas:
  `EarningsSummaryOut`, `TimeSeriesPoint`, `EarningsBreakdown`,
  `EarningsQuickStatsOut`, `EarningsTransactionsOut`, `EarningsTransactionOut`.
- **Web reference:** `frontend/src/api/endpoints/earnings.ts` for the call shape
  and query-param conventions; `frontend/src/api/types.ts` for field names.
  Caveat: the web `EarningsSummary` TS interface (`src/api/types.ts`) **omits**
  `time_series` and the web `getEarningsSummary` call sends only
  `from_date`/`to_date`/`granularity` (no `from_ts`/`to_ts`). The
  authoritative field/param set for this ticket is the **OpenAPI** schema
  (`EarningsSummaryOut` carries `time_series`; the operation accepts
  `from_ts`/`to_ts`), which we follow.

## 3. Functional Requirements

FR-1. Expose a suspend-fun Retrofit interface `EarningsApi` covering three GET
endpoints: summary (with embedded time series), quick-stats, and transactions
(cursor-paginated).

FR-2. `summary` MUST accept the optional filter parameters `from_date`,
`to_date` (ISO `YYYY-MM-DD`, UTC), `granularity` (`day`|`week`|`month`, default
`day`), and the Unix-seconds alternatives `from_ts`/`to_ts`. Nulls MUST be
omitted from the query string, not serialised as `from_date=null`.

FR-3. `transactions` MUST accept `limit` (1–200, default 50), `cursor`
(opaque, nullable), and the same date/ts window params as summary. The response
MUST surface `next_cursor` for downstream paging (AND-254).

FR-4. All DTOs MUST decode the backend's `*_cents` integer money fields and the
ISO `date` bucket label of each series point without loss. Decoding MUST be
tolerant of missing optional fields (backend supplies schema defaults such as
`tips: 0`, `currency: "USD"`).

FR-5. Provide pure mapper functions DTO → domain model that (a) keep money as
integer minor units (`Long` cents) — never floats — and (b) expose a derived
`Money(amountCents, currencyCode)` value type so the UI never re-implements
cents handling.

FR-6. The series mapper MUST preserve point order as returned by the backend and
parse each `date` string into a `LocalDate` while retaining the raw label for
display fallback when the granularity is week/month.

FR-7. A Hilt provider MUST construct `EarningsApi` from the shared session
`Retrofit`. No new `OkHttpClient` is created.

FR-8. No UI, no caching, no `Flow`, no ViewModel here — this ticket ends at
"callable interface + decoded domain models, proven by tests."

## 4. Technical Design

**Module placement.** DTOs + domain models + mappers in `core-model`
(`build.gradle.kts` already applies Moshi KSP). Interface + provider in
`core-network`.

**Retrofit interface** (`core-network/.../earnings/EarningsApi.kt`):

```kotlin
package com.testlogon.android.core.network.earnings

import com.testlogon.android.core.model.earnings.dto.EarningsSummaryDto
import com.testlogon.android.core.model.earnings.dto.EarningsQuickStatsDto
import com.testlogon.android.core.model.earnings.dto.EarningsTransactionsDto
import retrofit2.http.GET
import retrofit2.http.Query

interface EarningsApi {

    @GET("ui/earnings/summary")
    suspend fun getSummary(
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("granularity") granularity: String = "day",
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): EarningsSummaryDto

    @GET("ui/earnings/quick-stats")
    suspend fun getQuickStats(): EarningsQuickStatsDto

    @GET("ui/earnings/transactions")
    suspend fun getTransactions(
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): EarningsTransactionsDto
}
```

Retrofit omits `@Query` parameters whose value is `null`, satisfying FR-2/FR-3
without manual map building. The `user_sub`, `X-SESSION-ID`, and
`X-IMPERSONATION-TOKEN` parameters in the OpenAPI spec are server-side
operator/impersonation hooks; the mobile client relies on the session cookie and
deliberately omits them.

**Hilt provider** (`core-network/.../earnings/EarningsNetworkModule.kt`):

```kotlin
@Module
@InstallIn(SingletonComponent::class)
object EarningsNetworkModule {
    @Provides
    @Singleton
    fun provideEarningsApi(retrofit: Retrofit): EarningsApi =
        retrofit.create(EarningsApi::class.java)
}
```

`Retrofit` here is the qualified session-scoped instance built in the network
baseline (AND-010/AND-027), already carrying cookie jar, CSRF interceptor,
authenticator, and Moshi converter.

**Mapping layer** (`core-model/.../earnings/EarningsMappers.kt`): pure
top-level extension functions `fun EarningsSummaryDto.toDomain(): EarningsSummary`
etc. Mapping is total and null-safe; defaults mirror the backend
(`currency ?: "USD"`, missing breakdown component → `0`). `date` strings are
parsed with `LocalDate.parse(...)` inside a `runCatching` so a malformed bucket
label degrades to `rawDate` rather than throwing.

## 5. API Contract

Base URL: runtime-selected host (dev `http://18.222.237.167:8000`). All paths
relative to that base; all calls session-authenticated (cookies +
`X-CSRF-Token`). All money fields are integer **cents**.

**GET `/ui/earnings/summary`** → `200 EarningsSummaryOut`

Query (all optional): `from_date`, `to_date` (`YYYY-MM-DD`),
`granularity` (`day`|`week`|`month`, default `day`), `from_ts`, `to_ts` (Unix s).

```json
{
  "total_cents": 1284350,
  "currency": "USD",
  "transaction_count": 412,
  "breakdown": {
    "subscriptions": 800000,
    "tips": 250000,
    "unlocks": 150000,
    "vod_purchases": 80350,
    "other": 4000
  },
  "time_series": [
    { "date": "2026-05-01", "total": 41000, "tips": 9000,
      "subscriptions": 25000, "unlocks": 5000, "vod_purchases": 2000, "other": 0 }
  ]
}
```

**GET `/ui/earnings/quick-stats`** → `200 EarningsQuickStatsOut`

```json
{
  "today_cents": 12000,
  "this_week_cents": 89000,
  "this_month_cents": 412000,
  "all_time_cents": 1284350,
  "pending_payout_cents": 250000,
  "currency": "USD"
}
```

**GET `/ui/earnings/transactions`** → `200 EarningsTransactionsOut`

Query: `limit` (1–200, default 50), `cursor`, `from_date`, `to_date`,
`from_ts`, `to_ts`.

```json
{
  "items": [
    { "entry_id": "ee_01H...", "ts": 1746057600, "amount_cents": 999,
      "reason": "Tip from @fan", "category": "tips", "currency": "USD",
      "meta": { "post_id": "p_123" } }
  ],
  "next_cursor": "eyJrIjoiZWVfMDFIIn0="
}
```

Error envelope (all endpoints, via AND-015): the **only** error response these
three operations document in the OpenAPI spec is `422 HTTPValidationError`, whose
`detail` is an **array** of `ValidationError` objects (`[{ "loc": [...],
"msg": "...", "type": "..." }]`) — verified against `components.schemas.
HTTPValidationError` / `ValidationError`. At runtime FastAPI may also emit the
plain-string form (`HTTPException(detail="…")`) and some handlers a
`{ "code": "…", … }` object; the web client's `normalizeErrorDetail` already
tolerates all three, so AND-015's adapter is expected to do the same. This ticket
does **not** re-map errors; it relies on the shared error adapter. `401` triggers
the shared `Authenticator` (one refresh + retry — matching the web client's
single-refresh-then-retry path in `src/api/client.ts`). The dev host's `422`
validation errors are mapped by AND-015 and surfaced to AND-253.

## 6. Data & State Management

DTOs in `com.testlogon.android.core.model.earnings.dto` (Moshi codegen):

```kotlin
@JsonClass(generateAdapter = true)
data class EarningsSummaryDto(
    @Json(name = "total_cents") val totalCents: Long = 0,
    val currency: String = "USD",
    @Json(name = "transaction_count") val transactionCount: Int = 0,
    val breakdown: EarningsBreakdownDto = EarningsBreakdownDto(),
    @Json(name = "time_series") val timeSeries: List<TimeSeriesPointDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class EarningsBreakdownDto(
    val subscriptions: Long = 0, val tips: Long = 0, val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0, val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TimeSeriesPointDto(
    val date: String,
    val total: Long = 0, val tips: Long = 0, val subscriptions: Long = 0,
    val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0, val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class EarningsQuickStatsDto(
    @Json(name = "today_cents") val todayCents: Long = 0,
    @Json(name = "this_week_cents") val thisWeekCents: Long = 0,
    @Json(name = "this_month_cents") val thisMonthCents: Long = 0,
    @Json(name = "all_time_cents") val allTimeCents: Long = 0,
    @Json(name = "pending_payout_cents") val pendingPayoutCents: Long = 0,
    val currency: String = "USD",
)

@JsonClass(generateAdapter = true)
data class EarningsTransactionsDto(
    // NB: `items` is `required` in EarningsTransactionsOut; the `emptyList()`
    // default is a defensive convenience for the unreliable dev host returning
    // `200 {}`, not a relaxation of the contract.
    val items: List<EarningsTransactionDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class EarningsTransactionDto(
    @Json(name = "entry_id") val entryId: String,
    val ts: Long,
    @Json(name = "amount_cents") val amountCents: Long,
    val reason: String = "",
    val category: String = "",
    val currency: String = "USD",
    val meta: Map<String, Any?> = emptyMap(),
)
```

Domain models in `com.testlogon.android.core.model.earnings`:

```kotlin
data class Money(val amountCents: Long, val currencyCode: String)

data class EarningsSummary(
    val total: Money,
    val transactionCount: Int,
    val breakdown: EarningsBreakdown,
    val series: List<EarningsSeriesPoint>,
)
data class EarningsBreakdown(
    val subscriptions: Long, val tips: Long, val unlocks: Long,
    val vodPurchases: Long, val other: Long, val currencyCode: String,
)
data class EarningsSeriesPoint(
    val date: LocalDate?, val rawDate: String, val totalCents: Long,
    val tipsCents: Long, val subscriptionsCents: Long, val unlocksCents: Long,
    val vodPurchasesCents: Long, val otherCents: Long,
)
data class EarningsQuickStats(
    val today: Money, val thisWeek: Money, val thisMonth: Money,
    val allTime: Money, val pendingPayout: Money,
)
data class EarningsTransaction(
    val entryId: String, val timestampEpochSeconds: Long, val amount: Money,
    val reason: String, val category: EarningsCategory, val rawCategory: String,
)
data class EarningsTransactionsPage(
    val items: List<EarningsTransaction>, val nextCursor: String?,
)
enum class EarningsCategory { SUBSCRIPTION, TIP, UNLOCK, VOD_PURCHASE, OTHER;
    companion object { fun from(raw: String): EarningsCategory = /* lenient */ }
}
```

`meta` is intentionally dropped from the transaction domain model (UI does not
read it); it stays decodable to avoid Moshi failures on unknown extras. No Room
or DataStore writes occur here — persistence/caching belongs to AND-252.
This ticket produces immutable value objects only; there is no mutable state.

## 7. Error Handling & Resilience

- Network/transport failures, timeouts (~20s per the shared OkHttp config), and
  HTTP error codes are converted to `ApiResult.Failure` by the shared
  `apiCall {}` wrapper (AND-018) layered in AND-252 — `EarningsApi` itself
  returns the decoded body or throws, per Retrofit suspend semantics.
- All three operations are **idempotent GETs**, so the bounded-backoff retry
  policy (AND-016) applies; this ticket adds nothing beyond honouring it.
- Moshi decoding is defensive: every numeric/string field has a default so a
  partially-populated payload still decodes. The only required fields are
  `TimeSeriesPointDto.date`, `EarningsTransactionDto.entry_id/ts/amount_cents`,
  matching the backend's `required` lists; a payload missing these is a genuine
  contract violation and is allowed to surface as a decode error.
- `date` parsing failures degrade gracefully: `EarningsSeriesPoint.date` becomes
  `null` while `rawDate` is preserved, so weekly/monthly bucket labels (which may
  not be valid `YYYY-MM-DD`) never crash mapping.
- The unreliable dev host (plaintext HTTP, intermittent 5xx) is handled by the
  shared retry + offline/stale states owned downstream; mapping is pure and
  side-effect-free, so it is safe to call repeatedly.

## 8. Security & Privacy

- All earnings endpoints are session-gated; auth rides on the persistent cookie
  jar (AND-011) and the `X-CSRF-Token` header (AND-012). No tokens or
  credentials are handled in this ticket.
- Earnings figures and transaction reasons are sensitive financial PII. They
  MUST NOT be logged (see §10) and MUST NOT be written to any plaintext store
  here (no caching in this ticket; AND-252 owns any at-rest decisions).
- The `user_sub` / `X-IMPERSONATION-TOKEN` operator parameters are deliberately
  not exposed on the mobile interface, preventing a client from requesting
  another principal's earnings.
- Dev traffic is plaintext HTTP on the dev host only; release builds target
  HTTPS hosts. No cleartext exemption is widened by this ticket.

## 9. Accessibility & i18n

No UI is delivered here, so screen-level a11y is N/A and owned by the E34 screen
tickets (dashboard/charts). This ticket supports i18n/l10n by:

- never formatting currency in the data layer — money is carried as
  `Money(amountCents, currencyCode)` so the UI can apply a locale-aware
  `NumberFormat.getCurrencyInstance(locale)`;
- preserving `currencyCode` from the payload rather than hard-coding `$`;
- keeping date as `LocalDate` (+ raw label) for locale-aware formatting upstream.

## 10. Telemetry & Logging

- Reuse the redacted-logging policy from the auth area (AND-052). Earnings
  amounts, transaction reasons, and cursors MUST be redacted from any HTTP log;
  the OkHttp logging interceptor stays at `BASIC` (or `NONE` in release) so
  bodies are never emitted.
- This ticket emits no analytics events. Any "earnings_viewed"-style telemetry
  belongs to the ViewModel/screen tickets (AND-253 / E34) and must use
  non-PII counters only (e.g. event name + granularity, never amounts).
- A single non-PII debug log line on decode failure (`EarningsApi: decode
  failed for <endpoint>` with no body) is permitted to aid contract debugging.

## 11. Testing Strategy

All tests are JVM unit tests in `core-network`/`core-model` using
`MockWebServer` + the real Moshi instance and the `core-testing` fixtures
(AND-046). Targeted, fully covering the single acceptance criterion ("Earnings
payloads map (tested)").

Fixtures: `summary_full.json`, `summary_empty_series.json`,
`summary_missing_optional_fields.json`, `quick_stats.json`,
`transactions_page1.json` (with `next_cursor`), `transactions_last_page.json`
(`next_cursor: null`), `transactions_weekly_dates.json`, plus a `422`
validation-error body.

- **T-1 Path/verb/query:** enqueue 200s; call each method; assert
  `RecordedRequest.method == GET` and the resolved path/query
  (`/ui/earnings/summary?granularity=day`, etc.). Assert null params are
  **absent** from the query string.
- **T-2 Summary mapping:** decode `summary_full.json`; assert `totalCents`,
  `transactionCount`, every `breakdown` component, and that `series` preserves
  order and length; assert `series[0].date == LocalDate.parse("2026-05-01")`.
- **T-3 Defaults tolerance:** `summary_missing_optional_fields.json` decodes with
  `tips==0`, `currency=="USD"`, empty `time_series`.
- **T-4 Series date degradation:** `transactions`/summary weekly labels that are
  not `YYYY-MM-DD` map to `date == null` with `rawDate` retained (no throw).
- **T-5 Quick-stats mapping:** all five `Money` fields map to correct cents +
  currency.
- **T-6 Transactions paging:** `next_cursor` is surfaced; last-page maps to
  `nextCursor == null`; `category` maps via `EarningsCategory.from` including an
  unknown category → `OTHER`.
- **T-7 Limit clamping contract:** calling `getTransactions(limit = 50)` emits
  `limit=50`; document (not enforce) that values outside 1–200 are a backend 422.
- **T-8 Money invariant:** assert no field is a `Double`/`Float` anywhere in the
  DTO/domain graph (reflection-based guard test).

Coverage gate: 100% of the mapper functions exercised.

## 12. Dependencies & Sequencing

- **Depends on AND-027** (AuthApi / session endpoints) — provides the shared
  session `Retrofit`, cookie jar, CSRF, and the Hilt provider pattern reused
  here. Transitively depends on AND-010 (Retrofit+Moshi), AND-009 (OkHttp),
  AND-011/012/013 (cookies/CSRF/refresh), AND-015 (error mapping), AND-016
  (idempotent-GET retry), AND-018 (`ApiResult`), AND-046 (MockWebServer harness).
- **Blocks** the Earnings repository (AND-252, which wraps these calls in
  `ApiResult`, adds caching and `Flow`s), the Earnings ViewModel/UiState
  (AND-253), and the transactions Paging source (AND-254). Those AND-### ids are
  the downstream owners of caching, state, and UI for the E34 epic.
- Sequencing: land DTOs + mappers + interface + provider + tests together; merge
  to `android-port` before AND-252 begins.

## 13. Risks & Open Questions

- **Series granularity label format.** `granularity=week|month` may return
  `date` strings that are not `YYYY-MM-DD` (e.g. `2026-W18` or `2026-05`). Risk
  mitigated by the `rawDate` fallback; open question whether the backend
  guarantees a parseable format — confirm against `/openapi.json` examples or the
  web app before E34 chart work.
- **Currency mixing.** Backend allows per-field/per-transaction `currency`; if a
  creator has mixed-currency entries, summing in the UI is undefined. Open
  question for AND-253: clamp to the summary's top-level `currency` or display
  per-row. This ticket faithfully preserves whatever the payload states.
- **`pending_payout_cents` semantics** (gross vs. net, included in `all_time`?)
  are unspecified in the schema — flag for the Payouts epic (E35).
- **Unreliable dev host** can return empty/partial bodies; defensive defaults
  cover most cases, but a truly empty `200 {}` summary will map to an all-zero
  `EarningsSummary` — acceptable, surfaced as an "empty" state downstream.
- **`meta` shape** on transactions is `additionalProperties: true`; we decode but
  discard it. If a future requirement needs `meta.post_id` for deep links, the
  DTO already captures it.

## 14. Acceptance Criteria

1. `EarningsApi` exists in `core-network` with `getSummary`, `getQuickStats`,
   `getTransactions` suspend functions at the exact paths
   `ui/earnings/summary|quick-stats|transactions`, GET verb, and the query
   params in §4; null query params are omitted from the wire request (proved by
   `MockWebServer` `RecordedRequest`).
2. All DTOs and domain models in §5–§6 exist in `core-model` with Moshi codegen;
   the module compiles with no hand-written adapters.
3. `summary_full.json`, `quick_stats.json`, and `transactions_page1.json`
   fixtures decode and map to the domain models with every field asserted —
   **"Earnings payloads map (tested)"** is satisfied.
4. Money is integer cents end-to-end; no `Float`/`Double` exists in the DTO or
   domain graph (guard test passes).
5. Time **series** order is preserved; valid dates parse to `LocalDate`,
   non-parseable bucket labels degrade to `date == null` with `rawDate` kept.
6. `next_cursor` is surfaced on the transactions page; last-page maps to
   `nextCursor == null`.
7. A Hilt provider yields `EarningsApi` from the shared session `Retrofit`; no
   new `OkHttpClient`/`Retrofit` is constructed.
8. The full unit-test suite (§11, T-1…T-8) passes in CI (AND-050).

## 15. Definition of Done

- Code merged to `android-port`: `EarningsApi`, `EarningsNetworkModule`, all
  earnings DTOs, domain models, `EarningsCategory`, and `EarningsMappers`, under
  the canonical `com.testlogon.android.core.{network,model}.earnings` packages.
- Unit tests (T-1…T-8) green locally and on CI (AND-050); mapper coverage 100%.
- ktlint/detekt clean (AND-005); no new lint baselines added.
- No earnings amounts, reasons, or cursors appear in any log output (manual
  review against the §10 policy).
- KDoc on `EarningsApi` methods documents each endpoint, its params, and a link
  to the OpenAPI operationId; mapper functions documented as pure/total.
- Downstream tickets AND-252/253/254 can compile against these symbols with no
  further changes to this module (verified by a throwaway consumer stub or the
  repository PR that follows).
- PR description references AND-251 and AND-027, and notes the open questions in
  §13 for the E34 screen/charts and E35 payouts owners.

## 16. Citations & Assumption Audit

Each key technical claim below is paired with a VERDICT and an exact SOURCE
pointer. OpenAPI references are to
`reference/openapi.index.txt` (METHOD /path lines) and
`reference/openapi.pretty.json` (`components.schemas.<Name>`). Frontend
references are paths under `reference/src/`.

1. **`GET /ui/earnings/summary` → `200 EarningsSummaryOut`, query params
   `from_date,to_date,granularity,from_ts,to_ts`.** VERDICT: Verified. SOURCE:
   OpenAPI `GET /ui/earnings/summary` (op
   `earnings_summary_ui_earnings_summary_get`,
   `resp=200:EarningsSummaryOut`, `params=from_date,to_date,granularity,from_ts,
   to_ts,user_sub,X-SESSION-ID,X-IMPERSONATION-TOKEN`); frontend
   `src/api/endpoints/earnings.ts: getEarningsSummary`.
2. **`GET /ui/earnings/quick-stats` → `200 EarningsQuickStatsOut`, no query
   params.** VERDICT: Verified. SOURCE: OpenAPI `GET /ui/earnings/quick-stats`
   (op `earnings_quick_stats_ui_earnings_quick_stats_get`); frontend
   `src/api/endpoints/earnings.ts: getEarningsQuickStats`.
3. **`GET /ui/earnings/transactions` → `200 EarningsTransactionsOut`, query
   params `limit,cursor,from_date,to_date,from_ts,to_ts`.** VERDICT: Verified.
   SOURCE: OpenAPI `GET /ui/earnings/transactions` (op
   `earnings_transactions_ui_earnings_transactions_get`); frontend
   `src/api/endpoints/earnings.ts: getEarningsTransactions` (web sends
   `from_date,to_date,limit,cursor`; `from_ts/to_ts` are OpenAPI-only).
4. **All three operations are GET.** VERDICT: Verified. SOURCE: OpenAPI index
   lines 1431–1433 (all `GET`).
5. **`EarningsSummaryOut` fields: `total_cents` (int, default 0), `currency`
   (str, default "USD"), `transaction_count` (int, default 0), `breakdown`
   (`EarningsBreakdown`), `time_series` (array of `TimeSeriesPoint`).** VERDICT:
   Verified. SOURCE: `components.schemas.EarningsSummaryOut`. Note: the web
   `EarningsSummary` interface (`src/api/types.ts`) omits `time_series` — we
   follow OpenAPI, which includes it.
6. **`EarningsBreakdown` fields: `subscriptions,tips,unlocks,vod_purchases,other`
   (all int, default 0).** VERDICT: Verified. SOURCE:
   `components.schemas.EarningsBreakdown`; mirrors
   `src/api/types.ts: EarningsBreakdown`.
7. **`TimeSeriesPoint` fields: `date` (str, required) + `total,tips,
   subscriptions,unlocks,vod_purchases,other` (int, default 0).** VERDICT:
   Verified. SOURCE: `components.schemas.TimeSeriesPoint` (`required:["date"]`).
8. **`EarningsQuickStatsOut` fields: `today_cents,this_week_cents,
   this_month_cents,all_time_cents,pending_payout_cents` (int, default 0),
   `currency` (str, default "USD"); no required fields.** VERDICT: Verified.
   SOURCE: `components.schemas.EarningsQuickStatsOut`.
9. **`EarningsTransactionOut` fields: `entry_id` (str), `ts` (int),
   `amount_cents` (int) — all required; `reason` (str, default ""), `category`
   (str, default ""), `currency` (str, default "USD"), `meta` (object,
   `additionalProperties: true`).** VERDICT: Verified. SOURCE:
   `components.schemas.EarningsTransactionOut`
   (`required:["entry_id","ts","amount_cents"]`); mirrors
   `src/api/types.ts: EarningsTransaction`.
10. **`EarningsTransactionsOut` fields: `items` (array, required),
    `next_cursor` (string|null).** VERDICT: Verified. SOURCE:
    `components.schemas.EarningsTransactionsOut` (`required:["items"]`); mirrors
    `src/api/types.ts: EarningsTransactionsResp`.
11. **All money fields are integer cents (no float/double).** VERDICT: Verified.
    SOURCE: every `*_cents`/breakdown/series money field is
    `"type": "integer"` across the schemas above.
12. **Auth is session cookie + `X-CSRF-Token` header (CSRF value from `ui_csrf`
    cookie).** VERDICT: Verified. SOURCE: `src/api/client.ts` lines 167–171
    (`getCookie("ui_csrf")` → `headers.set("X-CSRF-Token", csrf)`) and
    `credentials: "include"` (cookie transport).
13. **`401` triggers a single session refresh then one retry.** VERDICT:
    Verified. SOURCE: `src/api/client.ts` lines 194–221 (`refreshSession()` then
    single retry `fetch`).
14. **Error `detail` may be a string, an array `[{msg,…}]`, or an object
    `{code,…}`.** VERDICT: Corrected/clarified. SOURCE: the only documented
    error response for these ops is `422 HTTPValidationError`, whose `detail` is
    an **array** of `ValidationError` (`components.schemas.HTTPValidationError`
    → `ValidationError`). The string/object forms are runtime FastAPI variants
    the web client's `normalizeErrorDetail` (`src/api/client.ts`) handles; they
    are not in the schema for these endpoints. §5 was updated to say so.
15. **`user_sub`, `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` params exist on the
    operations but are operator/impersonation hooks the mobile client omits.**
    VERDICT: Verified (existence) / Assumption (omission policy). SOURCE: OpenAPI
    index lines 1431–1433 list these params; web client only sets
    `X-IMPERSONATION-TOKEN` when an impersonation session is active
    (`src/api/client.ts` lines 162–165). Mobile-omit is a design decision (see
    Open assumptions).
16. **Retrofit omits `@Query` params whose value is `null`.** VERDICT: Verified.
    SOURCE: framework ref — Retrofit `@Query` null-omission behaviour,
    https://square.github.io/retrofit/2.x/retrofit/retrofit2/http/Query.html .
17. **Stack pins: Retrofit 2.11.0, OkHttp 4.12.0, Moshi 1.15.x, Hilt, minSdk 24
    / compileSdk 35.** VERDICT: Unverified-assumption (no source in the provided
    reference set). SOURCE: project convention asserted by the spec; not checkable
    against OpenAPI/frontend.
18. **`granularity=week|month` may return non-`YYYY-MM-DD` `date` labels.**
    VERDICT: Unverified-assumption. SOURCE: `TimeSeriesPoint.date` is an
    unformatted `"type": "string"` with no `format`/examples in OpenAPI; the
    exact week/month label format is not specified anywhere in the references.

### Corrections made

- **§2 (References):** Added a caveat that the web `EarningsSummary` type omits
  `time_series` and the web summary call omits `from_ts`/`to_ts`; declared
  OpenAPI as the authoritative field/param source for this ticket.
- **§5 (API Contract — error envelope):** Clarified that the only
  schema-documented error for these endpoints is `422 HTTPValidationError` with
  an **array** `detail`; the string/object `detail` shapes are runtime variants
  handled by the shared adapter, not part of these operations' schema. Added that
  the `401` single-refresh-then-retry matches the web client.
- **§6 (DTOs):** Annotated `EarningsTransactionsDto.items` to note it is
  `required` in the schema and the `emptyList()` default is a defensive choice
  for the flaky dev host, not a contract relaxation.

No endpoint path, HTTP method, request param, or response field name in the
original spec was found to be factually wrong against OpenAPI — the corrections
above are clarifications and one error-shape fix.

### Open assumptions

- **Stack/version pins (claim 17):** not verifiable from OpenAPI or frontend;
  trusted as project setup from AND-009/010/027.
- **Mobile omission of `user_sub`/impersonation params (claim 15):** a security
  design decision for the Android client; the sources confirm the params exist
  but cannot confirm the mobile policy.
- **Week/month `date` label format (claim 18):** OpenAPI gives `date` as a bare
  string with no examples; the `rawDate` + nullable `LocalDate` fallback is the
  mitigation. Confirm with backend before E34 charts.
- **`pending_payout_cents` semantics (gross/net, overlap with `all_time_cents`):**
  not described in the schema; deferred to E35 (Payouts).
- **Bearer `Authorization` header:** the web client also attaches
  `Authorization: Bearer` (`src/api/client.ts` lines 156–160) in addition to
  cookies. This spec assumes the Android client is cookie-session-only per
  AND-027; if AND-027 also issues a bearer token, the shared interceptor (not
  this ticket) would attach it.

## 17. Test Plan

All cases below are pure JVM/instrumentation tests for a transport+mapping
ticket; no earnings UI is delivered here, so Compose-UI/e2e cases are scoped to
the downstream screen tickets and only a11y-relevant *data-layer* guarantees are
asserted. Test targets: **JVM unit/Robolectric** (local, no device) and
**contract/MockWebServer** (also JVM) cover everything functional. The two
device-class rows exist only to confirm the decoder/mapper behaves identically
across ABI/API; they are NOT required for the acceptance criterion and may be
skipped in PR CI.

- **TC-AND-251-01** — Type: contract/MockWebServer. Target: JVM
  (`core-network`). Preconditions: `MockWebServer` enqueues `200` with
  `summary_full.json`; `EarningsApi` built from a `Retrofit` pointed at the mock.
  Steps: call `getSummary(granularity = "day")`; inspect `RecordedRequest`.
  Expected: `method == "GET"`, path == `/ui/earnings/summary?granularity=day`,
  and no `from_date/to_date/from_ts/to_ts` keys appear in the query string.
  Traces: AC-1.
- **TC-AND-251-02** — Type: contract/MockWebServer. Target: JVM. Preconditions:
  mock enqueues `200` for each endpoint. Steps: call `getQuickStats()` and
  `getTransactions(limit = 50)`; inspect both `RecordedRequest`s. Expected:
  `GET /ui/earnings/quick-stats` with empty query; `GET
  /ui/earnings/transactions?limit=50` with `cursor/from_date/to_date` absent.
  Traces: AC-1.
- **TC-AND-251-03** — Type: unit. Target: JVM (`core-model`). Preconditions:
  real Moshi instance; `summary_full.json` fixture. Steps: decode to
  `EarningsSummaryDto`, call `.toDomain()`. Expected: `total.amountCents ==
  1284350`, `total.currencyCode == "USD"`, `transactionCount == 412`, every
  `breakdown` component equals the fixture, `series` length and order preserved,
  `series[0].date == LocalDate.parse("2026-05-01")` with `rawDate == "2026-05-01"`.
  Traces: AC-3, AC-5.
- **TC-AND-251-04** — Type: unit. Target: JVM. Preconditions:
  `summary_missing_optional_fields.json` (only `time_series[0].date` present,
  everything else omitted). Steps: decode + map. Expected: schema defaults apply
  — `currency == "USD"`, `totalCents == 0`, `breakdown.tips == 0`,
  `transactionCount == 0`, empty/absent series handled without throwing. Traces:
  AC-2, AC-3.
- **TC-AND-251-05** — Type: unit. Target: JVM. Preconditions:
  `summary_weekly_dates.json` whose series `date` values are `"2026-W18"` /
  `"2026-05"` (granularity week/month). Steps: decode + map. Expected: mapping
  does not throw; `EarningsSeriesPoint.date == null`, `rawDate` preserved
  verbatim. Traces: AC-5.
- **TC-AND-251-06** — Type: unit. Target: JVM. Preconditions: `quick_stats.json`.
  Steps: decode `EarningsQuickStatsDto` + map. Expected: all five `Money` fields
  (`today,thisWeek,thisMonth,allTime,pendingPayout`) carry the exact fixture
  cents and `currencyCode == "USD"`. Traces: AC-3.
- **TC-AND-251-07** — Type: unit. Target: JVM. Preconditions:
  `transactions_page1.json` (with `next_cursor`) and `transactions_last_page.json`
  (`next_cursor: null`). Steps: decode + map both. Expected: page1
  `nextCursor == "<fixture>"`; last page `nextCursor == null`; `items` order and
  count preserved; each `amount` is `Money(amount_cents, currency)`. Traces:
  AC-3, AC-6.
- **TC-AND-251-08** — Type: unit. Target: JVM. Preconditions: a transactions
  fixture containing `category` values `"tips"`, `"subscription"`,
  `"vod_purchase"`, and an unknown `"chargeback"`. Steps: map each. Expected:
  known values map to the matching `EarningsCategory`; `"chargeback"` →
  `EarningsCategory.OTHER` with `rawCategory == "chargeback"`. Traces: AC-3.
- **TC-AND-251-09** — Type: unit (reflection guard). Target: JVM. Preconditions:
  none. Steps: reflectively walk every property of all earnings DTOs and domain
  models. Expected: no property is `Double`/`Float`/`kotlin.Double`/`kotlin.Float`
  — money is integer cents end-to-end. Traces: AC-4.
- **TC-AND-251-10** — Type: contract/MockWebServer (error path). Target: JVM.
  Preconditions: mock enqueues `422` with a real `HTTPValidationError` body
  (`{"detail":[{"loc":["query","limit"],"msg":"...","type":"..."}]}`). Steps:
  call `getTransactions(limit = 500)`; observe the thrown `HttpException`.
  Expected: Retrofit raises `HttpException(code = 422)`; the raw `detail` array
  body is available for the shared AND-015 adapter (this ticket asserts the call
  surfaces the 422, not the re-mapping). Traces: AC-1.
- **TC-AND-251-11** — Type: unit (resilience). Target: JVM. Preconditions:
  fixture `200 {}` (empty body, dev-host degraded case). Steps: decode
  `EarningsSummaryDto` + map. Expected: maps to an all-zero `EarningsSummary`
  (`total.amountCents == 0`, empty series, default `currency`) without throwing —
  the "empty state" surfaced downstream. Traces: AC-2, AC-3.
- **TC-AND-251-12** — Type: contract/MockWebServer (offline / flaky host).
  Target: JVM. Preconditions: `MockWebServer` configured to drop the connection
  (`SocketPolicy.DISCONNECT_AT_START`) or no enqueued response. Steps: call
  `getSummary()`. Expected: an `IOException` propagates from the suspend call
  (mapping is never reached); confirms `EarningsApi` does not swallow transport
  errors and leaves `ApiResult` wrapping to AND-252/AND-018. Traces: AC-1.
- **TC-AND-251-13** — Type: contract/MockWebServer (security). Target: JVM.
  Preconditions: mock enqueues `200`s. Steps: invoke all three methods; inspect
  every `RecordedRequest`. Expected: no `user_sub`, `X-SESSION-ID`, or
  `X-IMPERSONATION-TOKEN` is sent by the client; auth is left to the shared
  cookie jar + `X-CSRF-Token` interceptor (not added here). Traces: AC-1, AC-7.
- **TC-AND-251-14** — Type: unit (Hilt graph). Target: JVM / Robolectric.
  Preconditions: a test component installing `EarningsNetworkModule` with a
  fake/shared `Retrofit` binding. Steps: request `EarningsApi` from the graph.
  Expected: a non-null `EarningsApi` is provided from the **shared** `Retrofit`;
  no new `OkHttpClient`/`Retrofit` is instantiated (assert the injected
  `Retrofit` is the same instance). Traces: AC-7.

Device-class confirmation (optional, not gating):

- **TC-AND-251-15** — Type: instrumented. Target: emulator **AVD test35**
  (x86_64, API 35). Preconditions: instrumented variant of TC-03/07 fixtures on
  device. Steps: run the decode+map assertions on-device. Expected: identical
  results to JVM. Rationale: API-35 baseline. Traces: AC-3.
- **TC-AND-251-16** — Type: instrumented. Target: **physical device** Samsung
  Galaxy A15 5G (SM-A156U, serial R5CX821TA9R, arm64-v8a, API 34). Preconditions:
  device connected via adb; same instrumented decode+map suite. Steps: run on the
  arm64 device. Expected: identical results — confirms no ABI/API-34-vs-35
  divergence in Moshi codegen / `LocalDate` parsing. MUST run on the physical
  device (arm64 + API 34 path the emulator cannot represent). Traces: AC-3,
  AC-4, AC-5.

### Coverage matrix

| §14 Acceptance Criterion | Covered by |
| --- | --- |
| AC-1 — paths/verb/query params; null params omitted | TC-01, TC-02, TC-10, TC-12, TC-13 |
| AC-2 — DTOs/domain models exist, Moshi codegen, defaults tolerated | TC-04, TC-11 |
| AC-3 — fixtures decode & map ("payloads map (tested)") | TC-03, TC-04, TC-06, TC-07, TC-08, TC-11, TC-15, TC-16 |
| AC-4 — integer cents only, no Float/Double | TC-09, TC-16 |
| AC-5 — series order preserved; date parse vs. degrade | TC-03, TC-05, TC-16 |
| AC-6 — `next_cursor` surfaced; last page → null | TC-07 |
| AC-7 — Hilt provider from shared Retrofit; no new client | TC-13, TC-14 |
| AC-8 — full unit suite (T-1…T-8) green in CI | TC-01…TC-14 (all JVM cases) |
