package com.testlogon.android.data.earnings

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-251 — Retrofit interface + Moshi DTOs for the real creator-earnings surface.
 *
 * Verified against reference/openapi.index.txt (lines 1431..1433) and
 * reference/src/api/endpoints/earnings.ts + components.schemas in reference/openapi.pretty.json.
 * Money is uniformly integer cents (every backend amount field is an integer `*_cents`/breakdown
 * value); the series `date` is an ISO YYYY-MM-DD bucket label (week/month granularities may emit a
 * non-parseable label that degrades to a raw string downstream). Session cookies, Authorization Bearer
 * and X-CSRF-Token are attached by core-network interceptors; the operator-only `user_sub`,
 * `X-SESSION-ID`, `X-IMPERSONATION-TOKEN` params are deliberately NOT sent.
 *
 * Endpoint citations (reference/openapi.index.txt):
 *  - GET ui/earnings/summary      L1432  (EarningsSummaryOut; params from_date,to_date,granularity,from_ts,to_ts)
 *  - GET ui/earnings/quick-stats  L1431  (EarningsQuickStatsOut; no functional query params)
 *  - GET ui/earnings/transactions L1433  (EarningsTransactionsOut; params limit,cursor,from_date,to_date,from_ts,to_ts)
 *
 * Retrofit omits @Query params whose value is null, so unset filters never appear on the wire.
 */
interface EarningsApi {

    /** Earnings summary: totals, fixed-key breakdown, and the embedded time-series for the chart. */
    @GET("ui/earnings/summary")
    suspend fun getSummary(
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("granularity") granularity: String = DEFAULT_GRANULARITY,
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): EarningsSummaryDto

    /** Lifetime / pending-payout / period headline figures (not present in the summary payload). */
    @GET("ui/earnings/quick-stats")
    suspend fun getQuickStats(): EarningsQuickStatsDto

    /** Cursor-paginated raw earnings transactions (ledger). */
    @GET("ui/earnings/transactions")
    suspend fun getTransactions(
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
        @Query("from_date") fromDate: String? = null,
        @Query("to_date") toDate: String? = null,
        @Query("from_ts") fromTs: Long? = null,
        @Query("to_ts") toTs: Long? = null,
    ): EarningsTransactionsDto

    companion object {
        const val DEFAULT_GRANULARITY = "day"
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs (AND-251) ----

@JsonClass(generateAdapter = true)
data class EarningsSummaryDto(
    @Json(name = "total_cents") val totalCents: Long = 0,
    val currency: String = DEFAULT_CURRENCY,
    @Json(name = "transaction_count") val transactionCount: Int = 0,
    val breakdown: EarningsBreakdownDto = EarningsBreakdownDto(),
    @Json(name = "time_series") val timeSeries: List<TimeSeriesPointDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class EarningsBreakdownDto(
    val subscriptions: Long = 0,
    val tips: Long = 0,
    val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0,
    val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TimeSeriesPointDto(
    val date: String,
    val total: Long = 0,
    val tips: Long = 0,
    val subscriptions: Long = 0,
    val unlocks: Long = 0,
    @Json(name = "vod_purchases") val vodPurchases: Long = 0,
    val other: Long = 0,
)

@JsonClass(generateAdapter = true)
data class EarningsQuickStatsDto(
    @Json(name = "today_cents") val todayCents: Long = 0,
    @Json(name = "this_week_cents") val thisWeekCents: Long = 0,
    @Json(name = "this_month_cents") val thisMonthCents: Long = 0,
    @Json(name = "all_time_cents") val allTimeCents: Long = 0,
    @Json(name = "pending_payout_cents") val pendingPayoutCents: Long = 0,
    val currency: String = DEFAULT_CURRENCY,
)

@JsonClass(generateAdapter = true)
data class EarningsTransactionsDto(
    // `items` is required in the schema; the empty default is a defensive convenience for the flaky
    // dev host occasionally returning `200 {}`, NOT a relaxation of the contract.
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
    val currency: String = DEFAULT_CURRENCY,
    // additionalProperties: true on the backend; decoded so unknown extras never break Moshi, dropped
    // from the domain model (the UI does not read meta).
    val meta: Map<String, Any?> = emptyMap(),
)

internal const val DEFAULT_CURRENCY = "USD"
