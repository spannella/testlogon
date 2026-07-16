package com.testlogon.android.data.tipinsights

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.http.GET
import retrofit2.http.Query

/**
 * TIPX-D3/D4 — Retrofit interface + DTOs for the LEDGER-backed tip measurement surface.
 *
 * These are the reconciled, single-source-of-truth tip totals (see backend
 * app/services/tips_measurement.py):
 *  - GET ui/tips/received          creator's NET tips-received summary + top tippers + per-surface
 *    breakdown. total_net_cents reconciles to the earnings tips bucket and the leaderboard
 *    (net of the platform fee, all 8 surfaces, reversed-excluded).
 *  - GET ui/tips/received/history  creator's paginated NET tip credit rows (drill-down).
 *  - GET ui/tips/sent              tipper's paginated GROSS tip debit receipts (what they paid).
 *  - GET ui/tips/sent/summary      tipper's aggregate spend header.
 *
 * The base URL does NOT include /ui, so each path carries it. Cookies / Authorization: Bearer /
 * X-CSRF-Token are attached by the core-network interceptor chain. Retrofit omits null @Query params.
 */
interface TipInsightsApi {

    @GET("ui/tips/received")
    suspend fun getReceivedSummary(
        @Query("period") period: String = DEFAULT_PERIOD,
    ): TipsReceivedSummaryDto

    @GET("ui/tips/received/history")
    suspend fun getReceivedHistory(
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
        @Query("period") period: String = "all",
    ): TipTransactionsDto

    @GET("ui/tips/sent")
    suspend fun getSent(
        @Query("limit") limit: Int = DEFAULT_LIMIT,
        @Query("cursor") cursor: String? = null,
        @Query("period") period: String = "all",
    ): TipTransactionsDto

    @GET("ui/tips/sent/summary")
    suspend fun getSentSummary(
        @Query("period") period: String = "all",
    ): TipsSentSummaryDto

    companion object {
        const val DEFAULT_PERIOD = "30d"
        const val DEFAULT_LIMIT = 50
    }
}

// ---- DTOs ----

@JsonClass(generateAdapter = true)
data class TipSurfaceBucketDto(
    val count: Int = 0,
    @Json(name = "total_cents") val totalCents: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TipTopTipperDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "display_name") val displayName: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0,
    @Json(name = "tip_count") val tipCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class TipsReceivedSummaryDto(
    val period: String = "30d",
    @Json(name = "total_net_cents") val totalNetCents: Long = 0,
    @Json(name = "tip_count") val tipCount: Int = 0,
    @Json(name = "unique_tippers") val uniqueTippers: Int = 0,
    @Json(name = "by_type") val byType: Map<String, TipSurfaceBucketDto> = emptyMap(),
    @Json(name = "top_tippers") val topTippers: List<TipTopTipperDto> = emptyList(),
    val source: String = "ledger",
)

@JsonClass(generateAdapter = true)
data class TipTransactionDto(
    @Json(name = "entry_id") val entryId: String = "",
    val ts: Long = 0,
    @Json(name = "amount_cents") val amountCents: Long = 0,
    val reason: String = "",
    @Json(name = "content_type") val contentType: String = "",
    @Json(name = "content_id") val contentId: String = "",
    @Json(name = "counterparty_user_id") val counterpartyUserId: String = "",
    @Json(name = "counterparty_display_name") val counterpartyDisplayName: String = "",
    @Json(name = "platform_fee_cents") val platformFeeCents: Long = 0,
    @Json(name = "tip_payment_id") val tipPaymentId: String = "",
    val currency: String = "USD",
)

@JsonClass(generateAdapter = true)
data class TipTransactionsDto(
    val items: List<TipTransactionDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class TipsSentSummaryDto(
    val period: String = "all",
    @Json(name = "total_sent_cents") val totalSentCents: Long = 0,
    @Json(name = "tip_count") val tipCount: Int = 0,
    @Json(name = "unique_recipients") val uniqueRecipients: Int = 0,
    val source: String = "ledger",
)
