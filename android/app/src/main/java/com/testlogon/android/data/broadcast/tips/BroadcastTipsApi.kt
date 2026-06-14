package com.testlogon.android.data.broadcast.tips

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-282 — dedicated Retrofit interface for broadcast tips + goals.
 *
 * VERIFIED against reference/openapi.index.txt + src/api/endpoints/broadcast-tips.ts + broadcast.ts:
 *  - POST broadcast/sessions/{id}/chat/tip (BroadcastChatTipIn) -> 201 BroadcastChatMessageOut
 *  - GET  broadcast/sessions/{id}/tips/summary?top_limit=&recent_limit= -> BroadcastTipSummaryOut
 *  - GET  broadcast/sessions/{id}/goals -> BroadcastTipGoalsListOut { session_id, goals: [...] }
 *
 * The tip POST returns the tip rendered AS A CHAT MESSAGE (kind="tip" with tip_amount_cents /
 * tip_total_cents), NOT a summary/goals snapshot — so the summary + goals are refreshed via the two
 * idempotent GETs after a successful tip (and on a tip-bearing chat:message SSE event). A payment_method_id
 * is REQUIRED on every tip; the charge is authorized by [com.testlogon.android.data.messaging.BillingAuthorizer]
 * first (NotConfigured -> never POSTs). Money is integer cents; created_at is epoch SECONDS.
 *
 * Dedicated API distinct from MessagingApi (the messaging FakeApi is untouched) and from BroadcastChatApi.
 */
interface BroadcastTipsApi {

    @POST("broadcast/sessions/{id}/chat/tip")
    suspend fun submitTip(
        @Path("id") sessionId: String,
        @Body body: BroadcastChatTipDto,
    ): Response<TipMessageDto>

    @GET("broadcast/sessions/{id}/tips/summary")
    suspend fun getTipsSummary(
        @Path("id") sessionId: String,
        @Query("top_limit") topLimit: Int? = null,
        @Query("recent_limit") recentLimit: Int? = null,
    ): Response<TipSummaryDto>

    @GET("broadcast/sessions/{id}/goals")
    suspend fun getGoals(
        @Path("id") sessionId: String,
    ): Response<TipGoalsListDto>
}

/** BroadcastChatTipIn — { amount_cents (100..100000), payment_method_id (1..200), text? (<=280), currency? }. */
@JsonClass(generateAdapter = true)
data class BroadcastChatTipDto(
    @Json(name = "amount_cents") val amountCents: Long,
    @Json(name = "payment_method_id") val paymentMethodId: String,
    @Json(name = "text") val text: String? = null,
    @Json(name = "currency") val currency: String = "USD",
)

/**
 * BroadcastChatMessageOut for a tip (HTTP 201). Carries the tip fields on top of the base chat message.
 * `tip_total_cents` is the running session total at the time of the tip; `created_at` is epoch SECONDS.
 */
@JsonClass(generateAdapter = true)
data class TipMessageDto(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "text") val text: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "created_at") val createdAt: Long = 0L,
    @Json(name = "tip_amount_cents") val tipAmountCents: Long? = null,
    @Json(name = "tip_currency") val tipCurrency: String? = null,
    @Json(name = "tip_total_cents") val tipTotalCents: Long? = null,
)

/** BroadcastTipSummaryOut — only session_id is required; totals default to 0. No tipper_count field. */
@JsonClass(generateAdapter = true)
data class TipSummaryDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "total_cents") val totalCents: Long = 0L,
    @Json(name = "tip_count") val tipCount: Int = 0,
    @Json(name = "currency") val currency: String = "USD",
)

/** BroadcastTipGoalsListOut — { session_id, goals: [...] }. */
@JsonClass(generateAdapter = true)
data class TipGoalsListDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "goals") val goals: List<TipGoalDto> = emptyList(),
)

/** BroadcastTipGoalOut — required: goal_id, session_id, label, target_cents, created_at. */
@JsonClass(generateAdapter = true)
data class TipGoalDto(
    @Json(name = "goal_id") val goalId: String,
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "target_cents") val targetCents: Long = 0L,
    @Json(name = "current_cents") val currentCents: Long = 0L,
    @Json(name = "reached") val reached: Boolean = false,
    @Json(name = "reached_at") val reachedAt: Long? = null,
    @Json(name = "sort_order") val sortOrder: Int = 0,
    @Json(name = "created_at") val createdAt: Long = 0L,
)
