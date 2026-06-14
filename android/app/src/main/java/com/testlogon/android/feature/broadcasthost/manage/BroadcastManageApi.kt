package com.testlogon.android.feature.broadcasthost.manage

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.data.broadcast.shelf.ShelfItemDto
import com.testlogon.android.data.broadcast.shelf.ShelfListDto
import com.testlogon.android.data.broadcast.tips.TipGoalDto
import com.testlogon.android.data.broadcast.tips.TipGoalsListDto
import retrofit2.Response
import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.PATCH
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-314 — Retrofit interface for the HOST authoring surface of a live broadcast: goals CRUD + products
 * management (add / remove / reorder / set-price / clear-price). It is the authoring COUNTERPART to the
 * AND-282 tips/goals viewer (BroadcastTipsApi) and the AND-283 products-shelf viewer (BroadcastShelfApi).
 *
 * Kept SEPARATE from those viewer APIs so their fakes stay untouched; provided on the SHARED Retrofit by
 * [BroadcastManageApiModule] (no new OkHttp / Retrofit, no new dependency). Paths are relative (no leading
 * slash) so they resolve against the shared base URL; cookies / Authorization: Bearer / X-CSRF-Token are
 * attached project-wide by the core-network interceptor chain — this interface stays header-agnostic.
 *
 * REAL-BODY responses (list / create / add / set-price) decode their DTO. ACK-only responses (deleteGoal,
 * removeProduct, reorder, clearPrice) return `Response<Unit>`: an EMPTY 200 body is success by isSuccessful —
 * Retrofit consumes the body WITHOUT JSON parsing (an `{ ok }` body is also tolerated). A concrete DTO would
 * make Moshi throw EOF on an empty body (this bit us on AND-312/AND-313).
 *
 * DTOs are REUSED from AND-282/AND-283 ([TipGoalDto], [TipGoalsListDto], [ShelfItemDto], [ShelfListDto]); only
 * the create / add / reorder / price request+response DTOs are added here.
 */
interface BroadcastManageApi {

    // ---- GOALS ----

    /** GET .../goals -> 200 { session_id, goals: [TipGoalOut] }. Idempotent. */
    @GET("broadcast/sessions/{id}/goals")
    suspend fun getGoals(
        @Path("id") sessionId: String,
    ): Response<TipGoalsListDto>

    /** POST .../goals, body { label, target_cents, sort_order } -> 200/201 TipGoalOut. */
    @POST("broadcast/sessions/{id}/goals")
    suspend fun createGoal(
        @Path("id") sessionId: String,
        @Body body: TipGoalCreateDto,
    ): Response<TipGoalDto>

    /** DELETE .../goals/{goalId} -> 200 ({ ok, goal_id }); ACK -> Response of Unit (success-by-status). */
    @DELETE("broadcast/sessions/{id}/goals/{goalId}")
    suspend fun deleteGoal(
        @Path("id") sessionId: String,
        @Path("goalId") goalId: String,
    ): Response<Unit>

    // ---- PRODUCTS ----

    /** GET .../products -> 200 { session_id, items: [ShelfItemOut], count }. Idempotent. */
    @GET("broadcast/sessions/{id}/products")
    suspend fun getProducts(
        @Path("id") sessionId: String,
    ): Response<ShelfListDto>

    /** POST .../products, body { item_id, category_id, display_order } -> 200/201 ShelfItemOut. */
    @POST("broadcast/sessions/{id}/products")
    suspend fun addProduct(
        @Path("id") sessionId: String,
        @Body body: ShelfAddDto,
    ): Response<ShelfItemDto>

    /** DELETE .../products/{itemId} -> 200 (ACK); Response of Unit (success-by-status). */
    @DELETE("broadcast/sessions/{id}/products/{itemId}")
    suspend fun removeProduct(
        @Path("id") sessionId: String,
        @Path("itemId") itemId: String,
    ): Response<Unit>

    /**
     * PATCH .../products/reorder, body { item_order: [String] } -> 200 ({ ok }); ACK -> Response of Unit.
     * The reorder does NOT return the ordered shelf, so the caller RE-FETCHES the list afterwards.
     */
    @PATCH("broadcast/sessions/{id}/products/reorder")
    suspend fun reorderProducts(
        @Path("id") sessionId: String,
        @Body body: ShelfReorderDto,
    ): Response<Unit>

    /**
     * PATCH .../products/{itemId}/price, body { broadcast_price_cents, expires_in_seconds? } -> 200 PriceOut.
     * broadcast_price_cents must be > 0 and strictly < the catalog price (server-validated; client pre-checks).
     */
    @PATCH("broadcast/sessions/{id}/products/{itemId}/price")
    suspend fun setProductPrice(
        @Path("id") sessionId: String,
        @Path("itemId") itemId: String,
        @Body body: PriceSetDto,
    ): Response<PriceOutDto>

    /** DELETE .../products/{itemId}/price -> 200 (ACK); the row reverts to the catalog price. Response of Unit. */
    @DELETE("broadcast/sessions/{id}/products/{itemId}/price")
    suspend fun clearProductPrice(
        @Path("id") sessionId: String,
        @Path("itemId") itemId: String,
    ): Response<Unit>
}

// --- request / response DTOs (exact snake_case via @Json; absent optionals fall back to Kotlin defaults) ---

/** AND-314 — create-goal request body: { label (1..200), target_cents (100..10_000_000), sort_order (0..4) }. */
@JsonClass(generateAdapter = true)
data class TipGoalCreateDto(
    @Json(name = "label") val label: String,
    @Json(name = "target_cents") val targetCents: Long,
    @Json(name = "sort_order") val sortOrder: Int = 0,
)

/** AND-314 — add-product request body: { item_id (1..128), category_id (1..128), display_order (0..999) }. */
@JsonClass(generateAdapter = true)
data class ShelfAddDto(
    @Json(name = "item_id") val itemId: String,
    @Json(name = "category_id") val categoryId: String,
    @Json(name = "display_order") val displayOrder: Int = 0,
)

/** AND-314 — reorder request body: { item_order: [String] (1..50) }. The 200 is an ACK; re-fetch the list. */
@JsonClass(generateAdapter = true)
data class ShelfReorderDto(
    @Json(name = "item_order") val itemOrder: List<String>,
)

/**
 * AND-314 — set-price request body: { broadcast_price_cents (>0, strictly < catalog), expires_in_seconds?
 * (60..86400) }. An absent expiry means the broadcast price does not auto-expire.
 */
@JsonClass(generateAdapter = true)
data class PriceSetDto(
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
)

/**
 * AND-314 — set-price 200 result (PriceOut): { session_id, item_id, original_price_cents, broadcast_price_cents,
 * broadcast_price_expires_at?, discount_pct, set_by, set_at }. `original_price_cents` is the catalog price;
 * timestamps are epoch SECONDS. Merged into the matching [ShelfProduct] by the repository.
 */
@JsonClass(generateAdapter = true)
data class PriceOutDto(
    @Json(name = "session_id") val sessionId: String = "",
    @Json(name = "item_id") val itemId: String = "",
    @Json(name = "original_price_cents") val originalPriceCents: Long = 0L,
    @Json(name = "broadcast_price_cents") val broadcastPriceCents: Long = 0L,
    @Json(name = "broadcast_price_expires_at") val broadcastPriceExpiresAt: Long? = null,
    @Json(name = "discount_pct") val discountPct: Int = 0,
    @Json(name = "set_by") val setBy: String = "",
    @Json(name = "set_at") val setAt: Long = 0L,
)
