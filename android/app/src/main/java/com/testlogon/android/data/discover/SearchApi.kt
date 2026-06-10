package com.testlogon.android.data.discover

import retrofit2.http.Body
import retrofit2.http.DELETE
import retrofit2.http.GET
import retrofit2.http.POST
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-185/AND-186 — Retrofit interface for global multi-entity search (GET /ui/search) and the
 * server-backed search history used to drive recent searches (AND-186).
 *
 * Dedicated SearchApi so AND-185 never touches the AND-152 MessagingApi message search (the two
 * coexist). Idempotent authenticated GET; cookies + Authorization: Bearer + X-CSRF-Token are attached
 * by the core-network interceptor chain. The mutating history calls (POST/DELETE) also ride the CSRF
 * header from the same chain.
 *
 * Verified contract (reference/src/api/endpoints/search.ts: globalSearch; OpenAPI op
 * global_search_ui_search_get): params q (required, 1..500), types (CSV section keys, optional;
 * null = all nine), limit (backend default 5, max 20; web sends 10). The 200 body is [SearchResponseDto].
 *
 * Search history (reference/src/api/endpoints/search.ts: getSearchHistory / recordSearchHistory /
 * deleteSearchHistoryItem / clearSearchHistory; OpenAPI ops get_search_history_ui_search_history_get,
 * save_search_history_ui_search_history_post, delete_single_search_history_..., clear_all_search_history_...):
 *   GET    ui/search/history?limit=  -> { items: [{ id, query, ts, result_count }] }
 *   POST   ui/search/history         body { query, result_count } -> { ok, id }
 *   DELETE ui/search/history/{item_id}
 *   DELETE ui/search/history
 * NOTE: removal is by server item id (not query text), matching the verified contract.
 */
interface SearchApi {

    @GET("ui/search")
    suspend fun search(
        @Query("q") query: String,
        @Query("types") types: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): SearchResponseDto

    @GET("ui/search/history")
    suspend fun getHistory(
        @Query("limit") limit: Int = HISTORY_LIMIT,
    ): SearchHistoryResponseDto

    @POST("ui/search/history")
    suspend fun recordHistory(
        @Body body: RecordSearchHistoryReqDto,
    ): RecordSearchHistoryResDto

    @DELETE("ui/search/history/{item_id}")
    suspend fun deleteHistoryItem(
        @Path("item_id") itemId: String,
    ): SearchHistoryOkDto

    @DELETE("ui/search/history")
    suspend fun clearHistory(): SearchHistoryOkDto

    companion object {
        /** Web sends 10; backend caps at [MAX_LIMIT]. */
        const val DEFAULT_LIMIT = 10
        const val MAX_LIMIT = 20

        /** Web getSearchHistory default; server caps the list. */
        const val HISTORY_LIMIT = 20
    }
}
