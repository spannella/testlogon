package com.testlogon.android.data.discover

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-185 — Retrofit interface for global multi-entity search (GET /ui/search).
 *
 * Dedicated SearchApi so AND-185 never touches the AND-152 MessagingApi message search (the two
 * coexist). Idempotent authenticated GET; cookies + Authorization: Bearer + X-CSRF-Token are attached
 * by the core-network interceptor chain.
 *
 * Verified contract (reference/src/api/endpoints/search.ts: globalSearch; OpenAPI op
 * global_search_ui_search_get): params q (required, 1..500), types (CSV, optional; null = all), limit
 * (backend default 5, max 20; web sends 10). The 200 body is [SearchResponseDto].
 */
interface SearchApi {

    @GET("ui/search")
    suspend fun search(
        @Query("q") query: String,
        @Query("types") types: String? = null,
        @Query("limit") limit: Int = DEFAULT_LIMIT,
    ): SearchResponseDto

    companion object {
        /** Web sends 10; backend caps at [MAX_LIMIT]. */
        const val DEFAULT_LIMIT = 10
        const val MAX_LIMIT = 20
    }
}
