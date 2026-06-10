package com.testlogon.android.data.discover

import retrofit2.http.GET
import retrofit2.http.Path
import retrofit2.http.Query

/**
 * AND-182 / AND-183 / AND-184 — Retrofit interface for the discover + recommendations surfaces.
 *
 * Dedicated to this feature (separate from MessagingApi / FeedApi) so the discover work never touches
 * other features' API contracts. Paths are relative (no leading slash) so they resolve against the
 * shared Retrofit base URL; cookies, Authorization: Bearer and X-CSRF-Token are attached by the
 * core-network interceptor chain. All calls are idempotent GETs.
 *
 * Verified contract (reference/src/api/endpoints/discovery.ts + recommendations.ts; OpenAPI
 * openapi.index.txt lines for the /ui/discover/ endpoints and /ui/videos/gallery/for-you):
 *  - GET /ui/discover/suggested      (limit, default 12, <=50)         -> DiscoverySearchResponse
 *  - GET /ui/discover/trending       (limit, default 20, <=50)         -> DiscoverySearchResponse
 *  - GET /ui/discover/search         (q, limit, cursor?)               -> DiscoverySearchResponse
 *  - GET /ui/discover/trending-tags  (limit, default 20, <=50)         -> TrendingTagsResponse
 *  - GET /ui/discover/tags/{tag}     (limit, default 20, max 50, cursor?) -> TagDiscoverResponse
 *  - GET /ui/discover/creators       (limit, default 10)               -> CreatorSuggestionsResponse
 *  - GET /ui/videos/gallery/for-you  (limit, cursor?)                  -> ForYouResponse
 */
interface DiscoverApi {

    @GET("ui/discover/suggested")
    suspend fun getSuggested(@Query("limit") limit: Int = SUGGESTED_LIMIT): DiscoverySearchResponseDto

    @GET("ui/discover/trending")
    suspend fun getTrending(@Query("limit") limit: Int = TRENDING_LIMIT): DiscoverySearchResponseDto

    @GET("ui/discover/trending-tags")
    suspend fun getTrendingTags(@Query("limit") limit: Int = TAGS_LIMIT): TrendingTagsResponseDto

    @GET("ui/discover/search")
    suspend fun searchCreators(
        @Query("q") q: String,
        @Query("limit") limit: Int = SEARCH_LIMIT,
        @Query("cursor") cursor: String? = null,
    ): DiscoverySearchResponseDto

    @GET("ui/discover/tags/{tag}")
    suspend fun getPostsByTag(
        @Path("tag") tag: String,
        @Query("limit") limit: Int = TAG_PAGE_SIZE,
        @Query("cursor") cursor: String? = null,
    ): TagDiscoverResponseDto

    @GET("ui/discover/creators")
    suspend fun getCreatorSuggestions(
        @Query("limit") limit: Int = CREATORS_LIMIT,
    ): CreatorSuggestionsResponseDto

    @GET("ui/videos/gallery/for-you")
    suspend fun getForYou(
        @Query("limit") limit: Int = FOR_YOU_LIMIT,
        @Query("cursor") cursor: String? = null,
    ): ForYouResponseDto

    companion object {
        const val SUGGESTED_LIMIT = 12
        const val TRENDING_LIMIT = 20
        const val TAGS_LIMIT = 20
        const val SEARCH_LIMIT = 20
        const val CREATORS_LIMIT = 10
        const val FOR_YOU_LIMIT = 24
        const val TAG_PAGE_SIZE = 24
    }
}
