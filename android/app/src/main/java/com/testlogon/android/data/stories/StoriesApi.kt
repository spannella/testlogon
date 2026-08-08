package com.testlogon.android.data.stories

import retrofit2.http.Body
import retrofit2.http.GET
import retrofit2.http.Headers
import retrofit2.http.POST
import retrofit2.http.Path

/**
 * AND-199 / AND-200 — dedicated Retrofit interface for the Stories surface.
 *
 * Separate from FeedApi / MessagingApi so this feature never touches their contracts. Paths are
 * relative (no leading slash) so they resolve against the shared Retrofit base URL; session cookies,
 * Authorization: Bearer and X-CSRF-Token are attached by the core-network interceptor chain.
 *
 * Verified contract (reference/src/api/endpoints/stories.ts; reference/src/api/types.ts):
 *  - GET  ui/stories/bar                 -> StoryBarResp   (idempotent, bounded-backoff eligible)
 *  - GET  ui/stories/user/{user_id}      -> UserStoriesResp (idempotent)
 *  - POST ui/stories/{story_id}/view     -> StoryViewResp  (empty body; NOT retried; deduped by id)
 *  - POST ui/stories                     -> CreateStoryResp (PAR-01; 429 when the daily limit is hit)
 */
interface StoriesApi {

    @GET("ui/stories/bar")
    suspend fun getStoryBar(): StoryBarRespDto

    @GET("ui/stories/user/{userId}")
    suspend fun getUserStories(@Path("userId") userId: String): UserStoriesRespDto

    /** Record a view for a story. Empty request body; response StoryViewResp (HTTP 200). */
    @Headers("Content-Type: application/json")
    @POST("ui/stories/{storyId}/view")
    suspend fun recordView(@Path("storyId") storyId: String): StoryViewRespDto

    /**
     * PAR-01 — create a story (IMAGE-first for v1). Returns the created story; the backend answers 429
     * when the per-day story limit is hit (surfaced by the repository as a distinct rate-limited result).
     */
    @Headers("Content-Type: application/json")
    @POST("ui/stories")
    suspend fun createStory(@Body body: CreateStoryReqDto): CreateStoryRespDto
}
