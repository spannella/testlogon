package com.testlogon.android.data.activity

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-091 — Retrofit interface for the account activity feed.
 *
 * Path is relative (no leading slash) so it resolves against the shared Retrofit base URL; cookies,
 * Authorization and X-CSRF-Token are attached by the core-network interceptor chain. The method is
 * suspend and returns the typed DTO body; non-2xx surfaces as retrofit2.HttpException.
 *
 * Verified against reference/src/api/endpoints/activityFeed.ts (getActivityFeed) and OpenAPI
 * GET /ui/activity/feed (params cursor,limit; resp ActivityFeedResponse). The server `limit` default
 * is 20 (min 1, max 100); this client sends an explicit 20 like the web client. `user_sub` and the
 * impersonation headers are out of scope (self-scoped feed via the session).
 */
interface ActivityApi {

    /** Paginated, newest-first activity feed. Idempotent GET. Only cursor + limit are sent. */
    @GET("ui/activity/feed")
    suspend fun getActivity(
        @Query("cursor") cursor: String? = null,
        @Query("limit") limit: Int? = null,
    ): ActivityFeedResponseDto
}
