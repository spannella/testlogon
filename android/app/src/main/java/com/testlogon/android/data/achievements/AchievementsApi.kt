package com.testlogon.android.data.achievements

import retrofit2.http.GET
import retrofit2.http.Query

/**
 * AND-093 / AND-094 — Retrofit interface for achievements + leaderboard.
 *
 * Paths are relative; cookies / Authorization / X-CSRF-Token are attached by the core-network
 * interceptor chain. All GETs are idempotent. Non-2xx surfaces as retrofit2.HttpException.
 *
 * Verified against reference/src/api/endpoints/achievements.ts and OpenAPI:
 *  - earned       -> GET ui/achievements                 (optional displayed,category)
 *  - progress     -> GET ui/achievements/progress
 *  - definitions  -> GET ui/achievements/definitions     (active_only, default true)
 *  - leaderboard  -> GET ui/achievements/leaderboard     (period required, limit<=100, cursor)
 *  - my rank      -> GET ui/achievements/leaderboard/me  (period required)
 */
interface AchievementsApi {

    @GET("ui/achievements")
    suspend fun getMyAchievements(
        @Query("displayed") displayed: Boolean? = null,
        @Query("category") category: String? = null,
    ): MyAchievementsResponseDto

    @GET("ui/achievements/progress")
    suspend fun getProgress(): AchievementProgressResponseDto

    @GET("ui/achievements/definitions")
    suspend fun listDefinitions(
        @Query("active_only") activeOnly: Boolean = true,
    ): AchievementDefinitionsResponseDto

    @GET("ui/achievements/leaderboard")
    suspend fun getLeaderboard(
        @Query("period") period: String = "alltime",
        @Query("limit") limit: Int = 50,
        @Query("cursor") cursor: String? = null,
    ): LeaderboardListDto

    @GET("ui/achievements/leaderboard/me")
    suspend fun getMyRank(
        @Query("period") period: String = "alltime",
    ): MyRankDto
}
