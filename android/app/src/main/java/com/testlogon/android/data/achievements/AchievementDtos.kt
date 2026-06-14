package com.testlogon.android.data.achievements

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-093 / AND-094 — wire DTOs for the achievements + leaderboard surfaces.
 *
 * Verified contract (reference/src/api/types.ts + reference/src/api/endpoints/achievements.ts;
 * OpenAPI 200 bodies are untyped so the web types are authoritative):
 *  - GET /ui/achievements -> { achievements: UserAchievement[], total_points, achievement_count }
 *    (EARNED only; no `earned` flag, no locked rows).
 *  - GET /ui/achievements/progress -> { progress: AchievementProgress[] } (keyed by metric_key).
 *  - GET /ui/achievements/definitions?active_only= -> { definitions: AchievementDefinition[] }
 *    (full catalog; locked = definitions minus earned).
 *  - GET /ui/achievements/leaderboard?period=&limit=&cursor= -> { entries, next_cursor?, period }.
 *  - GET /ui/achievements/leaderboard/me?period= -> LeaderboardEntry & { period } (rank may be null).
 *
 * Fields are `label`/`icon_url`/`unlocked_at` (epoch SECONDS number), NOT title/icon/earned_at.
 */
@JsonClass(generateAdapter = true)
data class MyAchievementsResponseDto(
    @Json(name = "achievements") val achievements: List<UserAchievementDto> = emptyList(),
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
)

@JsonClass(generateAdapter = true)
data class UserAchievementDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "label") val label: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
    @Json(name = "points") val points: Int = 0,
    @Json(name = "unlocked_at") val unlockedAt: Long? = null,
    @Json(name = "trigger_event") val triggerEvent: String? = null,
    @Json(name = "displayed") val displayed: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class AchievementProgressResponseDto(
    @Json(name = "progress") val progress: List<AchievementProgressDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AchievementProgressDto(
    @Json(name = "metric_key") val metricKey: String,
    @Json(name = "current_value") val currentValue: Int = 0,
    @Json(name = "highest_value") val highestValue: Int = 0,
    @Json(name = "next_threshold") val nextThreshold: Int? = null,
)

@JsonClass(generateAdapter = true)
data class AchievementDefinitionsResponseDto(
    @Json(name = "definitions") val definitions: List<AchievementDefinitionDto> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class AchievementDefinitionDto(
    @Json(name = "achievement_id") val achievementId: String,
    @Json(name = "category") val category: String? = null,
    @Json(name = "label") val label: String = "",
    @Json(name = "description") val description: String? = null,
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
    @Json(name = "threshold") val threshold: Int? = null,
    @Json(name = "points") val points: Int = 0,
    @Json(name = "metric_key") val metricKey: String? = null,
    @Json(name = "active") val active: Boolean = true,
    @Json(name = "sort_order") val sortOrder: Int = 0,
)

// ── Leaderboard (AND-094) ──────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class LeaderboardListDto(
    @Json(name = "entries") val entries: List<LeaderboardEntryDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
    @Json(name = "period") val period: String? = null,
)

@JsonClass(generateAdapter = true)
data class LeaderboardEntryDto(
    @Json(name = "rank") val rank: Int = 0,
    @Json(name = "user_sub") val userSub: String = "",
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
    @Json(name = "display_badges") val displayBadges: List<BadgeSummaryDto> = emptyList(),
)

/** The /me endpoint returns LeaderboardEntry & { period }; rank may be null when unranked. */
@JsonClass(generateAdapter = true)
data class MyRankDto(
    @Json(name = "rank") val rank: Int? = null,
    @Json(name = "user_sub") val userSub: String? = null,
    @Json(name = "display_name") val displayName: String? = null,
    @Json(name = "total_points") val totalPoints: Int = 0,
    @Json(name = "achievement_count") val achievementCount: Int = 0,
    @Json(name = "display_badges") val displayBadges: List<BadgeSummaryDto> = emptyList(),
    @Json(name = "period") val period: String? = null,
)

@JsonClass(generateAdapter = true)
data class BadgeSummaryDto(
    @Json(name = "achievement_id") val achievementId: String = "",
    @Json(name = "label") val label: String = "",
    @Json(name = "icon_url") val iconUrl: String? = null,
    @Json(name = "rarity") val rarity: String? = null,
)
