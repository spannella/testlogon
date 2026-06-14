package com.testlogon.android.feature.achievements

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.achievements.Achievement
import com.testlogon.android.data.achievements.AchievementCatalog
import com.testlogon.android.data.achievements.AchievementProgress
import com.testlogon.android.data.achievements.AchievementsRepository
import com.testlogon.android.data.achievements.Leaderboard
import com.testlogon.android.data.achievements.LeaderboardEntry

/** AND-096 — in-memory [AchievementsRepository] fake for ViewModel unit tests. */
class FakeAchievementsRepository : AchievementsRepository {

    /** Successive catalog results; if a single value is set it is returned every time. */
    var catalogResults: ArrayDeque<ApiResult<AchievementCatalog>> = ArrayDeque()
    var leaderboardResult: ApiResult<Leaderboard> = ApiResult.Success(Leaderboard(emptyList(), null, null, "alltime"))

    var catalogCalls = 0

    override suspend fun getCatalog(): ApiResult<AchievementCatalog> {
        catalogCalls++
        return if (catalogResults.size > 1) catalogResults.removeFirst() else catalogResults.firstOrNull()
            ?: ApiResult.Success(emptyCatalog())
    }

    override suspend fun getLeaderboard(period: String, limit: Int): ApiResult<Leaderboard> =
        leaderboardResult

    companion object {
        fun earned(id: String) = Achievement(
            id = id, title = "Earned $id", description = null, iconUrl = null, rarity = "common",
            points = 10, earned = true, earnedAtEpochSeconds = 1L, progress = null,
        )

        fun locked(id: String, current: Int, target: Int) = Achievement(
            id = id, title = "Locked $id", description = null, iconUrl = null, rarity = "rare",
            points = 25, earned = false, earnedAtEpochSeconds = null,
            progress = AchievementProgress(current, target),
        )

        fun catalog(earned: List<Achievement>, locked: List<Achievement>) = AchievementCatalog(
            earned = earned, locked = locked, earnedCount = earned.size,
            totalPoints = earned.size * 10, total = earned.size + locked.size,
        )

        fun emptyCatalog() = AchievementCatalog(emptyList(), emptyList(), 0, 0, 0)

        fun entry(rank: Int, sub: String, isMe: Boolean = false) = LeaderboardEntry(
            rank = rank, userSub = sub, name = "Player $sub", points = 100 - rank,
            achievementCount = 1, badges = emptyList(), isMe = isMe,
        )

        fun failure(status: Int = 500) = ApiResult.Failure(ApiError(status = status, message = "boom"))
    }
}
