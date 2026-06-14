package com.testlogon.android.data.achievements

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** AND-096 — pure mapper/composition tests for the achievements catalog + leaderboard. */
class AchievementMapperTest {

    @Test
    fun buildCatalog_partitionsEarnedAndLocked_joinsProgress() {
        val my = MyAchievementsResponseDto(
            achievements = listOf(
                UserAchievementDto(achievementId = "first_login", label = "First", points = 10, unlockedAt = 1748592662L),
            ),
            totalPoints = 10,
            achievementCount = 1,
        )
        val progress = AchievementProgressResponseDto(
            progress = listOf(
                AchievementProgressDto(metricKey = "login_streak_days", currentValue = 7, nextThreshold = 10),
            ),
        )
        val definitions = AchievementDefinitionsResponseDto(
            definitions = listOf(
                AchievementDefinitionDto(achievementId = "first_login", label = "First", threshold = 1, metricKey = "logins"),
                AchievementDefinitionDto(achievementId = "streak_10", label = "On a Roll", threshold = 10, metricKey = "login_streak_days"),
            ),
        )

        val catalog = buildCatalog(my, progress, definitions)

        assertEquals(1, catalog.earned.size)
        assertEquals(1, catalog.locked.size) // definitions - earned
        assertEquals(1, catalog.earnedCount)
        assertEquals(2, catalog.total) // definitions.size
        val streak = catalog.locked.first { it.id == "streak_10" }
        assertEquals(0.7f, streak.progress?.fraction)
        assertEquals(10, streak.progress?.target)
        assertEquals("7 / 10", streak.progress?.label)
    }

    @Test
    fun buildCatalog_degradedMode_noDefinitions_rendersEarnedOnly() {
        val my = MyAchievementsResponseDto(
            achievements = listOf(UserAchievementDto(achievementId = "a", label = "A")),
            achievementCount = 1,
        )
        val catalog = buildCatalog(my, AchievementProgressResponseDto(), AchievementDefinitionsResponseDto())
        assertEquals(1, catalog.earned.size)
        assertTrue(catalog.locked.isEmpty())
        assertEquals(1, catalog.total) // falls back to earned.size
    }

    @Test
    fun progress_fractionClamped_andTargetZeroDropsProgress() {
        assertEquals(1f, AchievementProgress(current = 20, target = 10).fraction)
        assertEquals(0f, AchievementProgress(current = -5, target = 10).fraction)
        assertEquals(0f, AchievementProgress(current = 5, target = 0).fraction)

        val definitions = AchievementDefinitionsResponseDto(
            definitions = listOf(
                AchievementDefinitionDto(achievementId = "z", label = "Z", threshold = 0, metricKey = "m"),
            ),
        )
        val catalog = buildCatalog(MyAchievementsResponseDto(), AchievementProgressResponseDto(), definitions)
        assertNull(catalog.locked.single().progress) // target <= 0 -> null progress
    }

    @Test
    fun leaderboard_nameFallback_andClientSideIsMe() {
        val entry = LeaderboardEntryDto(rank = 2, userSub = "u_b", displayName = null, totalPoints = 100)
        val mapped = entry.toDomain(currentSub = "u_b")
        assertEquals("u_b", mapped.name) // displayName null -> userSub
        assertTrue(mapped.isMe)

        val other = LeaderboardEntryDto(rank = 3, userSub = "", displayName = null, totalPoints = 50).toDomain("u_b")
        assertEquals("Player #3", other.name) // both blank -> Player #rank
        assertFalse(other.isMe)
    }

    @Test
    fun myRank_nullRank_mapsToNull() {
        assertNull(MyRankDto(rank = null).toDomainOrNull(currentSub = "u_b"))
        val ranked = MyRankDto(rank = 57, userSub = "u_self", totalPoints = 910).toDomainOrNull("u_self")
        assertEquals(57, ranked?.rank)
        assertTrue(ranked?.isMe == true)
    }
}
