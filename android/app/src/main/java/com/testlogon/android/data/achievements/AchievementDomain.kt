package com.testlogon.android.data.achievements

/**
 * AND-093 / AND-094 — domain models + composition for achievements & leaderboard (framework-free,
 * JVM-unit-test safe).
 *
 * Timestamps stay epoch SECONDS Long (no java.time); the `earned` partition is DERIVED by set
 * membership across the three responses (there is no per-item earned flag on the wire). Progress is
 * joined onto locked items by metric_key, target = progress.nextThreshold ?: definition.threshold;
 * the fraction is clamped to 0f..1f.
 */
data class AchievementProgress(
    val current: Int,
    val target: Int,
) {
    /** 0f..1f, safe for LinearProgressIndicator; 0 when target <= 0. */
    val fraction: Float
        get() = if (target <= 0) 0f else (current.toFloat() / target).coerceIn(0f, 1f)

    /** "7 / 10" label. */
    val label: String get() = "$current / $target"
}

data class Achievement(
    val id: String,
    val title: String,
    val description: String?,
    val iconUrl: String?,
    val rarity: String?,
    val points: Int,
    val earned: Boolean,
    /** unlocked_at epoch SECONDS, or null. */
    val earnedAtEpochSeconds: Long?,
    /** null = no measurable progress (not started / earned). */
    val progress: AchievementProgress?,
)

/** Partitioned, count-summarized catalog aggregate consumed by the ViewModel/UI. */
data class AchievementCatalog(
    val earned: List<Achievement>,
    val locked: List<Achievement>,
    val earnedCount: Int,
    val totalPoints: Int,
    val total: Int,
) {
    val isEmpty: Boolean get() = earned.isEmpty() && locked.isEmpty()
}

// ── Leaderboard (AND-094) ──────────────────────────────────────────

data class BadgeSummary(
    val achievementId: String,
    val label: String,
    val iconUrl: String?,
    val rarity: String?,
)

data class LeaderboardEntry(
    val rank: Int,
    val userSub: String,
    val name: String,
    val points: Int,
    val achievementCount: Int,
    val badges: List<BadgeSummary>,
    val isMe: Boolean,
)

data class Leaderboard(
    val entries: List<LeaderboardEntry>,
    /** Built from the separate /me response; null when unranked or the call failed. */
    val me: LeaderboardEntry?,
    val nextCursor: String?,
    val period: String?,
)

// ── Mapping & composition ──────────────────────────────────────────

/**
 * Composes the [AchievementCatalog] from the three responses. Definitions/progress are best-effort:
 * when [definitions] is empty (call failed / degraded), `locked` is empty and `total` falls back to
 * the earned count.
 */
internal fun buildCatalog(
    my: MyAchievementsResponseDto,
    progress: AchievementProgressResponseDto,
    definitions: AchievementDefinitionsResponseDto,
): AchievementCatalog {
    val earnedIds = my.achievements.map { it.achievementId }.toSet()
    val progressByMetric = progress.progress.associateBy { it.metricKey }

    val earned = my.achievements
        .map { dto ->
            Achievement(
                id = dto.achievementId,
                title = dto.label,
                description = dto.description,
                iconUrl = dto.iconUrl,
                rarity = dto.rarity,
                points = dto.points,
                earned = true,
                earnedAtEpochSeconds = dto.unlockedAt?.takeIf { it > 0L },
                progress = null,
            )
        }
        .sortedByDescending { it.earnedAtEpochSeconds ?: Long.MIN_VALUE }

    val locked = definitions.definitions
        .filter { it.achievementId !in earnedIds }
        .map { def ->
            val metricProgress = def.metricKey?.let { progressByMetric[it] }
            val target = metricProgress?.nextThreshold ?: def.threshold
            val domainProgress = if (target != null && target > 0) {
                AchievementProgress(
                    current = (metricProgress?.currentValue ?: 0).coerceAtLeast(0),
                    target = target,
                )
            } else {
                null
            }
            Achievement(
                id = def.achievementId,
                title = def.label,
                description = def.description,
                iconUrl = def.iconUrl,
                rarity = def.rarity,
                points = def.points,
                earned = false,
                earnedAtEpochSeconds = null,
                progress = domainProgress,
            )
        }
        .sortedWith(
            compareByDescending<Achievement> { it.progress?.fraction ?: 0f }
                .thenBy { it.title },
        )

    return AchievementCatalog(
        earned = earned,
        locked = locked,
        earnedCount = my.achievementCount,
        totalPoints = my.totalPoints,
        total = if (definitions.definitions.isNotEmpty()) definitions.definitions.size else earned.size,
    )
}

internal fun BadgeSummaryDto.toDomain(): BadgeSummary =
    BadgeSummary(achievementId = achievementId, label = label, iconUrl = iconUrl, rarity = rarity)

internal fun LeaderboardEntryDto.toDomain(currentSub: String?): LeaderboardEntry =
    LeaderboardEntry(
        rank = rank,
        userSub = userSub,
        name = displayName?.takeIf { it.isNotBlank() }
            ?: userSub.takeIf { it.isNotBlank() }
            ?: "Player #$rank",
        points = totalPoints,
        achievementCount = achievementCount,
        badges = displayBadges.map { it.toDomain() },
        isMe = currentSub != null && currentSub == userSub,
    )

/** Maps the /me entry to a domain entry, or null when the user is unranked (rank absent). */
internal fun MyRankDto.toDomainOrNull(currentSub: String?): LeaderboardEntry? {
    val r = rank ?: return null
    return LeaderboardEntry(
        rank = r,
        userSub = userSub.orEmpty(),
        name = displayName?.takeIf { it.isNotBlank() }
            ?: userSub?.takeIf { it.isNotBlank() }
            ?: "You",
        points = totalPoints,
        achievementCount = achievementCount,
        badges = displayBadges.map { it.toDomain() },
        isMe = true,
    )
}
