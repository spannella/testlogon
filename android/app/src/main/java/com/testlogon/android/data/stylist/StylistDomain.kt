package com.testlogon.android.data.stylist

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free Stylist domain models + total DTO -> domain mappers.
 *
 * Mirrors the web Stylist pages (design overview, rules, review detail). Timestamps are epoch-seconds.
 * Severity/category are kept as raw lowercased strings (open sets on the backend) but severity folds to
 * a [RuleSeverity] enum for consistent colouring. Time formatting uses SimpleDateFormat/Date (java.time
 * unavailable — desugaring off) and stays JVM-unit-testable.
 */
enum class RuleSeverity { ERROR, WARNING, INFO, UNKNOWN;
    companion object {
        fun from(raw: String?): RuleSeverity = when (raw?.lowercase(Locale.US)) {
            "error" -> ERROR
            "warning" -> WARNING
            "info" -> INFO
            else -> UNKNOWN
        }
    }
}

data class PageScore(
    val pageUrl: String,
    val pageName: String,
    val designScore: Double,
    val accessibilityScore: Double?,
    val issuesFound: Int,
    val lastReviewedSeconds: Long,
) {
    fun formattedLastReviewed(): String =
        if (lastReviewedSeconds <= 0L) "" else DATE_FORMAT.format(Date(lastReviewedSeconds * 1000L))

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    }
}

data class OverallScore(
    val designScore: Double,
    val accessibilityScore: Double,
    val pagesReviewed: Int,
    val totalIssues: Int,
)

data class DesignOverview(
    val overall: OverallScore,
    val pages: List<PageScore>,
) {
    val isEmpty: Boolean get() = pages.isEmpty() && overall.pagesReviewed == 0
}

data class DesignRule(
    val id: String,
    val name: String,
    val category: String,
    val description: String,
    val severity: RuleSeverity,
    val enabled: Boolean,
)

data class ReviewIssue(
    val id: String,
    val category: String,
    val severity: RuleSeverity,
    val title: String,
    val description: String,
    val suggestion: String,
    val createdTicketId: String?,
)

data class ReviewScreenshot(
    val url: String,
    val viewport: String,
    val label: String,
)

data class UIReview(
    val id: String,
    val pageUrl: String,
    val pageName: String,
    val reviewType: String,
    val designScore: Double,
    val accessibilityScore: Double?,
    val issuesFound: Int,
    val status: String,
    val screenshots: List<ReviewScreenshot>,
    val issues: List<ReviewIssue>,
    val createdAtSeconds: Long,
)

// ---- Mappers (DTO -> domain) ----

internal fun PageDesignScoreDto.toDomain(): PageScore = PageScore(
    pageUrl = pageUrl,
    pageName = pageName,
    designScore = designScore,
    accessibilityScore = accessibilityScore,
    issuesFound = issuesFound,
    lastReviewedSeconds = lastReviewed,
)

internal fun OverallDesignScoreDto.toDomain(): OverallScore = OverallScore(
    designScore = overallDesignScore,
    accessibilityScore = overallAccessibilityScore,
    pagesReviewed = pagesReviewed,
    totalIssues = totalIssues,
)

internal fun DesignRuleDto.toDomain(): DesignRule = DesignRule(
    id = ruleId,
    name = name,
    category = category,
    description = description,
    severity = RuleSeverity.from(severity),
    enabled = enabled,
)

internal fun UIReviewIssueDto.toDomain(): ReviewIssue = ReviewIssue(
    id = issueId,
    category = category,
    severity = RuleSeverity.from(severity),
    title = title,
    description = description,
    suggestion = suggestion,
    createdTicketId = createdTicketId?.takeIf { it.isNotBlank() },
)

internal fun UIReviewScreenshotDto.toDomain(): ReviewScreenshot = ReviewScreenshot(
    url = url,
    viewport = viewport,
    label = label.ifBlank { "view" },
)

internal fun UIReviewDto.toDomain(): UIReview = UIReview(
    id = reviewId,
    pageUrl = pageUrl,
    pageName = pageName,
    reviewType = reviewType,
    designScore = designScore,
    accessibilityScore = accessibilityScore,
    issuesFound = issuesFound,
    status = status,
    screenshots = screenshots.map { it.toDomain() },
    issues = issues.map { it.toDomain() },
    createdAtSeconds = createdAt,
)
