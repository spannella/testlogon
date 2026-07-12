package com.testlogon.android.data.marketing

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free Marketing domain models + total DTO -> domain mappers.
 *
 * Mirrors the web Marketing pages (content dashboard, editor, calendar, engagement). Timestamps are
 * epoch-seconds. [MarketingStatus] folds the server status string into a closed enum (+ UNKNOWN) so the
 * UI can gate lifecycle actions (approve/publish/archive/delete) exactly like the web page.
 */
enum class MarketingStatus {
    DRAFT, REVIEW, APPROVED, SCHEDULED, PUBLISHED, ARCHIVED, UNKNOWN;

    companion object {
        fun from(raw: String?): MarketingStatus = when (raw?.lowercase(Locale.US)) {
            "draft" -> DRAFT
            "review" -> REVIEW
            "approved" -> APPROVED
            "scheduled" -> SCHEDULED
            "published" -> PUBLISHED
            "archived" -> ARCHIVED
            else -> UNKNOWN
        }
    }
}

data class MarketingContent(
    val id: String,
    val contentType: String,
    val title: String,
    val body: String,
    val summary: String?,
    val featureRefs: List<String>,
    val tags: List<String>,
    val seoTitle: String?,
    val seoDescription: String?,
    val status: MarketingStatus,
    val scheduledPublishAtSeconds: Long?,
    val publishedAtSeconds: Long?,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
) {
    val canApprove: Boolean get() = status == MarketingStatus.DRAFT || status == MarketingStatus.REVIEW
    val canPublish: Boolean get() = status == MarketingStatus.APPROVED || status == MarketingStatus.SCHEDULED
    val canArchive: Boolean get() = status == MarketingStatus.PUBLISHED
    val canDelete: Boolean get() = status == MarketingStatus.DRAFT
    val canSchedule: Boolean get() = status == MarketingStatus.APPROVED
}

data class MarketingContentPage(
    val items: List<MarketingContent>,
    val cursor: String?,
) {
    val isEmpty: Boolean get() = items.isEmpty()
}

data class CalendarEntry(
    val contentId: String,
    val title: String,
    val contentType: String,
    val status: MarketingStatus,
    val dateSeconds: Long,
) {
    fun formattedDate(): String =
        if (dateSeconds <= 0L) "" else DATE_FORMAT.format(Date(dateSeconds * 1000L))

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d", Locale.getDefault())
    }
}

data class EngagementSummary(
    val totalContent: Int,
    val totalViews: Int,
    val totalClicks: Int,
    val totalSignups: Int,
    val topPerforming: List<TopPerforming>,
) {
    /** Conversion rate as views->clicks percentage (mirrors the web computed field). */
    val conversionPercent: Double
        get() = if (totalViews > 0) (totalClicks.toDouble() / totalViews) * 100.0 else 0.0
}

data class TopPerforming(
    val contentId: String,
    val title: String,
    val clicks: Int,
)

// ---- Mappers (DTO -> domain) ----

internal fun MarketingContentDto.toDomain(): MarketingContent = MarketingContent(
    id = contentId,
    contentType = contentType,
    title = title,
    body = body,
    summary = summary?.takeIf { it.isNotBlank() },
    featureRefs = featureRefs.orEmpty(),
    tags = tags.orEmpty(),
    seoTitle = seoMeta?.title?.takeIf { it.isNotBlank() },
    seoDescription = seoMeta?.description?.takeIf { it.isNotBlank() },
    status = MarketingStatus.from(status),
    scheduledPublishAtSeconds = scheduledPublishAt,
    publishedAtSeconds = publishedAt,
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
)

internal fun MarketingContentListDto.toDomain(): MarketingContentPage = MarketingContentPage(
    items = items.map { it.toDomain() },
    cursor = cursor,
)

internal fun ContentCalendarEntryDto.toDomain(): CalendarEntry = CalendarEntry(
    contentId = contentId,
    title = title,
    contentType = contentType,
    status = MarketingStatus.from(status),
    dateSeconds = date,
)

internal fun MarketingEngagementSummaryDto.toDomain(): EngagementSummary = EngagementSummary(
    totalContent = totalContent,
    totalViews = totalViews,
    totalClicks = totalClicks,
    totalSignups = totalSignups,
    topPerforming = topPerforming.map { TopPerforming(it.contentId, it.title, it.clicks) },
)
