package com.testlogon.android.data.broadcast.qna

/**
 * AND-284 — live Q&A domain models (DTO-free). Timestamps are epoch SECONDS (Long); the wire values are
 * ~1.7e9 (10-digit) -> seconds. `viewerHasUpvoted` has NO server source and is tracked locally by the
 * ViewModel; `featured` is derived from status == "featured".
 */
data class QaQuestion(
    val id: String,
    val text: String,
    val authorDisplayName: String,
    val upvotes: Int,
    val featured: Boolean,
    val pinned: Boolean,
    val createdAtEpochSeconds: Long,
)

/** A snapshot: the featured banner question (nullable) + the de-duplicated list (excludes featured id). */
data class QaSnapshot(
    val featured: QaQuestion?,
    val questions: List<QaQuestion>,
)

internal const val QA_STATUS_FEATURED = "featured"

internal fun QaQuestionDto.toDomain(): QaQuestion = QaQuestion(
    id = questionId,
    text = text,
    authorDisplayName = submitterDisplayName,
    upvotes = voteCount,
    featured = status == QA_STATUS_FEATURED,
    pinned = pinned,
    createdAtEpochSeconds = createdAt,
)

/**
 * Host-console question row. Unlike the viewer [QaQuestion] (which only needs featured/pinned), the host
 * needs the raw moderation [status] (pending / featured / answered / dismissed) to drive the action buttons.
 */
data class QaHostQuestion(
    val id: String,
    val text: String,
    val authorDisplayName: String,
    val upvotes: Int,
    val status: String,
    val pinned: Boolean,
    val createdAtEpochSeconds: Long,
) {
    val isFeatured: Boolean get() = status == QA_STATUS_FEATURED
    val isAnswered: Boolean get() = status == "answered"
}

fun QaQuestionDto.toHostDomain(): QaHostQuestion = QaHostQuestion(
    id = questionId,
    text = text,
    authorDisplayName = submitterDisplayName.ifBlank { submitterId },
    upvotes = voteCount,
    status = status,
    pinned = pinned,
    createdAtEpochSeconds = createdAt,
)

/** Q&A engagement stats (host console). */
data class QaStats(
    val totalQuestions: Int,
    val answered: Int,
    val dismissed: Int,
    val featured: Int,
    val pending: Int,
    val totalUpvotes: Int,
    val avgUpvotes: Double,
    val answerRate: Double,
)

fun QaStatsDto.toDomain(): QaStats = QaStats(
    totalQuestions = totalQuestions,
    answered = answered,
    dismissed = dismissed,
    featured = featured,
    pending = pending,
    totalUpvotes = totalUpvotes,
    avgUpvotes = avgUpvotes,
    answerRate = answerRate,
)
