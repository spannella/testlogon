package com.testlogon.android.data.report

import com.testlogon.android.data.messaging.report.ReportReason

/**
 * AND-383 - cross-cutting Trust and Safety report-flow domain. JVM-pure (no android.*).
 *
 * Generalizes AND-163's message-only report into one reusable flow that targets a USER (profile photo),
 * a CONTENT item (feed post / comment / media) or a MESSAGE. The topic taxonomy is REUSED verbatim from
 * AND-163 ([ReportReason]: the six live categories spam / harassment / hate / sexual / violence_threats /
 * other; retired: extortion / criminal / racist) - it is intentionally NOT
 * duplicated into a second enum, so the two report surfaces cannot drift. Multi-select topics are
 * represented as a Set<ReportReason>; the message-scoped endpoint takes a single `reason_code`, for which
 * the first selected topic is sent (mirrors the web client `reason_code: topics[0]`).
 */

/** AND-383 - the kind of subject being reported. Drives endpoint routing and the wire `content_type`. */
enum class ReportKind { USER, CONTENT, MESSAGE }

/**
 * AND-383 - the subject of a report. `id` is the subject id (profile user id / content id / message id).
 *
 * For [Message] the `conversationId` is MANDATORY (the message-scoped endpoint path requires both the
 * conversation id and the message id; OQ-1 RESOLVED). For [Content] the `contentType` is one of the feed
 * wire values: "feed_post" | "feed_comment" | "feed_media".
 */
sealed interface ReportTarget {
    val id: String

    data class User(override val id: String, val displayName: String? = null) : ReportTarget

    /** MODX-11 - account-level report (content_type=user), keyed on the user; no profile photo required. */
    data class Account(override val id: String, val displayName: String? = null) : ReportTarget

    data class Content(
        override val id: String,
        val contentType: String,
        val syndicateId: String? = null,
        val categoryId: String? = null,
        val itemId: String? = null,
        val sessionId: String? = null,
    ) : ReportTarget

    data class Message(override val id: String, val conversationId: String) : ReportTarget
}

/** AND-383 - the [ReportKind] implied by a target. */
val ReportTarget.kind: ReportKind
    get() = when (this) {
        is ReportTarget.User -> ReportKind.USER
        is ReportTarget.Account -> ReportKind.USER
        is ReportTarget.Content -> ReportKind.CONTENT
        is ReportTarget.Message -> ReportKind.MESSAGE
    }

/** AND-383 - the outcome propagated back to the originating call site via `onCompleted`. */
enum class ReportOutcome { SUBMITTED, ALREADY_REPORTED, CANCELLED }

/**
 * AND-383 - normalized result of a successful report, common to both endpoints. `alreadyReported` is true
 * only for the moderation endpoint's `status == "deduplicated"` (FR-8); the message endpoint only ever
 * returns "submitted", so it is always false there.
 */
data class ReportResult(
    val reportId: String,
    val alreadyReported: Boolean,
)

/** AND-383 - the offered topic set + per-kind ordering. All five topics are offered for every kind. */
object ReportTopics {
    /** Stable, wire-compatible ordering (guards against accidental reordering - see TC and §11). */
    val ALL: List<ReportReason> = ReportReason.SELECTABLE

    /**
     * Topics offered for [kind]. The web client offers all five for every kind; this seam exists so a
     * future per-kind filter can be applied in one place without touching callers.
     */
    fun forKind(@Suppress("UNUSED_PARAMETER") kind: ReportKind): List<ReportReason> = ALL
}

/** AND-383 - wire `content_type` for a USER/CONTENT moderation report. MESSAGE does not use this path. */
internal fun ReportTarget.moderationContentType(): String = when (this) {
    is ReportTarget.User -> "profile_photo"
    is ReportTarget.Account -> "user"
    is ReportTarget.Content -> contentType
    is ReportTarget.Message ->
        error("Message targets are not reported via the moderation endpoint")
}
