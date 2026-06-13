package com.testlogon.android.feature.kyc.cases.model

import com.testlogon.android.core.model.kyc.KycCaseOut
import com.testlogon.android.core.model.kyc.KycCaseStatus
import com.testlogon.android.core.model.kyc.KycReviewScheduleDto
import com.testlogon.android.core.model.kyc.KycReviewScheduleEnvelopeDto
import com.testlogon.android.core.model.kyc.KycTriggerEventDto
import com.testlogon.android.core.model.kyc.KycTriggerEventListEnvelopeDto
import java.time.Instant

/**
 * AND-329 - feature domain model + DTO mappers + the two PURE functions for the READ-ONLY KYC case-status &
 * ongoing-monitoring surface.
 *
 * REUSE: the case list + per-case detail come from AND-319's KycApi (listCases / getCase), so the case DTO
 * ([KycCaseOut]) and its [KycCaseStatus] enum are REUSED verbatim (NOT redefined). Only the ongoing-monitoring
 * schedule / triggers are new DTOs (in core-model). All DTO -> domain mapping happens BEFORE the typed
 * ApiResult in the repository (mirrors AND-326..328); epoch-second Longs become [java.time.Instant]; unknown
 * status tokens fall back to [KycCaseStatus.UNKNOWN] (via KycCaseStatus.fromToken).
 *
 * TIMELINE: there is NO inline history array on the wire. [synthesizeTimeline] SYNTHESIZES an ordered (oldest
 * -> newest) timeline client-side from the case fields. It is a PURE function (no I/O, no clock) so it is
 * directly unit-testable.
 *
 * MONITORING: [monitoringActive] is a PURE reducer over the (already-mapped) schedule + trigger events. The
 * banner shows when the schedule status is one of needs_review / grace_period / downgraded (NOT the steady
 * "active" state), OR when any recent trigger event is present.
 */

// ---- Case summaries (list) ----

/** A lightweight case-list row mapped from AND-319's [KycCaseOut]. */
data class KycCaseSummary(
    val caseId: String,
    val status: KycCaseStatus,
    val createdAt: Instant,
    val updatedAt: Instant,
)

/** Maps AND-319's [KycCaseOut] to the case-list summary (epoch-second -> Instant). */
fun KycCaseOut.toSummary(): KycCaseSummary = KycCaseSummary(
    caseId = kyc_case_id,
    status = status,
    createdAt = Instant.ofEpochSecond(created_at),
    updatedAt = Instant.ofEpochSecond(updated_at),
)

// ---- Case detail (summary + synthesized timeline + reason codes) ----

/** The per-case detail: the summary, the synthesized timeline, and the review reason codes (if any). */
data class KycCaseDetail(
    val case: KycCaseSummary,
    val timeline: List<TimelineEvent>,
    val reasonCodes: List<String>,
)

/**
 * One synthesized timeline entry. [kind] is a stable machine token (e.g. "created", "documents",
 * "submitted", "decision", "current") used by the screen to pick an icon + label; [note] is optional
 * supplementary copy (e.g. a comma-joined reason-code list on a decision event).
 */
data class TimelineEvent(
    val at: Instant,
    val kind: String,
    val label: String,
    val note: String? = null,
)

/** Stable timeline-event kind tokens (UI maps these to icon + localized label). */
object TimelineKind {
    const val CREATED = "created"
    const val DOCUMENTS = "documents"
    const val SUBMITTED = "submitted"
    const val DECISION = "decision"
    const val CURRENT = "current"
    const val UPDATED = "updated"
}

/**
 * PURE synthesis of an ordered (oldest -> newest) timeline from a single [KycCaseOut]. There is NO wire history
 * array; the events are derived from the case fields:
 *   - created_at                              -> a "created" event,
 *   - files present                           -> a "documents" event (at the earliest uploaded_at, else created),
 *   - submission non-empty                    -> a "submitted" event,
 *   - review.decided_at + review.decision     -> a "decision" event carrying the reason codes (as note),
 *   - the status-derived "current" event      -> at updated_at,
 *   - updated_at (if no later event landed)   -> a trailing "updated" marker.
 *
 * [label] uses the supplied [labels] resolver so the screen can pass localized strings while the synthesis
 * itself stays pure + locale-agnostic (tests pass an identity resolver). Events are sorted by [at] ascending;
 * ties keep insertion order (so created precedes documents at the same instant).
 */
fun synthesizeTimeline(
    case: KycCaseOut,
    labels: TimelineLabels = TimelineLabels.TOKENS,
): List<TimelineEvent> {
    val created = Instant.ofEpochSecond(case.created_at)
    val updated = Instant.ofEpochSecond(case.updated_at)
    val events = mutableListOf<TimelineEvent>()

    events += TimelineEvent(at = created, kind = TimelineKind.CREATED, label = labels.created)

    if (case.files.isNotEmpty()) {
        val docAt = case.files.mapNotNull { it.uploaded_at }.minOrNull()
            ?.let { Instant.ofEpochSecond(it) }
            ?: created
        events += TimelineEvent(at = docAt, kind = TimelineKind.DOCUMENTS, label = labels.documents)
    }

    if (case.submission.isNotEmpty()) {
        // No explicit submitted_at on the wire; anchor at updated_at as the best-known submission time.
        events += TimelineEvent(at = updated, kind = TimelineKind.SUBMITTED, label = labels.submitted)
    }

    val review = case.review
    val decidedAt = review?.decided_at
    val decision = review?.decision
    if (decidedAt != null && !decision.isNullOrBlank()) {
        val note = review.reason_codes.takeIf { it.isNotEmpty() }?.joinToString(", ")
        events += TimelineEvent(
            at = Instant.ofEpochSecond(decidedAt),
            kind = TimelineKind.DECISION,
            label = labels.decision(decision),
            note = note,
        )
    }

    events += TimelineEvent(
        at = updated,
        kind = TimelineKind.CURRENT,
        label = labels.current(case.status),
    )

    // Stable oldest -> newest order; sortedBy is stable so same-instant ties keep insertion order.
    return events.sortedBy { it.at }
}

/**
 * Label resolver for [synthesizeTimeline]. Production passes a resolver backed by string resources; tests pass
 * [TOKENS] (stable machine tokens) so the synthesis stays pure + locale-agnostic.
 */
data class TimelineLabels(
    val created: String,
    val documents: String,
    val submitted: String,
    val decision: (String) -> String,
    val current: (KycCaseStatus) -> String,
) {
    companion object {
        /** Identity / token resolver for pure tests (no Android resources). */
        val TOKENS = TimelineLabels(
            created = TimelineKind.CREATED,
            documents = TimelineKind.DOCUMENTS,
            submitted = TimelineKind.SUBMITTED,
            decision = { "decision:$it" },
            current = { "current:${it.token}" },
        )
    }
}

// ---- Ongoing monitoring (schedule + triggers -> banner state) ----

/** Domain model of the ongoing-monitoring review schedule (epoch dates -> Instant). */
data class ReviewSchedule(
    val caseId: String?,
    val status: String,
    val nextReviewDate: Instant?,
    val graceDeadline: Instant?,
    val lastReviewDate: Instant?,
)

/** Domain model of one ongoing-monitoring trigger event. */
data class TriggerEvent(
    val eventId: String?,
    val triggerType: String?,
    val caseId: String?,
    val createdAt: Instant?,
    val note: String?,
)

/**
 * The derived monitoring banner state. [active] gates the banner. [status] is the (lowercased) schedule status
 * token or null; [message] is a stable machine token describing why the banner is active (the screen maps it to
 * a localized string), or null when inactive.
 */
data class MonitoringState(
    val active: Boolean,
    val status: String?,
    val nextReviewDate: Instant?,
    val graceDeadline: Instant?,
    val caseId: String?,
    val message: String?,
) {
    companion object {
        /** The inactive (no-banner) state. */
        val INACTIVE = MonitoringState(
            active = false,
            status = null,
            nextReviewDate = null,
            graceDeadline = null,
            caseId = null,
            message = null,
        )
    }
}

/** The schedule statuses that warrant a banner (the steady "active" state does NOT). */
private val ATTENTION_STATUSES = setOf("needs_review", "grace_period", "downgraded")

/** Maps the schedule envelope DTO to the domain schedule (null when absent). */
fun KycReviewScheduleEnvelopeDto.toDomain(): ReviewSchedule? = schedule?.toDomain()

/** Maps the schedule DTO to the domain schedule (epoch-second -> Instant; status lowercased). */
fun KycReviewScheduleDto.toDomain(): ReviewSchedule = ReviewSchedule(
    caseId = case_id,
    status = status.lowercase(),
    nextReviewDate = next_review_date?.let { Instant.ofEpochSecond(it) },
    graceDeadline = grace_deadline?.let { Instant.ofEpochSecond(it) },
    lastReviewDate = last_review_date?.let { Instant.ofEpochSecond(it) },
)

/** Maps the triggers envelope DTO to the domain trigger list. */
fun KycTriggerEventListEnvelopeDto.toDomain(): List<TriggerEvent> = events.map { it.toDomain() }

/** Maps a trigger-event DTO to the domain trigger (epoch-second -> Instant). */
fun KycTriggerEventDto.toDomain(): TriggerEvent = TriggerEvent(
    eventId = event_id,
    triggerType = trigger_type,
    caseId = case_id,
    createdAt = created_at?.let { Instant.ofEpochSecond(it) },
    note = note,
)

/**
 * PURE reducer deciding the monitoring banner state from the (already-mapped) [schedule] + [triggers]:
 *   - schedule present AND status in { needs_review, grace_period, downgraded } -> ACTIVE (status drives copy),
 *   - else any trigger event present                                            -> ACTIVE (generic trigger copy),
 *   - else                                                                      -> INACTIVE (no banner).
 *
 * The steady "active" schedule status does NOT raise the banner. No I/O, no clock: directly unit-testable.
 */
fun monitoringActive(
    schedule: ReviewSchedule?,
    triggers: List<TriggerEvent>,
): MonitoringState {
    if (schedule != null && schedule.status in ATTENTION_STATUSES) {
        return MonitoringState(
            active = true,
            status = schedule.status,
            nextReviewDate = schedule.nextReviewDate,
            graceDeadline = schedule.graceDeadline,
            caseId = schedule.caseId,
            message = "schedule:${schedule.status}",
        )
    }
    if (triggers.isNotEmpty()) {
        val latest = triggers.maxByOrNull { it.createdAt ?: Instant.EPOCH }
        return MonitoringState(
            active = true,
            status = schedule?.status,
            nextReviewDate = schedule?.nextReviewDate,
            graceDeadline = schedule?.graceDeadline,
            caseId = latest?.caseId ?: schedule?.caseId,
            message = "trigger",
        )
    }
    return MonitoringState.INACTIVE
}
