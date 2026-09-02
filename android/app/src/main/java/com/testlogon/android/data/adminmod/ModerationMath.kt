package com.testlogon.android.data.adminmod

/**
 * Framework-free moderation ticket math: the case-state machine, SLA/age computation and
 * action-gating shared by [com.testlogon.android.feature.adminmod.ModerationBoardViewModel] and
 * its Composables. Kept dependency-free (pure Kotlin, no Android / Moshi / coroutines) so it is
 * JVM-unit-testable and so the ViewModel, the list rows and the detail sheet share ONE source of
 * truth for "what state is this case in?", "what actions are legal here?" and "how overdue is it?".
 *
 * Mirrors the backend contract:
 *   - case states (app/services/moderation_case.py / moderation_lifecycle.py):
 *       visible / open -> under_review -> hold (confirm) or dismissed (dismiss)
 *       hold -> awaiting_final -> reinstated | deleted (final-call), or hold sweep -> deleted.
 *   - HOLD_WINDOW_SECONDS = 30d (poster-response hold) and AWAITING_FINAL_SLA_SECONDS = 14d
 *     (human final-call SLA) are the two deadlines a moderator watches.
 *   - a case is TERMINAL once it is dismissed / reinstated / deleted / closed and takes no
 *     further lifecycle actions.
 *
 * All times are epoch-SECONDS to match the DTOs.
 */
object ModerationMath {

    /** Poster-response hold window (backend moderation_case.HOLD_WINDOW_SECONDS). */
    const val HOLD_WINDOW_SECONDS: Long = 30L * 86400L

    /** Human final-call SLA once a case is escalated (backend AWAITING_FINAL_SLA_SECONDS). */
    const val AWAITING_FINAL_SLA_SECONDS: Long = 14L * 86400L

    /** Normalized moderation case states. [UNKNOWN] keeps forward-compat with new server tokens. */
    enum class CaseState {
        VISIBLE,
        OPEN,
        UNDER_REVIEW,
        HOLD,
        AWAITING_FINAL,
        DISMISSED,
        REINSTATED,
        DELETED,
        CLOSED,
        UNKNOWN,
    }

    /** Lifecycle actions a moderator can take, mirroring the /admin/moderation endpoints. */
    enum class CaseAction {
        CLAIM,
        DISMISS,
        CONFIRM,
        FINAL_CALL,
    }

    /**
     * Map a raw server state token to a [CaseState]. Blank / unknown -> [CaseState.UNKNOWN] so a
     * new backend state never crashes the board (degrade-safe). Accepts both the case-state tokens
     * and the legacy ticket "status" tokens the tickets list can emit.
     */
    fun caseState(raw: String?): CaseState = when (raw?.trim()?.lowercase()) {
        "visible" -> CaseState.VISIBLE
        "open", "new" -> CaseState.OPEN
        "under_review", "claimed", "in_review" -> CaseState.UNDER_REVIEW
        "hold", "on_hold" -> CaseState.HOLD
        "awaiting_final" -> CaseState.AWAITING_FINAL
        "dismissed" -> CaseState.DISMISSED
        "reinstated" -> CaseState.REINSTATED
        "deleted", "removed" -> CaseState.DELETED
        "closed", "resolved" -> CaseState.CLOSED
        null, "" -> CaseState.UNKNOWN
        else -> CaseState.UNKNOWN
    }

    /** A case is terminal once no lifecycle action can move it further. */
    fun isTerminal(state: CaseState): Boolean = when (state) {
        CaseState.DISMISSED,
        CaseState.REINSTATED,
        CaseState.DELETED,
        CaseState.CLOSED -> true
        else -> false
    }

    fun isTerminal(raw: String?): Boolean = isTerminal(caseState(raw))

    /**
     * Whether [action] is legal from [state]. This is the state-machine core — the board buttons
     * and the ViewModel both gate on this so an illegal action is never even offered.
     *
     *   - CLAIM: only an un-owned reviewable case (open/visible/under_review-unclaimed).
     *   - DISMISS / CONFIRM: only while under review (a fresh reviewable case).
     *   - FINAL_CALL: only once escalated to hold / awaiting_final.
     * Terminal states allow nothing.
     */
    fun canApply(state: CaseState, action: CaseAction, owned: Boolean = false): Boolean {
        if (isTerminal(state)) return false
        return when (action) {
            CaseAction.CLAIM -> !owned && (state == CaseState.OPEN ||
                state == CaseState.VISIBLE ||
                state == CaseState.UNDER_REVIEW ||
                state == CaseState.UNKNOWN)
            CaseAction.DISMISS,
            CaseAction.CONFIRM ->
                state == CaseState.OPEN ||
                    state == CaseState.VISIBLE ||
                    state == CaseState.UNDER_REVIEW
            CaseAction.FINAL_CALL ->
                state == CaseState.HOLD || state == CaseState.AWAITING_FINAL
        }
    }

    /** The set of lifecycle actions currently legal — drives which buttons the row shows. */
    fun availableActions(state: CaseState, owned: Boolean = false): List<CaseAction> =
        CaseAction.entries.filter { canApply(state, it, owned) }

    /**
     * Age of a ticket in whole seconds (never negative). [createdAt] and [now] are epoch-seconds.
     */
    fun ageSeconds(createdAt: Long, now: Long): Long = (now - createdAt).coerceAtLeast(0L)

    /** Age in whole minutes (floored), used for the "oldest open" and per-row age chips. */
    fun ageMinutes(createdAt: Long, now: Long): Long = ageSeconds(createdAt, now) / 60L

    /**
     * The active deadline for a case, if any:
     *   - HOLD: prefer the server-provided [holdUntil]; else createdAt + 30d.
     *   - AWAITING_FINAL: [holdUntil] (if given) else createdAt + 14d final-call SLA.
     * Reviewable/terminal states have no hold deadline -> null.
     */
    fun deadline(state: CaseState, createdAt: Long, holdUntil: Long?): Long? = when (state) {
        CaseState.HOLD ->
            holdUntil?.takeIf { it > 0L } ?: (createdAt + HOLD_WINDOW_SECONDS)
        CaseState.AWAITING_FINAL ->
            holdUntil?.takeIf { it > 0L } ?: (createdAt + AWAITING_FINAL_SLA_SECONDS)
        else -> null
    }

    /**
     * Seconds remaining until [deadline]; negative once breached; null when there is no deadline.
     */
    fun secondsToDeadline(
        state: CaseState,
        createdAt: Long,
        holdUntil: Long?,
        now: Long,
    ): Long? = deadline(state, createdAt, holdUntil)?.let { it - now }

    /** True once a case with a deadline has passed it (SLA breach). No-deadline states are never breached. */
    fun isSlaBreached(
        state: CaseState,
        createdAt: Long,
        holdUntil: Long?,
        now: Long,
    ): Boolean {
        val remaining = secondsToDeadline(state, createdAt, holdUntil, now) ?: return false
        return remaining < 0L
    }

    /** Coarse urgency bucket for row emphasis. */
    enum class SlaBucket { NONE, OK, DUE_SOON, BREACHED }

    /**
     * Bucket a case for display. [dueSoonSeconds] defaults to 24h — inside that window (but not yet
     * breached) is DUE_SOON. States without a deadline are NONE.
     */
    fun slaBucket(
        state: CaseState,
        createdAt: Long,
        holdUntil: Long?,
        now: Long,
        dueSoonSeconds: Long = 86400L,
    ): SlaBucket {
        val remaining = secondsToDeadline(state, createdAt, holdUntil, now) ?: return SlaBucket.NONE
        return when {
            remaining < 0L -> SlaBucket.BREACHED
            remaining <= dueSoonSeconds -> SlaBucket.DUE_SOON
            else -> SlaBucket.OK
        }
    }
}
