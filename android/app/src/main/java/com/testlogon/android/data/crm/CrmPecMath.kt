package com.testlogon.android.data.crm

/**
 * CRM-AND-PEC — PURE, framework-free logic for the CRM Projects / Events / Campaigns surfaces.
 * No Android / java.time-formatting types leak in, so every function is JVM-unit-testable
 * (mirrors the CrmSalesMath idiom).
 *
 * Responsibilities:
 *  - project status classification + label (mirror CrmProjectStatus in crmProjects.ts).
 *  - event capacity state (full / waitlisting / open) from a CrmCapacity roll-up.
 *  - campaign status/type labels + budget cents formatting + open/click-rate percent formatting.
 *  - epoch-timestamp → "YYYY-MM-DD" date formatting (UTC, no locale/Android dependency), tolerant
 *    of BOTH epoch-seconds and epoch-millis (the backend uses seconds; guard against ms drift).
 *
 * Degrade, never throw: null / malformed inputs render as a neutral placeholder rather than raising,
 * so a 404 (module disabled) or dev-host drift shows cleanly.
 */
object CrmPecMath {

    const val EM_DASH: String = "—"

    // ── Project status (mirror CrmProjectStatus) ──────────────────────────────

    const val PROJECT_DRAFT = "draft"
    const val PROJECT_IN_REVIEW = "in_review"
    const val PROJECT_UNDERWAY = "underway"
    const val PROJECT_COMPLETED = "completed"
    const val PROJECT_DEFERRED = "deferred"

    /** Ordered, curated status list used by the create/edit chip row. */
    val PROJECT_STATUSES: List<String> = listOf(
        PROJECT_DRAFT, PROJECT_IN_REVIEW, PROJECT_UNDERWAY, PROJECT_COMPLETED, PROJECT_DEFERRED,
    )

    fun isProjectClosed(status: String?): Boolean =
        status == PROJECT_COMPLETED || status == PROJECT_DEFERRED

    fun isProjectActive(status: String?): Boolean =
        status == PROJECT_UNDERWAY || status == PROJECT_IN_REVIEW

    /** Human label for a project status key. Unknown keys are title-cased from snake_case. */
    fun projectStatusLabel(status: String?): String = when (status) {
        PROJECT_DRAFT -> "Draft"
        PROJECT_IN_REVIEW -> "In review"
        PROJECT_UNDERWAY -> "Underway"
        PROJECT_COMPLETED -> "Completed"
        PROJECT_DEFERRED -> "Deferred"
        null -> EM_DASH
        else -> titleCaseSnake(status)
    }

    /**
     * Clamp a raw percent-complete (0..100) for a progress bar. Out-of-range / negative degrades
     * into the valid band rather than overflowing the bar.
     */
    fun clampPercent(percent: Int): Int = percent.coerceIn(0, 100)

    // ── Event capacity state ──────────────────────────────────────────────────

    enum class CapacityState { UNLIMITED, OPEN, FULL }

    /**
     * Derive the coarse capacity state from a capacity roll-up.
     *
     * A null / non-positive [maxAttendance] means uncapped → UNLIMITED. Otherwise FULL when the
     * available spots are zero-or-fewer (or accepted has met/exceeded the cap), else OPEN.
     */
    fun capacityState(maxAttendance: Int?, acceptedCount: Int, availableSpots: Int?): CapacityState {
        if (maxAttendance == null || maxAttendance <= 0) return CapacityState.UNLIMITED
        val remaining = availableSpots ?: (maxAttendance - acceptedCount)
        return if (remaining <= 0 || acceptedCount >= maxAttendance) CapacityState.FULL else CapacityState.OPEN
    }

    /** Short "3 / 10" style attendance label; uncapped shows "N going". */
    fun capacityLabel(maxAttendance: Int?, acceptedCount: Int): String =
        if (maxAttendance == null || maxAttendance <= 0) {
            "$acceptedCount going"
        } else {
            "$acceptedCount / $maxAttendance"
        }

    // ── Event invitee / registration (EVT-002/003) ────────────────────────────
    // Mirrors CrmInviteStatus / CrmRegistrationStatus in crmEvents.ts.

    const val INVITE_PENDING = "pending"
    const val INVITE_SENT = "sent"
    const val INVITE_ACCEPTED = "accepted"
    const val INVITE_DECLINED = "declined"

    const val REG_REGISTERED = "registered"
    const val REG_ACCEPTED = "accepted"
    const val REG_DECLINED = "declined"
    const val REG_WAITLISTED = "waitlisted"
    const val REG_ATTENDED = "attended"

    /** Human label for an invite status; unknown/blank keys are title-cased / em-dashed. */
    fun inviteStatusLabel(status: String?): String = when (status) {
        INVITE_PENDING -> "Pending"
        INVITE_SENT -> "Invited"
        INVITE_ACCEPTED -> "Accepted"
        INVITE_DECLINED -> "Declined"
        null -> EM_DASH
        else -> titleCaseSnake(status)
    }

    /** Human label for a registration status; unknown/blank keys are title-cased / em-dashed. */
    fun registrationStatusLabel(status: String?): String = when (status) {
        REG_REGISTERED -> "Registered"
        REG_ACCEPTED -> "Accepted"
        REG_DECLINED -> "Declined"
        REG_WAITLISTED -> "Waitlisted"
        REG_ATTENDED -> "Attended"
        null -> EM_DASH
        else -> titleCaseSnake(status)
    }

    /** True when a "send invitations" action is meaningful (there is at least one un-sent invitee). */
    fun canSendInvitations(pendingCount: Int): Boolean = pendingCount > 0

    /** Count of invitees still awaiting a send (status pending). */
    fun pendingInviteCount(statuses: List<String?>): Int =
        statuses.count { it == INVITE_PENDING }

    /**
     * Whether a registrant may still RSVP (accept/decline). Once they have accepted, declined, or
     * been checked in / marked attended, the RSVP action is closed. A waitlisted or freshly-registered
     * row is still open.
     */
    fun canRespond(status: String?, checkedInAt: Long?): Boolean {
        if (isCheckedIn(checkedInAt)) return false
        return when (status) {
            REG_ACCEPTED, REG_DECLINED, REG_ATTENDED -> false
            else -> true
        }
    }

    /** A registrant is checked-in when a positive check-in timestamp is present. */
    fun isCheckedIn(checkedInAt: Long?): Boolean = checkedInAt != null && checkedInAt > 0

    /**
     * Whether an owner/admin may check a registrant in: only an accepted (or already-registered)
     * attendee who has not yet been checked in. Declined / waitlisted attendees cannot be checked in.
     */
    fun canCheckIn(status: String?, checkedInAt: Long?): Boolean {
        if (isCheckedIn(checkedInAt)) return false
        return when (status) {
            REG_ACCEPTED, REG_REGISTERED, REG_ATTENDED -> true
            else -> false
        }
    }

    /** Coarse RSVP state for surfacing chips / actions on a registration row. */
    enum class RsvpState { PENDING, ACCEPTED, DECLINED, WAITLISTED, CHECKED_IN }

    fun rsvpState(status: String?, checkedInAt: Long?): RsvpState = when {
        isCheckedIn(checkedInAt) || status == REG_ATTENDED -> RsvpState.CHECKED_IN
        status == REG_ACCEPTED -> RsvpState.ACCEPTED
        status == REG_DECLINED -> RsvpState.DECLINED
        status == REG_WAITLISTED -> RsvpState.WAITLISTED
        else -> RsvpState.PENDING
    }

    /** "Waitlist #3" style label, or em-dash when not waitlisted / no position. */
    fun waitlistLabel(position: Int?): String =
        if (position == null || position <= 0) EM_DASH else "Waitlist #$position"

    // ── Campaign status / type ────────────────────────────────────────────────

    fun campaignStatusLabel(status: String?): String =
        if (status.isNullOrBlank()) EM_DASH else titleCaseSnake(status)

    fun campaignTypeLabel(type: String?): String = when (type) {
        "email" -> "Email"
        "phone" -> "Phone"
        "mail" -> "Mail"
        "fax" -> "Fax"
        "sms" -> "SMS"
        null -> EM_DASH
        else -> titleCaseSnake(type)
    }

    // ── Money / rate formatting ───────────────────────────────────────────────

    /** Integer cents → "$1,234.56". Negative preserved as "-$…". */
    fun formatCents(cents: Long): String {
        val negative = cents < 0
        val abs = if (negative) -cents else cents
        val dollars = abs / 100
        val remainder = (abs % 100).toInt()
        val grouped = groupThousands(dollars)
        val centsStr = remainder.toString().padStart(2, '0')
        return (if (negative) "-$" else "$") + "$grouped.$centsStr"
    }

    /** A 0.0..1.0 rate → "42.5%". Out-of-range clamps into 0..100%. Handles the drift where the
     *  backend already returns a 0..100 percentage by treating any value > 1.0 as already-percent. */
    fun formatRate(rate: Double): String {
        val pct = when {
            rate.isNaN() -> 0.0
            rate <= 1.0 -> rate * 100.0
            else -> rate
        }.coerceIn(0.0, 100.0)
        // one decimal place, trimming a trailing ".0"
        val rounded = kotlin.math.round(pct * 10.0) / 10.0
        val s = if (rounded == rounded.toLong().toDouble()) rounded.toLong().toString() else rounded.toString()
        return "$s%"
    }

    // ── Date formatting ───────────────────────────────────────────────────────

    private val DAYS_IN_MONTH = intArrayOf(31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31)

    /**
     * Format an epoch timestamp as an ISO "YYYY-MM-DD" UTC date. Accepts null (→ em-dash) and is
     * tolerant of both epoch-SECONDS and epoch-MILLIS: any magnitude ≥ 1e12 is treated as millis.
     * Pure integer/calendar math — no java.time, no locale — so it is deterministic under test.
     */
    fun formatDate(epoch: Long?): String {
        if (epoch == null || epoch <= 0) return EM_DASH
        val seconds = if (epoch >= 1_000_000_000_000L) epoch / 1000 else epoch
        var days = Math.floorDiv(seconds, 86_400L)
        // days since 1970-01-01
        var year = 1970
        while (true) {
            val yearDays = if (isLeap(year)) 366 else 365
            if (days >= yearDays) {
                days -= yearDays
                year++
            } else {
                break
            }
        }
        var month = 0
        while (month < 12) {
            var dim = DAYS_IN_MONTH[month].toLong()
            if (month == 1 && isLeap(year)) dim = 29
            if (days >= dim) {
                days -= dim
                month++
            } else {
                break
            }
        }
        val day = (days + 1).toInt()
        val mm = (month + 1).toString().padStart(2, '0')
        val dd = day.toString().padStart(2, '0')
        return "$year-$mm-$dd"
    }

    /** A "start → end" date-range label, degrading each side to em-dash. Returns em-dash if both absent. */
    fun dateRange(start: Long?, end: Long?): String {
        if ((start == null || start <= 0) && (end == null || end <= 0)) return EM_DASH
        return "${formatDate(start)} → ${formatDate(end)}"
    }

    // ── internal helpers ──────────────────────────────────────────────────────

    private fun isLeap(y: Int): Boolean = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0)

    private fun groupThousands(value: Long): String {
        val s = value.toString()
        if (s.length <= 3) return s
        val sb = StringBuilder()
        val firstGroup = s.length % 3
        var i = 0
        if (firstGroup > 0) {
            sb.append(s, 0, firstGroup)
            i = firstGroup
        }
        while (i < s.length) {
            if (sb.isNotEmpty()) sb.append(',')
            sb.append(s, i, i + 3)
            i += 3
        }
        return sb.toString()
    }

    private fun titleCaseSnake(raw: String): String =
        raw.split('_', ' ')
            .filter { it.isNotBlank() }
            .joinToString(" ") { part ->
                part.replaceFirstChar { c -> c.uppercaseChar() }
            }
            .ifBlank { EM_DASH }
}
