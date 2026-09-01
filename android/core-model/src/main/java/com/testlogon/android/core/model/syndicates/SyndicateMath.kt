package com.testlogon.android.core.model.syndicates

/**
 * Pure (framework-free) helpers for the syndicate MANAGEMENT surface (invites / join-requests / bundle
 * plans / subscribe). Deliberately has NO Android / network / coroutine dependency so it is unit-testable
 * on the plain JVM (see SyndicateMathTest).
 *
 * Mirrors the backend contract in app/routers/syndicates.py + app/models.py:
 *   - BundlePlanCreateIn: name 2..100, description <=1000, price_cents 100..100000, interval month|year.
 *   - A subscriber cannot subscribe twice to the same plan (dedupe by plan_id among ACTIVE subs).
 *   - Only the admin may invite / approve / reject / transfer-admin / author plans.
 *
 * Money is always integer *_cents; there is NO float arithmetic here.
 */
object SyndicateMath {

    // Backend BundlePlanCreateIn field bounds (app/models.py).
    const val PLAN_NAME_MIN = 2
    const val PLAN_NAME_MAX = 100
    const val PLAN_DESC_MAX = 1000
    const val PLAN_PRICE_MIN_CENTS = 100
    const val PLAN_PRICE_MAX_CENTS = 100_000

    /** The two accepted billing intervals (BundlePlanCreateIn interval pattern ^(month|year)$). */
    val VALID_INTERVALS: List<String> = listOf("month", "year")

    /** SyndicateJoinRequestIn.message max_length (app/models.py). */
    const val JOIN_MESSAGE_MAX = 500

    /**
     * Validate a bundle-plan draft against the backend BundlePlanCreateIn bounds. Returns an ordered list
     * of field-scoped errors (empty == valid). Trimming mirrors what the UI submits (name is trimmed).
     */
    fun validatePlanDraft(
        name: String,
        priceCents: Int,
        interval: String,
        description: String = "",
    ): List<PlanFieldError> {
        val errors = mutableListOf<PlanFieldError>()
        val trimmedName = name.trim()
        when {
            trimmedName.length < PLAN_NAME_MIN ->
                errors += PlanFieldError(PlanField.NAME, "Name must be at least $PLAN_NAME_MIN characters")
            trimmedName.length > PLAN_NAME_MAX ->
                errors += PlanFieldError(PlanField.NAME, "Name must be at most $PLAN_NAME_MAX characters")
        }
        when {
            priceCents < PLAN_PRICE_MIN_CENTS ->
                errors += PlanFieldError(PlanField.PRICE, "Price must be at least ${formatCents(PLAN_PRICE_MIN_CENTS)}")
            priceCents > PLAN_PRICE_MAX_CENTS ->
                errors += PlanFieldError(PlanField.PRICE, "Price must be at most ${formatCents(PLAN_PRICE_MAX_CENTS)}")
        }
        if (interval !in VALID_INTERVALS) {
            errors += PlanFieldError(PlanField.INTERVAL, "Interval must be one of ${VALID_INTERVALS.joinToString("/")}")
        }
        if (description.length > PLAN_DESC_MAX) {
            errors += PlanFieldError(PlanField.DESCRIPTION, "Description must be at most $PLAN_DESC_MAX characters")
        }
        return errors
    }

    /** True when the plan draft passes every backend bound (a convenience over [validatePlanDraft]). */
    fun isPlanDraftValid(
        name: String,
        priceCents: Int,
        interval: String,
        description: String = "",
    ): Boolean = validatePlanDraft(name, priceCents, interval, description).isEmpty()

    /**
     * Parse a user-typed price string ("$12.50", "12.5", "  9 ") into integer cents, or null when it is
     * blank / non-numeric / negative. Half-cent inputs round to the nearest cent. Currency symbols,
     * spaces and thousands-commas are tolerated.
     */
    fun parsePriceToCents(raw: String): Int? {
        val cleaned = raw.trim().removePrefix("$").replace(",", "").replace(" ", "")
        if (cleaned.isEmpty()) return null
        val dollars = cleaned.toDoubleOrNull() ?: return null
        if (dollars < 0.0) return null
        return Math.round(dollars * 100.0).toInt()
    }

    /** Render integer cents as a plain "$X.YY" string (no locale grouping; UI-agnostic). */
    fun formatCents(cents: Int): String {
        val sign = if (cents < 0) "-" else ""
        val abs = kotlin.math.abs(cents)
        return "$sign$${abs / 100}.${(abs % 100).toString().padStart(2, '0')}"
    }

    /**
     * The per-interval price label, e.g. "$9.99 / mo" or "$99.00 / yr". Unknown intervals fall back to the
     * raw interval token.
     */
    fun priceLabel(priceCents: Int, interval: String): String {
        val unit = when (interval.lowercase()) {
            "month" -> "mo"
            "year" -> "yr"
            else -> interval
        }
        return "${formatCents(priceCents)} / $unit"
    }

    /**
     * Whether [subscriberId] can subscribe to [planId]. False when they already hold an ACTIVE subscription
     * to that exact plan (the backend rejects a duplicate). [activePlanIds] is the set of plan_ids the
     * subscriber currently subscribes to (any non-cancelled status counts as active).
     */
    fun canSubscribe(planId: String, activePlanIds: Set<String>): Boolean =
        planId.isNotBlank() && planId !in activePlanIds

    /**
     * Whether [userId] is eligible to be INVITED to a syndicate: they must not already be a member and
     * must not already have a pending invite. Guards the admin invite form against duplicate sends.
     */
    fun canInvite(userId: String, memberIds: Set<String>, pendingInviteeIds: Set<String>): Boolean =
        userId.isNotBlank() && userId !in memberIds && userId !in pendingInviteeIds

    /**
     * Whether the current viewer may perform an ADMIN action (invite / approve / reject / transfer-admin /
     * author a plan). Mirrors the server-side _require_admin check. [adminUserId] may be null/blank when the
     * profile has not loaded, in which case the action is NOT allowed (fail-closed).
     */
    fun isAdmin(viewerUserId: String?, adminUserId: String?): Boolean =
        !viewerUserId.isNullOrBlank() && viewerUserId == adminUserId

    /**
     * Whether a transfer-admin target is valid: the new admin must be a non-blank member who is NOT already
     * the current admin. Fail-closed on blanks.
     */
    fun canTransferAdmin(newAdminUserId: String, currentAdminUserId: String?, memberIds: Set<String>): Boolean =
        newAdminUserId.isNotBlank() &&
            newAdminUserId != currentAdminUserId &&
            newAdminUserId in memberIds

    /** Normalise a wire invite/request status token to a typed [MembershipStatus] with an UNKNOWN fallback. */
    fun membershipStatus(raw: String?): MembershipStatus = when (raw?.trim()?.lowercase()) {
        "pending" -> MembershipStatus.PENDING
        "accepted", "approved", "active" -> MembershipStatus.ACCEPTED
        "rejected", "declined" -> MembershipStatus.REJECTED
        null, "" -> MembershipStatus.UNKNOWN
        else -> MembershipStatus.UNKNOWN
    }

    /**
     * Human-readable label for one audit action token (the backend emits snake_case actions like
     * "invite_member" / "approve_request" / "transfer_admin"). Unknown tokens are title-cased verbatim.
     */
    fun auditActionLabel(action: String?): String {
        val token = action?.trim().orEmpty()
        if (token.isEmpty()) return "Activity"
        return token.split('_', ' ')
            .filter { it.isNotBlank() }
            .joinToString(" ") { part -> part.replaceFirstChar { it.uppercaseChar() } }
    }
}

/** Which plan field an error belongs to (drives inline per-field UI errors). */
enum class PlanField { NAME, PRICE, INTERVAL, DESCRIPTION }

/** One field-scoped validation error for a bundle-plan draft. */
data class PlanFieldError(val field: PlanField, val message: String)

/** Typed invite/request lifecycle status with an UNKNOWN fallback for forward-compat wire values. */
enum class MembershipStatus { PENDING, ACCEPTED, REJECTED, UNKNOWN }
