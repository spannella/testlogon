package com.testlogon.android.data.marketing.campaigns

import java.util.Locale

/**
 * Framework-free pure logic for OFBiz Marketing CAMPAIGNS: the campaign lifecycle state machine
 * (a 1:1 mirror of `_CAMPAIGN_TRANSITIONS` in app/services/marketing_campaigns.py), plus display
 * formatters for money (budget cents) and segment/list sizes.
 *
 * Nothing here touches Android, Retrofit or coroutines, so it is fully unit-testable on the JVM.
 */
object MarketingMath {

    /**
     * Campaign lifecycle. Values match the server status strings exactly (lowercase). UNKNOWN folds any
     * unrecognized server string so the UI never crashes on a new backend status.
     */
    enum class CampaignStatus(val wire: String) {
        DRAFT("draft"),
        SCHEDULED("scheduled"),
        ACTIVE("active"),
        PAUSED("paused"),
        COMPLETED("completed"),
        ARCHIVED("archived"),
        UNKNOWN("");

        companion object {
            fun from(raw: String?): CampaignStatus = when (raw?.lowercase(Locale.US)) {
                "draft" -> DRAFT
                "scheduled" -> SCHEDULED
                "active" -> ACTIVE
                "paused" -> PAUSED
                "completed" -> COMPLETED
                "archived" -> ARCHIVED
                else -> UNKNOWN
            }
        }
    }

    /** Campaign objective. Values match the server objective strings. */
    enum class CampaignObjective(val wire: String, val label: String) {
        AWARENESS("awareness", "Awareness"),
        TRAFFIC("traffic", "Traffic"),
        CONVERSIONS("conversions", "Conversions"),
        RETENTION("retention", "Retention");

        companion object {
            val ALL: List<CampaignObjective> = entries

            fun from(raw: String?): CampaignObjective? = when (raw?.lowercase(Locale.US)) {
                "awareness" -> AWARENESS
                "traffic" -> TRAFFIC
                "conversions" -> CONVERSIONS
                "retention" -> RETENTION
                else -> null
            }
        }
    }

    /**
     * The allowed status transitions, mirroring the backend state machine exactly:
     *   draft     -> scheduled, active, archived
     *   scheduled -> active, archived
     *   active    -> paused, completed, archived
     *   paused    -> active, archived
     *   completed -> archived
     *   archived  -> (terminal)
     */
    private val TRANSITIONS: Map<CampaignStatus, Set<CampaignStatus>> = mapOf(
        CampaignStatus.DRAFT to setOf(CampaignStatus.SCHEDULED, CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
        CampaignStatus.SCHEDULED to setOf(CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
        CampaignStatus.ACTIVE to setOf(CampaignStatus.PAUSED, CampaignStatus.COMPLETED, CampaignStatus.ARCHIVED),
        CampaignStatus.PAUSED to setOf(CampaignStatus.ACTIVE, CampaignStatus.ARCHIVED),
        CampaignStatus.COMPLETED to setOf(CampaignStatus.ARCHIVED),
        CampaignStatus.ARCHIVED to emptySet(),
        CampaignStatus.UNKNOWN to emptySet(),
    )

    /** The valid target states reachable from [current], in a stable display order. */
    fun allowedTransitions(current: CampaignStatus): List<CampaignStatus> {
        val allowed = TRANSITIONS[current].orEmpty()
        // Preserve enum declaration order for deterministic UI.
        return CampaignStatus.entries.filter { it in allowed }
    }

    /** True when [current] -> [target] is a legal transition. */
    fun canTransition(current: CampaignStatus, target: CampaignStatus): Boolean =
        target in TRANSITIONS[current].orEmpty()

    /** True when the campaign is in a terminal state (no further transitions). */
    fun isTerminal(status: CampaignStatus): Boolean = TRANSITIONS[status].orEmpty().isEmpty()

    /**
     * "Send" (materialize + fan-out to recipients) is only meaningful for a live campaign, matching the
     * web affordance which surfaces Send on active campaigns.
     */
    fun canSend(status: CampaignStatus): Boolean = status == CampaignStatus.ACTIVE

    /**
     * Format an integer cents budget as USD, e.g. 150000 -> "$1,500.00", 0 -> "$0.00".
     * Negative values (should not occur) are formatted with a leading minus.
     */
    fun formatBudget(cents: Long): String {
        val negative = cents < 0
        val abs = if (negative) -cents else cents
        val dollars = abs / 100
        val remainder = (abs % 100).toInt()
        val grouped = groupThousands(dollars)
        val body = "$" + grouped + "." + remainder.toString().padStart(2, '0')
        return if (negative) "-$body" else body
    }

    /**
     * Parse a user-entered dollar string (e.g. "1500", "1,500.50", "$25") into integer cents, or null
     * when the input is blank / not a valid non-negative amount. Used to validate the create form.
     */
    fun parseBudgetToCents(input: String): Long? {
        val cleaned = input.trim().removePrefix("$").replace(",", "")
        if (cleaned.isEmpty()) return null
        val value = cleaned.toDoubleOrNull() ?: return null
        if (value < 0.0 || value.isNaN() || value.isInfinite()) return null
        return Math.round(value * 100.0)
    }

    /**
     * Human-friendly size label for a segment or contact list, e.g.
     *  0     -> "No members"
     *  1     -> "1 member"
     *  42    -> "42 members"
     *  1500  -> "1.5K members"
     *  2_000_000 -> "2M members"
     */
    fun formatSegmentSize(count: Int): String {
        if (count <= 0) return "No members"
        val noun = if (count == 1) "member" else "members"
        return compact(count) + " " + noun
    }

    /** Compact-number formatting (1_500 -> "1.5K", 2_000_000 -> "2M"). */
    fun compact(count: Int): String = when {
        count < 1_000 -> count.toString()
        count < 1_000_000 -> trimTenth(count / 1_000.0) + "K"
        else -> trimTenth(count / 1_000_000.0) + "M"
    }

    /** One-line predicate summary, e.g. "total_spend_cents >= 1000". */
    fun formatPredicate(attribute: String, operator: String, value: String): String {
        val op = when (operator.lowercase(Locale.US)) {
            "eq" -> "="
            "neq" -> "≠"
            "gt" -> ">"
            "gte" -> "≥"
            "lt" -> "<"
            "lte" -> "≤"
            "in" -> "in"
            "not_in" -> "not in"
            else -> operator
        }
        return "$attribute $op $value".trim()
    }

    // ---- internal helpers ----

    private fun trimTenth(v: Double): String {
        val rounded = Math.round(v * 10.0) / 10.0
        return if (rounded % 1.0 == 0.0) rounded.toLong().toString()
        else String.format(Locale.US, "%.1f", rounded)
    }

    private fun groupThousands(n: Long): String {
        val s = n.toString()
        if (s.length <= 3) return s
        val sb = StringBuilder()
        val first = s.length % 3
        if (first > 0) {
            sb.append(s, 0, first)
            if (s.length > first) sb.append(',')
        }
        var i = first
        while (i < s.length) {
            sb.append(s, i, i + 3)
            if (i + 3 < s.length) sb.append(',')
            i += 3
        }
        return sb.toString()
    }
}
