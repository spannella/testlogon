package com.testlogon.android.data.crm

/**
 * CRM-AND-1 — PURE, framework-free logic for the CRM Sales surface. No Android / java.time types, so
 * every function here is JVM-unit-testable (mirrors the KbMath / PurchaseHistoryMath idiom).
 *
 * Responsibilities:
 *  - lead-score bucketing (server score 0..maxScore -> Cold / Warm / Hot band for the list badge).
 *  - opportunity stage classification (won / lost / closed / open) mirroring the web helpers in
 *    frontend/src/api/endpoints/opportunities.ts (isWonStage / isLostStage / isClosedStage).
 *  - pipeline weighted-forecast maths: per-stage weighted amount (amount * probability) and the
 *    open-pipeline weighted roll-up used by the pipeline board header.
 *  - cents formatting (integer cents -> "$1,234.56") with no locale/Android dependency.
 *
 * Degrade, never throw: null / malformed inputs are treated as "nothing to show" (empty / zero)
 * rather than raising, so a 404 (module disabled) or dev-host drift renders cleanly.
 */
object CrmSalesMath {

    // ── Lead scoring ────────────────────────────────────────────────────────

    /** Coarse lead-quality band derived from the server's numeric score. */
    enum class LeadScoreBand { COLD, WARM, HOT }

    /** Default backend cap (LeadScoreRules.max_score default in app/services/leads.py). */
    const val DEFAULT_MAX_SCORE: Int = 100

    /**
     * Bucket a raw lead score into a coarse band for the list badge.
     *
     * The score is clamped into 0..[maxScore] first (degrade on out-of-range / negative caps). The band
     * split is on the fraction of the cap: < 1/3 -> COLD, < 2/3 -> WARM, else HOT. A non-positive
     * [maxScore] degrades to COLD (nothing meaningful to bucket).
     */
    fun scoreBand(score: Int, maxScore: Int = DEFAULT_MAX_SCORE): LeadScoreBand {
        if (maxScore <= 0) return LeadScoreBand.COLD
        val clamped = score.coerceIn(0, maxScore)
        val fraction = clamped.toDouble() / maxScore.toDouble()
        return when {
            fraction < 1.0 / 3.0 -> LeadScoreBand.COLD
            fraction < 2.0 / 3.0 -> LeadScoreBand.WARM
            else -> LeadScoreBand.HOT
        }
    }

    // ── Opportunity stage classification (mirror opportunities.ts) ───────────

    const val STAGE_CLOSED_WON: String = "closed_won"
    const val STAGE_CLOSED_LOST: String = "closed_lost"

    fun isWonStage(stage: String?): Boolean = stage == STAGE_CLOSED_WON

    fun isLostStage(stage: String?): Boolean = stage == STAGE_CLOSED_LOST

    fun isClosedStage(stage: String?): Boolean = isWonStage(stage) || isLostStage(stage)

    fun isOpenStage(stage: String?): Boolean = !isClosedStage(stage)

    /**
     * Human label for a stage key. Prefers the curated map (mirrors STAGE_LABELS in opportunities.ts);
     * unknown keys fall back to a title-cased de-underscored form so a new server stage still renders.
     */
    fun stageLabel(stage: String?): String {
        if (stage.isNullOrBlank()) return "—"
        STAGE_LABELS[stage]?.let { return it }
        return stage.split('_')
            .filter { it.isNotBlank() }
            .joinToString(" ") { part -> part.replaceFirstChar { it.uppercaseChar() } }
    }

    /** Canonical stage order (open stages first, then won, then lost) mirroring the web OPPORTUNITY_STAGES. */
    val STAGE_ORDER: List<String> = listOf(
        "prospecting",
        "qualification",
        "needs_analysis",
        "value_proposition",
        "id_decision_makers",
        "proposal_price_quote",
        "negotiation_review",
        STAGE_CLOSED_WON,
        STAGE_CLOSED_LOST,
    )

    private val STAGE_LABELS: Map<String, String> = mapOf(
        "prospecting" to "Prospecting",
        "qualification" to "Qualification",
        "needs_analysis" to "Needs Analysis",
        "value_proposition" to "Value Proposition",
        "id_decision_makers" to "Decision Makers",
        "proposal_price_quote" to "Proposal / Quote",
        "negotiation_review" to "Negotiation",
        STAGE_CLOSED_WON to "Closed Won",
        STAGE_CLOSED_LOST to "Closed Lost",
    )

    /** Default win-probability for a stage, used when the server omits a per-opportunity probability. */
    fun defaultProbabilityFor(stage: String?): Int = when (stage) {
        "prospecting" -> 10
        "qualification" -> 20
        "needs_analysis" -> 25
        "value_proposition" -> 40
        "id_decision_makers" -> 50
        "proposal_price_quote" -> 65
        "negotiation_review" -> 80
        STAGE_CLOSED_WON -> 100
        STAGE_CLOSED_LOST -> 0
        else -> 10
    }

    // ── Weighted forecast maths ─────────────────────────────────────────────

    /**
     * Weighted amount for one opportunity: amount * (probability / 100), rounded to whole cents.
     *
     * [probability] is clamped into 0..100. A closed_lost stage always weights to 0 and closed_won to the
     * full amount, regardless of a stale probability field (mirrors the backend weighting invariant).
     * Negative amounts degrade to 0.
     */
    fun weightedAmountCents(amountCents: Long, probability: Int, stage: String? = null): Long {
        if (amountCents <= 0L) return 0L
        if (isLostStage(stage)) return 0L
        if (isWonStage(stage)) return amountCents
        val p = probability.coerceIn(0, 100)
        // round half-up on cents
        return (amountCents * p + 50) / 100
    }

    /**
     * Open-pipeline weighted roll-up: sum of [weightedAmountCents] across the OPEN opportunities only
     * (closed_won / closed_lost excluded — they are realised / dead, not pipeline). Returns 0 for empty.
     */
    fun openPipelineWeightedCents(opps: List<PipelineOppLike>): Long =
        opps.asSequence()
            .filter { isOpenStage(it.stage) }
            .sumOf { weightedAmountCents(it.amountCents, it.probability, it.stage) }

    /** Total un-weighted amount across OPEN opportunities. */
    fun openPipelineAmountCents(opps: List<PipelineOppLike>): Long =
        opps.asSequence().filter { isOpenStage(it.stage) }.sumOf { maxOf(0L, it.amountCents) }

    /** Total realised (closed_won) amount. */
    fun wonAmountCents(opps: List<PipelineOppLike>): Long =
        opps.asSequence().filter { isWonStage(it.stage) }.sumOf { maxOf(0L, it.amountCents) }

    /**
     * Win-rate over CLOSED opportunities only: won / (won + lost), as a 0..100 percentage rounded to the
     * nearest whole percent. Returns 0 when nothing is closed yet (avoid a divide-by-zero).
     */
    fun winRatePct(opps: List<PipelineOppLike>): Int {
        val won = opps.count { isWonStage(it.stage) }
        val lost = opps.count { isLostStage(it.stage) }
        val closed = won + lost
        if (closed == 0) return 0
        return ((won.toDouble() / closed.toDouble()) * 100.0 + 0.5).toInt()
    }

    /** Group opportunities by stage, preserving [STAGE_ORDER] then any unknown trailing stages. */
    fun groupByStage(opps: List<PipelineOppLike>): List<Pair<String, List<PipelineOppLike>>> {
        val byStage = opps.groupBy { it.stage ?: "prospecting" }
        val ordered = STAGE_ORDER.filter { byStage.containsKey(it) }
        val extras = byStage.keys.filter { it !in STAGE_ORDER }.sorted()
        return (ordered + extras).map { it to (byStage[it] ?: emptyList()) }
    }

    // ── Cents formatting ────────────────────────────────────────────────────

    /** Integer cents -> "$1,234.56" (USD-style, no locale dependency so it is deterministic in tests). */
    fun formatCents(cents: Long, currencySymbol: String = "$"): String {
        val negative = cents < 0
        val abs = if (negative) -cents else cents
        val dollars = abs / 100
        val remainder = (abs % 100).toInt()
        val grouped = groupThousands(dollars)
        val centsPart = if (remainder < 10) "0$remainder" else remainder.toString()
        val sign = if (negative) "-" else ""
        return "$sign$currencySymbol$grouped.$centsPart"
    }

    private fun groupThousands(value: Long): String {
        val digits = value.toString()
        if (digits.length <= 3) return digits
        val sb = StringBuilder()
        val firstGroup = digits.length % 3
        var idx = 0
        if (firstGroup > 0) {
            sb.append(digits, 0, firstGroup)
            idx = firstGroup
        }
        while (idx < digits.length) {
            if (sb.isNotEmpty()) sb.append(',')
            sb.append(digits, idx, idx + 3)
            idx += 3
        }
        return sb.toString()
    }

    /** Minimal shape the pipeline maths need from an opportunity (keeps the maths DTO/domain-agnostic). */
    interface PipelineOppLike {
        val stage: String?
        val amountCents: Long
        val probability: Int
    }

    /** Convenience concrete carrier for tests / callers that don't have a domain object handy. */
    data class PipelineOpp(
        override val stage: String?,
        override val amountCents: Long,
        override val probability: Int,
    ) : PipelineOppLike
}
