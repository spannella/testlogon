package com.testlogon.android.data.crm

/**
 * CRM-AND-OPP — PURE, framework-free logic for the sales FORECAST + QUOTA surface (OPP-005/006). No
 * Android / java.time types, so every function here is JVM-unit-testable (mirrors the [CrmSalesMath]
 * idiom). Complements [CrmSalesMath] (which owns stage classification + per-opp weighting); this file
 * owns the forecast-worksheet roll-ups (committed / best-case / pipeline / gap-to-quota) and the
 * quota-attainment percentage.
 *
 * Degrade, never throw: null / malformed / negative inputs are treated as zero rather than raising, so
 * a 404 (module disabled) or dev-host drift renders cleanly.
 */
object ForecastMath {

    /**
     * Quota-attainment as a WHOLE percentage of [closedCents] against [quotaCents], rounded half-up.
     *
     * A non-positive quota degrades to 0 (nothing to attain against — avoids divide-by-zero). Negative
     * closed degrades to 0. The result is NOT capped at 100 (a rep can exceed quota, which the UI shows).
     */
    fun attainmentPct(closedCents: Long, quotaCents: Long): Int {
        if (quotaCents <= 0L) return 0
        val closed = maxOf(0L, closedCents)
        return ((closed.toDouble() / quotaCents.toDouble()) * 100.0 + 0.5).toInt()
    }

    /**
     * Remaining amount to reach quota: max(0, quota - closed). Zero once quota is met or exceeded, and
     * zero for a non-positive quota (nothing to close).
     */
    fun gapToQuotaCents(closedCents: Long, quotaCents: Long): Long {
        if (quotaCents <= 0L) return 0L
        val closed = maxOf(0L, closedCents)
        return maxOf(0L, quotaCents - closed)
    }

    /**
     * Coverage ratio: how many multiples of the remaining quota gap the open pipeline covers, as a whole
     * percentage. E.g. gap $10k, pipeline $30k -> 300%. Zero gap (quota met) -> 0 (nothing to cover).
     * Non-positive quota -> 0.
     */
    fun pipelineCoveragePct(pipelineCents: Long, closedCents: Long, quotaCents: Long): Int {
        val gap = gapToQuotaCents(closedCents, quotaCents)
        if (gap <= 0L) return 0
        val pipeline = maxOf(0L, pipelineCents)
        return ((pipeline.toDouble() / gap.toDouble()) * 100.0 + 0.5).toInt()
    }

    /**
     * A derived forecast roll-up combining a worksheet's rep-entered figures with the closed / quota
     * figures the server computes. Everything is clamped non-negative.
     */
    data class ForecastRollup(
        val committedCents: Long,
        val bestCaseCents: Long,
        val pipelineCents: Long,
        val closedCents: Long,
        val quotaCents: Long,
    ) {
        /** Committed + already-closed — the "call number" a rep would commit to. */
        val commitTotalCents: Long get() = committedCents + closedCents

        /** Best-case + already-closed — the optimistic ceiling. */
        val bestCaseTotalCents: Long get() = bestCaseCents + closedCents

        val attainmentPct: Int get() = attainmentPct(closedCents, quotaCents)
        val gapToQuotaCents: Long get() = gapToQuotaCents(closedCents, quotaCents)
        val pipelineCoveragePct: Int get() = pipelineCoveragePct(pipelineCents, closedCents, quotaCents)

        /** True once the committed forecast (closed + committed) reaches quota. */
        val committedMeetsQuota: Boolean get() = quotaCents > 0L && commitTotalCents >= quotaCents
    }

    /** Build a [ForecastRollup], clamping every input non-negative (degrade on bad server drift). */
    fun rollup(
        committedCents: Long,
        bestCaseCents: Long,
        pipelineCents: Long,
        closedCents: Long,
        quotaCents: Long,
    ): ForecastRollup = ForecastRollup(
        committedCents = maxOf(0L, committedCents),
        bestCaseCents = maxOf(0L, bestCaseCents),
        pipelineCents = maxOf(0L, pipelineCents),
        closedCents = maxOf(0L, closedCents),
        quotaCents = maxOf(0L, quotaCents),
    )

    // ── Pipeline-report roll-ups (OPP-006) ──────────────────────────────────

    /** Minimal shape the report maths need from one stage row (keeps the maths DTO/domain-agnostic). */
    interface StageMetricLike {
        val stage: String?
        val count: Int
        val totalAmountCents: Long
        val weightedAmountCents: Long
    }

    /** Sum of un-weighted amount across OPEN stages only (closed_won / closed_lost excluded). */
    fun openTotalAmountCents(rows: List<StageMetricLike>): Long =
        rows.asSequence()
            .filter { CrmSalesMath.isOpenStage(it.stage) }
            .sumOf { maxOf(0L, it.totalAmountCents) }

    /** Sum of weighted amount across OPEN stages only. */
    fun openWeightedAmountCents(rows: List<StageMetricLike>): Long =
        rows.asSequence()
            .filter { CrmSalesMath.isOpenStage(it.stage) }
            .sumOf { maxOf(0L, it.weightedAmountCents) }

    /** Total realised (closed_won) amount across the report rows. */
    fun wonAmountCents(rows: List<StageMetricLike>): Long =
        rows.asSequence()
            .filter { CrmSalesMath.isWonStage(it.stage) }
            .sumOf { maxOf(0L, it.totalAmountCents) }

    /** Total open-opportunity COUNT across the report rows. */
    fun openCount(rows: List<StageMetricLike>): Int =
        rows.asSequence()
            .filter { CrmSalesMath.isOpenStage(it.stage) }
            .sumOf { maxOf(0, it.count) }

    /**
     * Funnel conversion for one stage as a whole percentage of the TOTAL open+won count that has reached
     * at least this stage. Simplistic (share of pipeline by count) — enough for a bar-width in the UI.
     * Zero total -> 0.
     */
    fun stageSharePct(stageCount: Int, totalCount: Int): Int {
        if (totalCount <= 0) return 0
        val c = maxOf(0, stageCount)
        return ((c.toDouble() / totalCount.toDouble()) * 100.0 + 0.5).toInt()
    }
}
