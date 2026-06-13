package com.testlogon.android.core.model.helpdesk

/**
 * AND-377 — domain model for the helpdesk agent dashboard metrics.
 *
 * JVM-pure (no android.* / java.time API-26): timestamps are epoch-SECONDS Longs (matching the
 * helpdesk queue domain), formatted at render time. The four count metrics are always present (they
 * are derived client-side from the helpdesk queue — see §5 critical correction: there is NO server
 * helpdesk-metrics endpoint, so the Q1 queue-derivation path is the realistic primary source). The
 * time-based and throughput metrics have no client source and stay null (rendered as a dash).
 *
 * @param openCount             open conversations (not closed).
 * @param unassignedCount       conversations with no active agent.
 * @param assignedToMeCount     conversations whose active agent is the current user.
 * @param slaAtRiskCount        conversations flagged at-risk (awaiting-agent, unassigned).
 * @param avgFirstResponseSeconds avg first-response duration; null when no client source.
 * @param avgResolutionSeconds  avg resolution duration; null when no client source.
 * @param resolvedByMeToday     agent throughput today; null when no client source.
 * @param deltas                optional per-metric delta vs. the previous period (empty in Q1 mode).
 * @param generatedAtEpochSeconds when these metrics were computed (epoch seconds).
 */
data class HelpdeskMetrics(
    val openCount: Int,
    val unassignedCount: Int,
    val assignedToMeCount: Int,
    val slaAtRiskCount: Int,
    val avgFirstResponseSeconds: Long? = null,
    val avgResolutionSeconds: Long? = null,
    val resolvedByMeToday: Int? = null,
    val deltas: Map<String, Int> = emptyMap(),
    val generatedAtEpochSeconds: Long,
) {
    /**
     * True when every count is zero and there is no time/throughput data — the dashboard treats this
     * as an [empty] state rather than rendering an all-zero grid for a fresh agent.
     */
    val isEmpty: Boolean
        get() = openCount == 0 &&
            unassignedCount == 0 &&
            assignedToMeCount == 0 &&
            slaAtRiskCount == 0 &&
            avgFirstResponseSeconds == null &&
            avgResolutionSeconds == null &&
            (resolvedByMeToday == null || resolvedByMeToday == 0)
}
