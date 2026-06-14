package com.testlogon.android.core.testing.helpdesk

import com.testlogon.android.core.model.helpdesk.AgentAvailabilityState
import com.testlogon.android.core.model.helpdesk.Availability
import com.testlogon.android.core.model.helpdesk.HelpdeskMetrics

/**
 * AND-381 - SHARED, dependency-light domain fixtures for the Helpdesk feature (epic E49: agent
 * dashboard / claim-assignment / availability / helpdesk ViewModel, AND-377..380) test suites.
 *
 * SCOPE (obey the core-testing dependency rule): core-testing depends on core-MODEL ONLY, so
 * EVERYTHING here references ONLY core-model helpdesk domain types - the AND-377 [HelpdeskMetrics]
 * and the AND-379 [Availability] / [AgentAvailabilityState]. The helpdesk QUEUE/CLAIM domain types
 * ([HelpdeskQueueItem], [HelpdeskClaimResult], [ClaimState], ...) and the network DTOs
 * ([HelpdeskClaimOutDto], [ConversationDto]) live in the :app data layer, NOT core-model, so they
 * CANNOT be referenced here; a fixture needing one of those lives in :app's own test source. These
 * are PURE in-memory domain builders, not JSON.
 *
 * WHY (anti-duplication, spec AC-11 / FR-5): the E49 suites each hand-roll a tiny throwaway
 * [HelpdeskMetrics] builder (e.g. HelpdeskDashboardViewModelTest's private metrics()). This
 * consolidates one realistic, reusable set covering the shapes the suites care about: a populated
 * metrics snapshot, the all-zero EMPTY snapshot the dashboard treats specially ([HelpdeskMetrics.isEmpty]),
 * a snapshot carrying the optional time/throughput metrics AND per-metric [HelpdeskMetrics.deltas]
 * (including a forward-compat UNKNOWN delta key the mapper must tolerate, FR-2), plus the availability
 * roster (ONLINE / AWAY + their heartbeat-status vocabulary). It is ADDITIVE - it does NOT replace the
 * narrow per-test builders any suite already uses.
 *
 * NOTE: KDoc here deliberately avoids the comment-terminator character pair.
 */
object HelpdeskFixtures {

    /** Stable epoch-SECONDS timestamp used by the metrics fixtures (deterministic). */
    const val GENERATED_AT_EPOCH_SECONDS = 1_749_132_069L

    /** Stable conversation ids referenced across helpdesk suites. */
    const val CONVERSATION_ID = "cnv_fixture_1"
    const val SELF_USER_ID = "usr_self"
    const val OTHER_USER_ID = "usr_other"

    /**
     * A populated dashboard metrics snapshot (the four count metrics non-zero, the optional
     * time/throughput metrics left null - matching the realistic Q1 client-derivation path where there
     * is NO server metrics endpoint, spec section 5/16, so those have no client source).
     */
    fun metrics(
        open: Int = 5,
        unassigned: Int = 2,
        assignedToMe: Int = 1,
        sla: Int = 1,
        avgFirstResponseSeconds: Long? = null,
        avgResolutionSeconds: Long? = null,
        resolvedByMeToday: Int? = null,
        deltas: Map<String, Int> = emptyMap(),
        generatedAtEpochSeconds: Long = GENERATED_AT_EPOCH_SECONDS,
    ): HelpdeskMetrics = HelpdeskMetrics(
        openCount = open,
        unassignedCount = unassigned,
        assignedToMeCount = assignedToMe,
        slaAtRiskCount = sla,
        avgFirstResponseSeconds = avgFirstResponseSeconds,
        avgResolutionSeconds = avgResolutionSeconds,
        resolvedByMeToday = resolvedByMeToday,
        deltas = deltas,
        generatedAtEpochSeconds = generatedAtEpochSeconds,
    )

    /**
     * The all-zero EMPTY snapshot a fresh agent sees: every count zero and every optional metric
     * absent, so [HelpdeskMetrics.isEmpty] is true and the dashboard renders its empty state rather
     * than an all-zero grid.
     */
    fun emptyMetrics(): HelpdeskMetrics = metrics(
        open = 0,
        unassigned = 0,
        assignedToMe = 0,
        sla = 0,
        avgFirstResponseSeconds = null,
        avgResolutionSeconds = null,
        resolvedByMeToday = null,
        deltas = emptyMap(),
    )

    /**
     * A "rich" snapshot exercising the OPTIONAL fields a real server-backed metrics source would
     * carry: non-null avg first-response / resolution durations, a non-null resolved-by-me-today
     * throughput, and a [HelpdeskMetrics.deltas] map that mixes known per-metric keys WITH a
     * forward-compat UNKNOWN key (FR-2: the consumer must tolerate extra delta keys, never throw).
     */
    fun metricsWithTimeAndDeltas(): HelpdeskMetrics = metrics(
        open = 42,
        unassigned = 9,
        assignedToMe = 4,
        sla = 3,
        avgFirstResponseSeconds = 540L,
        avgResolutionSeconds = 7_200L,
        resolvedByMeToday = 11,
        deltas = mapOf(
            "open" to -4,
            "unassigned" to 2,
            "assigned_to_me" to 1,
            // forward-compat: an unrecognized delta key the consumer must tolerate (FR-2).
            "teleporting_metric" to 99,
        ),
    )

    /** Both availability values for parameterised gating tests (ONLINE first = eligible to claim). */
    fun availabilityRoster(): List<Availability> = listOf(Availability.ONLINE, Availability.AWAY)

    /** A diagnostic availability-state snapshot (defaults to AWAY = ineligible, matching production). */
    fun availabilityState(
        availability: Availability = Availability.AWAY,
        lastChangedAt: Long = 0L,
        pushPending: Boolean = false,
    ): AgentAvailabilityState = AgentAvailabilityState(
        availability = availability,
        lastChangedAt = lastChangedAt,
        pushPending = pushPending,
    )
}
