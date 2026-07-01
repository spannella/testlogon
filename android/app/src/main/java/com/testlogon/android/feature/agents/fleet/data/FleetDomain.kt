package com.testlogon.android.feature.agents.fleet.data

/** AGENTS-BASICS (web-parity) - framework-free domain for the FLEET dashboard surface. */

/** A compact worker summary shown on the fleet dashboard. */
data class FleetWorker(
    val id: String,
    val label: String,
    val agentType: String,
    val status: String,
    val agentState: String,
    val currentTicketTitle: String,
    val uptimeSeconds: Long,
    val estimatedCostCents: Long,
    val ticketsCompleted: Int,
)

/** Fleet status snapshot (GET .../status). */
data class FleetStatus(
    val totalWorkers: Int,
    val statusCounts: Map<String, Int>,
    val queueDepth: Int,
    val workers: List<FleetWorker>,
)

/** Fleet capacity (GET .../capacity). */
data class FleetCapacity(
    val queueByType: Map<String, Int>,
    val workersByType: Map<String, Int>,
    val workersByState: Map<String, Int>,
    val recommendedAction: String,
)

/** Result of a bulk start-all / stop-all. */
data class BulkActionResult(
    val count: Int,
    val errors: List<Pair<String, String>>,
)

/** One fleet worker template. */
data class WorkerTemplate(
    val id: String,
    val label: String,
    val agentType: String,
    val tool: String,
    val computeType: String,
    val instanceType: String,
    val createdAt: Long?,
)
