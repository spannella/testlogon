package com.testlogon.android.feature.agents.fleet.data

import com.testlogon.android.core.network.agents.BulkActionResultDto
import com.testlogon.android.core.network.agents.FleetCapacityDto
import com.testlogon.android.core.network.agents.FleetStatusDto
import com.testlogon.android.core.network.agents.WorkerSummaryDto
import com.testlogon.android.core.network.agents.WorkerTemplateDto

/** AGENTS-BASICS (web-parity) - DTO -> domain mappers for the FLEET surface. */

fun WorkerSummaryDto.toDomain(): FleetWorker = FleetWorker(
    id = workerId,
    label = label,
    agentType = agentType,
    status = workerStatus,
    agentState = agentState,
    currentTicketTitle = currentTicketTitle,
    uptimeSeconds = uptimeSeconds,
    estimatedCostCents = estimatedCostCents,
    ticketsCompleted = ticketsCompleted,
)

fun FleetStatusDto.toDomain(): FleetStatus = FleetStatus(
    totalWorkers = totalWorkers,
    statusCounts = statusCounts,
    queueDepth = queueDepth,
    workers = workers.map { it.toDomain() },
)

fun FleetCapacityDto.toDomain(): FleetCapacity = FleetCapacity(
    queueByType = queueByType,
    workersByType = workersByType,
    workersByState = workersByState,
    recommendedAction = recommendedAction,
)

fun BulkActionResultDto.toDomain(): BulkActionResult = BulkActionResult(
    count = count,
    errors = errors.map { it.workerId to it.error },
)

fun WorkerTemplateDto.toDomain(): WorkerTemplate = WorkerTemplate(
    id = templateId,
    label = label,
    agentType = agentType,
    tool = tool,
    computeType = computeType,
    instanceType = instanceType,
    createdAt = createdAt.takeIf { it > 0 },
)
