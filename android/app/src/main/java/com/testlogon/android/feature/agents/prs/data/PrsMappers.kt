package com.testlogon.android.feature.agents.prs.data

import com.testlogon.android.core.network.agents.AgentCompletionDto
import com.testlogon.android.core.network.agents.AgentPrDto
import com.testlogon.android.core.network.agents.WorkSummaryDto

/** AGENTS-BASICS (web-parity) - DTO -> domain mapper for the agent-PR surface. Epoch-0 sentinels map to null. */
fun AgentPrDto.toDomain(): AgentPr = AgentPr(
    prId = prId,
    workerId = workerId,
    ticketId = ticketId,
    repoUrl = repoUrl,
    prUrl = prUrl,
    prNumber = prNumber,
    branch = branch,
    title = title,
    description = description,
    filesChanged = filesChanged,
    commitCount = commitCount,
    status = AgentPrStatus.from(status),
    statusWire = status,
    createdAt = createdAt.takeIf { it > 0 },
    mergedAt = mergedAt.takeIf { it > 0 },
)

/** DTO -> domain mapper for the agent work-summary. */
fun WorkSummaryDto.toDomain(): WorkSummary = WorkSummary(
    ticketId = ticketId,
    text = text,
    filesChanged = filesChanged,
    decisions = decisions,
    testResults = testResults.entries.map { it.key to it.value },
)

/** DTO -> domain mapper for a work-completion result. A null PR maps to null. */
fun AgentCompletionDto.toDomain(): AgentCompletion = AgentCompletion(
    ticketId = ticketId,
    summary = summary.toDomain(),
    pr = pr?.toDomain(),
    newStatus = newStatus,
    nextAgentType = nextAgentType,
)
