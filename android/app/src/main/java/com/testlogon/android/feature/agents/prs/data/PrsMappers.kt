package com.testlogon.android.feature.agents.prs.data

import com.testlogon.android.core.network.agents.AgentPrDto

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
