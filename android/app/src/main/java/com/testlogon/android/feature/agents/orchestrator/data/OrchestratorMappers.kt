package com.testlogon.android.feature.agents.orchestrator.data

import com.testlogon.android.core.network.agents.AgentStatusDto
import com.testlogon.android.core.network.agents.CompleteTicketResultDto
import com.testlogon.android.core.network.agents.EligibleTicketDto
import com.testlogon.android.core.network.agents.EligibleTicketsDto
import com.testlogon.android.core.network.agents.HeartbeatResultDto
import com.testlogon.android.core.network.agents.LoopActionResultDto
import com.testlogon.android.core.network.agents.ReleaseTicketResultDto
import com.testlogon.android.core.network.agents.TicketFilterConfigDto

/** AGENT-ORCHESTRATOR (web-parity) - DTO <-> domain mappers for the ORCHESTRATOR surface. */

fun TicketFilterConfigDto?.toDomain(): TicketFilter =
    if (this == null) TicketFilter()
    else TicketFilter(types = types, tags = tags, spaceIds = spaceIds, priorities = priorities)

fun TicketFilter.toDto(): TicketFilterConfigDto =
    TicketFilterConfigDto(types = types, tags = tags, spaceIds = spaceIds, priorities = priorities)

fun AgentStatusDto.toDomain(): AgentStatus = AgentStatus(
    workerId = workerId,
    state = AgentLoopState.from(agentState),
    currentTicketId = currentTicketId,
    currentTicketTitle = currentTicketTitle,
    ticketsCompleted = ticketsCompleted,
    ticketsFailed = ticketsFailed,
    heartbeatAt = heartbeatAt,
    lastActivityAt = lastActivityAt,
    ticketFilter = ticketFilter.toDomain(),
    loopRunning = loopRunning,
)

fun LoopActionResultDto.toDomain(): LoopActionResult = LoopActionResult(
    ok = ok,
    workerId = workerId,
    agentState = AgentLoopState.from(agentState),
    message = message,
)

fun ReleaseTicketResultDto.toDomain(): TicketOpResult = TicketOpResult(
    ok = ok,
    workerId = workerId,
    ticketId = releasedTicketId,
    agentState = AgentLoopState.from(agentState),
)

fun CompleteTicketResultDto.toDomain(): TicketOpResult = TicketOpResult(
    ok = ok,
    workerId = workerId,
    ticketId = completedTicketId,
    agentState = AgentLoopState.from(agentState),
)

fun HeartbeatResultDto.toDomain(): HeartbeatResult = HeartbeatResult(ok = ok, heartbeatAt = heartbeatAt)

fun EligibleTicketDto.toDomain(): EligibleTicket = EligibleTicket(
    ticketId = ticketId,
    title = title,
    priority = priority,
    type = type,
    tags = tags,
    spaceId = spaceId,
    createdAt = createdAt,
)

fun EligibleTicketsDto.toDomain(): EligibleTickets = EligibleTickets(
    tickets = tickets.map { it.toDomain() },
    count = count,
    filterApplied = filterApplied?.toDomain(),
)
