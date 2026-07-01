package com.testlogon.android.feature.agents.memory.data

import com.testlogon.android.core.network.agents.AgentIdentityDto
import com.testlogon.android.core.network.agents.MemoryEntryDto
import com.testlogon.android.core.network.agents.ProjectContextDto

/** AGENTS-BASICS (web-parity) - DTO -> domain mappers for the MEMORY surface. Epoch-0 sentinels map to null. */

fun AgentIdentityDto.toDomain(): AgentIdentity = AgentIdentity(
    agentType = agentType,
    identityText = identityText,
    customInstructions = customInstructions,
    updatedAt = updatedAt.takeIf { it > 0 },
)

fun ProjectContextDto.toDomain(): ProjectContext = ProjectContext(
    repoUrl = repoUrl,
    branchConvention = branchConvention,
    codingStandards = codingStandards,
    prTemplate = prTemplate,
    testFramework = testFramework,
    ciCommands = ciCommands,
    fileStructureNotes = fileStructureNotes,
    updatedAt = updatedAt.takeIf { it > 0 },
)

fun MemoryEntryDto.toDomain(): MemoryEntry = MemoryEntry(
    memoryId = memoryId,
    category = category,
    title = title,
    content = content,
    ticketId = ticketId,
    importance = importance,
    tokenCount = tokenCount,
    createdAt = createdAt.takeIf { it > 0 },
    summarized = summarized,
    summary = summary,
)
