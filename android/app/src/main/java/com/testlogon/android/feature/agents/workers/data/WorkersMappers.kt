package com.testlogon.android.feature.agents.workers.data

import com.testlogon.android.core.network.agents.ComputeOptionDto
import com.testlogon.android.core.network.agents.ProvisionStepDto
import com.testlogon.android.core.network.agents.ToolInfoDto
import com.testlogon.android.core.network.agents.WorkerDto

/**
 * AGENTS-BASICS (web-parity) - DTO -> domain mappers for the WORKERS surface (in :app; core-model cannot depend
 * on core-network). Epoch-0 sentinels map to null.
 */

fun ProvisionStepDto.toDomain(): ProvisionStep = ProvisionStep(
    step = step,
    status = status,
    ts = ts.takeIf { it > 0 },
    detail = detail,
)

fun WorkerDto.toDomain(): Worker = Worker(
    id = workerId,
    label = label,
    agentType = agentType,
    tool = tool,
    toolVersion = toolVersion,
    computeType = computeType,
    instanceType = instanceType,
    llmKeyId = llmKeyId,
    llmProvider = llmProvider,
    publicIp = publicIp,
    status = WorkerStatus.from(workerStatus),
    statusWire = workerStatus,
    repoUrl = repoUrl,
    branchConvention = branchConvention,
    idleTimeoutSeconds = idleTimeoutSeconds,
    lastActivityAt = lastActivityAt.takeIf { it > 0 },
    createdAt = createdAt.takeIf { it > 0 },
    startedAt = startedAt.takeIf { it > 0 },
    errorMessage = errorMessage,
    provisionLog = provisionLog.map { it.toDomain() },
)

fun ToolInfoDto.toDomain(): ToolInfo = ToolInfo(
    tool = tool,
    displayName = displayName.ifBlank { tool },
    description = description,
    requiredProvider = requiredProvider,
)

fun ComputeOptionDto.toDomain(): ComputeOption = ComputeOption(
    computeType = computeType,
    instanceType = instanceType,
    vcpu = vcpu,
    memoryGb = memoryGb,
    costCentsPerMin = costCentsPerMin,
)
