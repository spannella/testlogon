package com.testlogon.android.feature.agents.llmkeys.data

import com.testlogon.android.core.network.agents.LlmKeyDto
import com.testlogon.android.core.network.agents.LlmKeyTestDto
import com.testlogon.android.core.network.agents.LlmProviderInfoDto

/** AGENTS-BASICS (web-parity) - DTO -> domain mappers for the LLM keys surface (epoch-0 -> null). */

fun LlmKeyDto.toDomain(): LlmKey = LlmKey(
    id = keyId,
    provider = provider,
    label = label,
    keySuffix = keySuffix,
    baseUrl = baseUrl,
    modelPreference = modelPreference,
    availableModels = availableModels,
    rateLimitRpm = rateLimitRpm,
    monthlyBudgetCents = monthlyBudgetCents,
    currentMonthUsageCents = currentMonthUsageCents,
    totalRequests = totalRequests,
    status = status,
    lastTestedAt = lastTestedAt.takeIf { it > 0 },
    lastUsedAt = lastUsedAt.takeIf { it > 0 },
    createdAt = createdAt.takeIf { it > 0 },
    assignedWorkerIds = assignedWorkerIds,
)

fun LlmKeyTestDto.toDomain(): LlmKeyTestResult = LlmKeyTestResult(
    ok = ok,
    models = models,
    error = error,
    latencyMs = latencyMs,
)

fun LlmProviderInfoDto.toDomain(): LlmProvider = LlmProvider(
    provider = provider,
    displayName = displayName.ifBlank { provider },
    baseUrl = baseUrl,
    models = models,
)
