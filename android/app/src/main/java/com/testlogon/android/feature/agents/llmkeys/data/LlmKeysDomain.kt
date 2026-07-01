package com.testlogon.android.feature.agents.llmkeys.data

/**
 * AGENTS-BASICS (web-parity) - framework-free domain for the LLM provider KEYS surface. Kept in feature/data.
 * Times are EPOCH SECONDS (0 -> null via the mapper). The plaintext api_key is NEVER modelled (never returned).
 */

/** One LLM provider key. */
data class LlmKey(
    val id: String,
    val provider: String,
    val label: String,
    val keySuffix: String,
    val baseUrl: String,
    val modelPreference: String,
    val availableModels: List<String>,
    val rateLimitRpm: Int,
    val monthlyBudgetCents: Int,
    val currentMonthUsageCents: Int,
    val totalRequests: Long,
    val status: String,
    val lastTestedAt: Long?,
    val lastUsedAt: Long?,
    val createdAt: Long?,
    val assignedWorkerIds: List<String>,
)

/** Result of a key test. */
data class LlmKeyTestResult(
    val ok: Boolean,
    val models: List<String>,
    val error: String,
    val latencyMs: Long,
)

/** A provider descriptor for the create form's provider picker. */
data class LlmProvider(
    val provider: String,
    val displayName: String,
    val baseUrl: String,
    val models: List<String>,
)
