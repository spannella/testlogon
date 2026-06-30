package com.testlogon.android.feature.delegationkeys.data

/**
 * Framework-free domain models for the delegation-API keys surface (web parity: /delegation-api).
 * Kept in feature/data (NOT core-model) because core-model cannot depend on core-network. Times are EPOCH
 * SECONDS; null means "never" / "no expiry" (the mapper maps the wire 0 -> null).
 */

/** One delegation API key as shown in a list. The secret is NEVER part of this model (only on create). */
data class DelegationApiKey(
    val keyId: String,
    val label: String,
    val creatorId: String,
    val permissions: List<String>,
    val status: String,
    val prefix: String,
    val rateLimitRpm: Int,
    val totalCalls: Int,
    val createdAt: Long?,
    val lastUsedAt: Long?,
    val expiresAt: Long?,
)

/**
 * The result of creating a delegation API key. [secret] is the ONE-TIME full secret, shown once and never
 * retrievable - surfaced inline by the screen and never persisted / logged.
 */
data class CreatedDelegationApiKey(
    val key: DelegationApiKey,
    val secret: String?,
)

/** One creator the caller delegates for (populates the create dialog + per-creator permission subset). */
data class ManagedCreator(
    val creatorId: String,
    val label: String,
    val permissions: List<String>,
    val status: String,
)
