package com.testlogon.android.feature.apikeys.data

/**
 * B-APIKEY (batch 7) - framework-free domain models for the API-keys management surface.
 *
 * Times are EPOCH SECONDS (the backend's epoch Longs); the UI formats them. [expiresAt] == null means "no
 * expiry" (the mapper maps the wire 0 -> null). The kept in feature/data (NOT core-model) because core-model
 * cannot depend on core-network; mirrors the AND-264 referrals domain pattern.
 */

/** One API key as shown in the list. The secret is NEVER part of this model (only on create). */
data class ApiKey(
    val id: String,
    val label: String,
    val capabilities: List<String>,
    val createdAt: Long?,
    val lastUsedAt: Long?,
    val expiresAt: Long?,
    val prefix: String,
    // Batch 8 (#18): per-key IP allow/deny CIDR rules (from the list endpoint).
    val allowCidrs: List<String> = emptyList(),
    val denyCidrs: List<String> = emptyList(),
)

/**
 * The result of creating an API key. [secret] is the ONE-TIME full secret (`ak_<id>.<...>`), shown once and
 * never retrievable again - it is surfaced inline by the create screen and never persisted / logged.
 */
data class CreatedApiKey(
    val id: String,
    val label: String,
    val secret: String,
    val capabilities: List<String>,
    val createdAt: Long?,
    val expiresAt: Long?,
)
