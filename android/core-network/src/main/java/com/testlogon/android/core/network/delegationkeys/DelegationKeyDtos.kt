package com.testlogon.android.core.network.delegationkeys

import com.squareup.moshi.Json

/**
 * Delegation-API keys transport DTOs (web parity: the /delegation-api page). These are the DELEGATED-access
 * keys (a tool acting on a creator's behalf) - DISTINCT from the personal developer keys under
 * core.network.apikeys (/ui/api_keys). Backend: app/routers/delegation_api.py, prefix /ui/delegation-api.
 *
 * CODEGEN NOTE (identical to the apikeys/syndicates pattern): core-network does NOT apply the Moshi KSP
 * codegen plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory on the shared Moshi.
 * Every wire key is pinned with an explicit @Json(name = ...); @JsonClass(generateAdapter=true) is OMITTED.
 *
 * TIME: created_at / last_used_at / expires_at are EPOCH SECONDS (Long); 0 = "never"/"no expiry" (the :app
 * mapper normalises 0 -> null). key_secret is present ONLY on create (shown once).
 */

/** One delegation API key row (GET /keys and /creator-keys). The secret is NEVER present here. */
data class DelegationApiKeyDto(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "owner_sub") val ownerSub: String? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "permissions") val permissions: List<String> = emptyList(),
    @Json(name = "preset") val preset: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "prefix") val prefix: String? = null,
    @Json(name = "rate_limit_rpm") val rateLimitRpm: Int? = null,
    @Json(name = "total_calls") val totalCalls: Int? = null,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    // Present only on the create response.
    @Json(name = "key_secret") val keySecret: String? = null,
)

/** Request body for POST /ui/delegation-api/keys. */
data class DelegationApiKeyCreateRequest(
    @Json(name = "label") val label: String,
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "permissions") val permissions: List<String>,
    @Json(name = "expires_in_days") val expiresInDays: Int? = null,
)

/**
 * One managed-creator row (GET /ui/delegates/managed) - the creators the caller delegates for, used to
 * populate the create dialog's creator selector + the per-creator allowed-permission subset.
 */
data class ManagedCreatorDto(
    @Json(name = "creator_id") val creatorId: String,
    @Json(name = "permissions") val permissions: List<String> = emptyList(),
    @Json(name = "preset") val preset: String? = null,
    @Json(name = "status") val status: String? = null,
    @Json(name = "label") val label: String? = null,
    @Json(name = "accepted_at") val acceptedAt: Long? = null,
)
