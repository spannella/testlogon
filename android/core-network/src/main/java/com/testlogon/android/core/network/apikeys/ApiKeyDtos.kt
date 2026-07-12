package com.testlogon.android.core.network.apikeys

import com.squareup.moshi.Json

/**
 * B-APIKEY (batch 7) - transport DTOs for the API-keys management surface (developer API keys).
 *
 * CODEGEN NOTE (identical to the AND-398 WebhookDtos pattern): core-network does NOT apply the Moshi KSP codegen
 * plugin, so these DTOs decode via the reflective KotlinJsonAdapterFactory registered on the shared Moshi in
 * NetworkModule.provideMoshi. The reflective factory maps Kotlin property names to JSON keys VERBATIM (Moshi does
 * NOT auto snake_case), so every wire key is pinned with an explicit @Json(name = ...).
 * @JsonClass(generateAdapter = true) is intentionally OMITTED.
 *
 * WIRE CONTRACT (verified live against prod app/routers/api_keys.py + app/services/api_keys.py; relative paths,
 * NO leading slash):
 *   GET  ui/api_keys          -> { "keys": [ ApiKeyDto ] } (NAMED envelope; revoked keys are filtered server-side)
 *   POST ui/api_keys          -> CreateApiKeyResultDto (the created key WITH the one-time `key_secret`).
 *                                Body = CreateApiKeyRequest. NOTE: gated by require_fresh_mfa -> a 401
 *                                "Fresh MFA required" is possible when the caller has MFA factors configured.
 *   POST ui/api_keys/revoke   -> { "ok": true }. Body = RevokeApiKeyRequest. Also gated by require_fresh_mfa.
 *
 * TIME: `created_at` / `expires_at` / `last_used_at` are EPOCH SECONDS typed as Long (NOT ISO-8601). `expires_at`
 * == 0 means "no expiry" (the :app mapper treats 0 as null). The :app mapper formats at the UI.
 *
 * SECRET: `key_secret` is returned ONLY on create (shown once); it is NEVER present on the list. The full secret
 * is `ak_<key_id>.<secret>`; the list rows carry only a `prefix` (e.g. `ak_<first8>`) for display.
 */

/** One API key as returned in the GET ui/api_keys list (the secret is NEVER present here - only on create). */
data class ApiKeyDto(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "capabilities") val capabilities: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "last_used_at") val lastUsedAt: Long? = null,
    @Json(name = "expires_at") val expiresAt: Long? = null,
    @Json(name = "prefix") val prefix: String? = null,
    @Json(name = "revoked") val revoked: Boolean = false,
    // Batch 8 (#18): the list endpoint also carries each key's IP allow/deny rules (CIDRs).
    @Json(name = "allow_cidrs") val allowCidrs: List<String> = emptyList(),
    @Json(name = "deny_cidrs") val denyCidrs: List<String> = emptyList(),
)

/** Envelope for GET ui/api_keys (the body is {"keys": [...]}). */
data class ApiKeysListDto(
    @Json(name = "keys") val keys: List<ApiKeyDto> = emptyList(),
)

/**
 * Result of POST ui/api_keys. Carries the ONE-TIME `key_secret` (the full `ak_<key_id>.<secret>` value, shown
 * once and never retrievable again) plus the persisted metadata.
 */
data class CreateApiKeyResultDto(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "key_secret") val keySecret: String,
    @Json(name = "label") val label: String? = null,
    @Json(name = "capabilities") val capabilities: List<String> = emptyList(),
    @Json(name = "created_at") val createdAt: Long? = null,
    @Json(name = "expires_at") val expiresAt: Long? = null,
)

/**
 * Request body for POST ui/api_keys. `label` is a free-text name (server truncates to 64 chars); `capabilities`
 * is the product-scope list (defaults to empty -> the backend applies the default scope set);
 * `expires_in_days` is optional (absent -> no expiry).
 */
data class CreateApiKeyRequest(
    @Json(name = "label") val label: String,
    @Json(name = "capabilities") val capabilities: List<String> = emptyList(),
    @Json(name = "expires_in_days") val expiresInDays: Int? = null,
)

/** Request body for POST ui/api_keys/revoke. */
data class RevokeApiKeyRequest(
    @Json(name = "key_id") val keyId: String,
)

/**
 * Batch 8 (#17): request body for PATCH ui/api_keys/{key_id}/scopes (also accepts a `scopes` alias server-side).
 * Replaces the full capability set for the key (require_fresh_mfa gated).
 */
data class SetScopesRequest(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "capabilities") val capabilities: List<String> = emptyList(),
)

/** Response of the scopes set/patch: { ok, capabilities, ... }. */
data class SetScopesResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "capabilities") val capabilities: List<String> = emptyList(),
)

/**
 * Batch 8 (#18): request body for POST ui/api_keys/ip_rules. SET/REPLACE semantics - the lists fully replace
 * the key's current allow/deny CIDRs (require_fresh_mfa gated).
 */
data class SetIpRulesRequest(
    @Json(name = "key_id") val keyId: String,
    @Json(name = "allow_cidrs") val allowCidrs: List<String> = emptyList(),
    @Json(name = "deny_cidrs") val denyCidrs: List<String> = emptyList(),
)

/** Response of POST ui/api_keys/ip_rules: { ok, allow_cidrs, deny_cidrs }. */
data class SetIpRulesResultDto(
    @Json(name = "ok") val ok: Boolean = false,
    @Json(name = "allow_cidrs") val allowCidrs: List<String> = emptyList(),
    @Json(name = "deny_cidrs") val denyCidrs: List<String> = emptyList(),
)
