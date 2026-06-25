package com.testlogon.android.feature.apikeys.data

import com.testlogon.android.core.network.apikeys.ApiKeyDto
import com.testlogon.android.core.network.apikeys.CreateApiKeyResultDto

/**
 * B-APIKEY (batch 7) - DTO -> domain mappers for the API-keys surface. They live in :app (NOT core-model)
 * because core-model cannot depend on core-network. Mirrors the AND-398 WebhookMappers pattern.
 *
 * `expires_at` == 0 (the backend's "no expiry" sentinel) maps to null. `last_used_at` == 0 ("never used") maps
 * to null. The label defaults to "" when absent.
 */

/** Maps a wire [ApiKeyDto] to the domain [ApiKey] (0-sentinels normalised to null). */
fun ApiKeyDto.toDomain(): ApiKey = ApiKey(
    id = keyId,
    label = label.orEmpty(),
    capabilities = capabilities,
    createdAt = createdAt?.takeIf { it > 0 },
    lastUsedAt = lastUsedAt?.takeIf { it > 0 },
    expiresAt = expiresAt?.takeIf { it > 0 },
    prefix = prefix.orEmpty(),
)

/** Maps the create-result DTO to the domain [CreatedApiKey] (carries the one-time secret). */
fun CreateApiKeyResultDto.toDomain(): CreatedApiKey = CreatedApiKey(
    id = keyId,
    label = label.orEmpty(),
    secret = keySecret,
    capabilities = capabilities,
    createdAt = createdAt?.takeIf { it > 0 },
    expiresAt = expiresAt?.takeIf { it > 0 },
)
