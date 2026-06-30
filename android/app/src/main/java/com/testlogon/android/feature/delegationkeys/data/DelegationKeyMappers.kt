package com.testlogon.android.feature.delegationkeys.data

import com.testlogon.android.core.network.delegationkeys.DelegationApiKeyDto
import com.testlogon.android.core.network.delegationkeys.ManagedCreatorDto

/**
 * DTO -> domain mappers for the delegation-API keys surface. Live in :app (NOT core-model) because
 * core-model cannot depend on core-network. The 0 epoch sentinel ("never" / "no expiry") maps to null.
 */

fun DelegationApiKeyDto.toDomain(): DelegationApiKey = DelegationApiKey(
    keyId = keyId,
    label = label.orEmpty(),
    creatorId = creatorId.orEmpty(),
    permissions = permissions,
    status = status?.takeIf { it.isNotBlank() } ?: "active",
    prefix = prefix.orEmpty(),
    rateLimitRpm = rateLimitRpm ?: 0,
    totalCalls = totalCalls ?: 0,
    createdAt = createdAt?.takeIf { it > 0 },
    lastUsedAt = lastUsedAt?.takeIf { it > 0 },
    expiresAt = expiresAt?.takeIf { it > 0 },
)

fun DelegationApiKeyDto.toCreated(): CreatedDelegationApiKey = CreatedDelegationApiKey(
    key = toDomain(),
    secret = keySecret?.takeIf { it.isNotBlank() },
)

fun ManagedCreatorDto.toDomain(): ManagedCreator = ManagedCreator(
    creatorId = creatorId,
    label = label?.takeIf { it.isNotBlank() } ?: creatorId,
    permissions = permissions,
    status = status.orEmpty(),
)
