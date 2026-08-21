package com.testlogon.android.feature.apikeys.data

import com.testlogon.android.core.network.apikeys.ApiKeyDto
import com.testlogon.android.core.network.apikeys.CreateApiKeyResultDto
import com.testlogon.android.core.network.apikeys.GatewayEndpointsDto
import com.testlogon.android.core.network.apikeys.KeyProtocolsDto
import com.testlogon.android.core.network.apikeys.ProtocolCredentialsDto

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
    allowCidrs = allowCidrs,
    denyCidrs = denyCidrs,
)

/** Maps the create-result DTO to the domain [CreatedApiKey] (carries the one-time secret). */
fun CreateApiKeyResultDto.toDomain(): CreatedApiKey = CreatedApiKey(
    id = keyId,
    label = label.orEmpty(),
    secret = keySecret,
    capabilities = capabilities,
    createdAt = createdAt?.takeIf { it > 0 },
    expiresAt = expiresAt?.takeIf { it > 0 },
    protocolCredentials = protocolCredentials?.toDomain(),
)

/** Maps the one-time `protocol_credentials` block to domain (blank fields normalised to null). */
fun ProtocolCredentialsDto.toDomain(): ProtocolCredentials = ProtocolCredentials(
    wsToken = ws?.wsToken?.takeIf { it.isNotBlank() },
    fixUsername = fix?.username?.takeIf { it.isNotBlank() },
    fixPassword = fix?.password?.takeIf { it.isNotBlank() },
    binaryApiKey = binary?.apiKey?.takeIf { it.isNotBlank() },
    binarySecret = binary?.secret?.takeIf { it.isNotBlank() },
)

/** Maps GET me/gateway/endpoints -> domain (absent sections default to disabled/empty). */
fun GatewayEndpointsDto.toDomain(): GatewayEndpoints = GatewayEndpoints(
    wsUrl = ws?.url.orEmpty(),
    wsEnabled = ws?.enabled ?: false,
    fixHost = fix?.host.orEmpty(),
    fixPort = fix?.port,
    fixRunning = fix?.running ?: false,
    binaryEndpoint = binary?.endpoint.orEmpty(),
    binaryEnabled = binary?.enabled ?: false,
)

/** Maps GET ui/api_keys/{id}/protocols -> domain (a null section = that protocol is not enabled for the key). */
fun KeyProtocolsDto.toDomain(): KeyProtocols = KeyProtocols(
    rest = rest?.let { RestProtocolInfo(baseUrl = it.baseUrl, scopes = it.scopes) },
    ws = ws?.let { WsProtocolInfo(url = it.url, subs = it.subs, tokenSet = it.tokenSet) },
    fix = fix?.let {
        FixProtocolInfo(
            senderCompId = it.senderCompId,
            targetCompId = it.targetCompId,
            host = it.host,
            port = it.port,
            username = it.username,
            msgTypes = it.msgTypes,
            status = it.status,
        )
    },
    binary = binary?.let {
        BinaryProtocolInfo(
            endpoint = it.endpoint,
            hmacScheme = it.hmacScheme,
            ops = it.ops,
            keySet = it.keySet,
        )
    },
)
