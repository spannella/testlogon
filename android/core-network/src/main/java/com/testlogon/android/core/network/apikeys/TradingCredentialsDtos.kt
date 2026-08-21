package com.testlogon.android.core.network.apikeys

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass
import com.testlogon.android.core.network.json.LenientInt

/**
 * MULTI-PROTOCOL trading/custody credentials — transport DTOs for provisioning REST/WS/FIX/Binary access
 * against the unified exchange gateway. NEW endpoints; ALL reads DEGRADE ON 404 (the repository maps a 404 to an
 * honest "not available yet" empty/absent value; existing content-scope keys keep working unchanged).
 *
 * Mirrors the web contract (frontend `api/types.ts` + `endpoints/tradingCredentials.ts`) VERBATIM. Relative
 * paths, NO leading slash (matching the rest of the ApiKeysApi). All fields are defaulted so a partial/absent
 * server body decodes cleanly; `@LenientInt` guards the FIX/gateway port coming across as a quoted string.
 *
 * @JsonClass(generateAdapter = true) is declared for parity with the codebase convention; core-network decodes
 * via the reflective KotlinJsonAdapterFactory on the shared Moshi, so every wire key is pinned with @Json.
 */

// ── Create body extension (protocols) + one-time protocol credentials on the create result ────────────

/** One-time WS credential returned on create (WS token — show-once). */
@JsonClass(generateAdapter = true)
data class WsProtocolCredentialDto(
    @Json(name = "ws_token") val wsToken: String = "",
)

/** One-time FIX credential returned on create (username + password — show-once). */
@JsonClass(generateAdapter = true)
data class FixProtocolCredentialDto(
    @Json(name = "username") val username: String = "",
    @Json(name = "password") val password: String = "",
)

/** One-time binary credential returned on create (api_key + secret — show-once). */
@JsonClass(generateAdapter = true)
data class BinaryProtocolCredentialDto(
    @Json(name = "api_key") val apiKey: String = "",
    @Json(name = "secret") val secret: String = "",
)

/** The one-time `protocol_credentials` block on the create result (any subset present). */
@JsonClass(generateAdapter = true)
data class ProtocolCredentialsDto(
    @Json(name = "ws") val ws: WsProtocolCredentialDto? = null,
    @Json(name = "fix") val fix: FixProtocolCredentialDto? = null,
    @Json(name = "binary") val binary: BinaryProtocolCredentialDto? = null,
)

// ── GET me/gateway/endpoints ──────────────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class GatewayWsEndpointDto(
    @Json(name = "url") val url: String = "",
    @Json(name = "enabled") val enabled: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class GatewayFixEndpointDto(
    @Json(name = "host") val host: String = "",
    @LenientInt @Json(name = "port") val port: Int? = null,
    @Json(name = "running") val running: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class GatewayBinaryEndpointDto(
    @Json(name = "endpoint") val endpoint: String = "",
    @Json(name = "enabled") val enabled: Boolean = false,
)

/** Response of GET me/gateway/endpoints — per-protocol gateway availability. */
@JsonClass(generateAdapter = true)
data class GatewayEndpointsDto(
    @Json(name = "ws") val ws: GatewayWsEndpointDto? = null,
    @Json(name = "fix") val fix: GatewayFixEndpointDto? = null,
    @Json(name = "binary") val binary: GatewayBinaryEndpointDto? = null,
)

// ── GET ui/api_keys/{id}/protocols ──────────────────────────────────────────────────────────────────

@JsonClass(generateAdapter = true)
data class KeyProtocolsRestDto(
    @Json(name = "base_url") val baseUrl: String = "",
    @Json(name = "scopes") val scopes: List<String> = emptyList(),
)

@JsonClass(generateAdapter = true)
data class KeyProtocolsWsDto(
    @Json(name = "url") val url: String = "",
    @Json(name = "subs") val subs: List<String> = emptyList(),
    @Json(name = "token_set") val tokenSet: Boolean = false,
)

@JsonClass(generateAdapter = true)
data class KeyProtocolsFixDto(
    @Json(name = "sender_comp_id") val senderCompId: String = "",
    @Json(name = "target_comp_id") val targetCompId: String = "",
    @Json(name = "host") val host: String = "",
    @LenientInt @Json(name = "port") val port: Int? = null,
    @Json(name = "username") val username: String = "",
    @Json(name = "msg_types") val msgTypes: List<String> = emptyList(),
    @Json(name = "status") val status: String = "",
)

@JsonClass(generateAdapter = true)
data class KeyProtocolsBinaryDto(
    @Json(name = "endpoint") val endpoint: String = "",
    @Json(name = "hmac_scheme") val hmacScheme: String = "",
    @Json(name = "ops") val ops: List<String> = emptyList(),
    @Json(name = "key_set") val keySet: Boolean = false,
)

/** Response of GET ui/api_keys/{id}/protocols — the per-protocol connection details for a key. */
@JsonClass(generateAdapter = true)
data class KeyProtocolsDto(
    @Json(name = "rest") val rest: KeyProtocolsRestDto? = null,
    @Json(name = "ws") val ws: KeyProtocolsWsDto? = null,
    @Json(name = "fix") val fix: KeyProtocolsFixDto? = null,
    @Json(name = "binary") val binary: KeyProtocolsBinaryDto? = null,
)

// ── POST ui/api_keys/{id}/protocols/{protocol}/rotate ─────────────────────────────────────────────────

/** Response of a protocol secret rotate — the ONE-TIME new secret for [protocol] (show-once). */
@JsonClass(generateAdapter = true)
data class RotateProtocolSecretDto(
    @Json(name = "protocol") val protocol: String = "",
    @Json(name = "secret") val secret: String = "",
)
