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
    // MULTI-PROTOCOL: one-time WS/FIX/binary credential material when protocols were provisioned (show-once).
    val protocolCredentials: ProtocolCredentials? = null,
)

/**
 * MULTI-PROTOCOL — one-time credential material returned on create when `protocols` were requested. Held only
 * in-session for the show-once surface; NEVER persisted or logged. Any subset may be present.
 */
data class ProtocolCredentials(
    val wsToken: String? = null,
    val fixUsername: String? = null,
    val fixPassword: String? = null,
    val binaryApiKey: String? = null,
    val binarySecret: String? = null,
) {
    /** True when nothing was provisioned (a content-only key). */
    val isEmpty: Boolean
        get() = wsToken == null && fixUsername == null && fixPassword == null &&
            binaryApiKey == null && binarySecret == null
}

/** MULTI-PROTOCOL — the unified exchange gateway per-protocol availability (from GET me/gateway/endpoints). */
data class GatewayEndpoints(
    val wsUrl: String,
    val wsEnabled: Boolean,
    val fixHost: String,
    val fixPort: Int?,
    val fixRunning: Boolean,
    val binaryEndpoint: String,
    val binaryEnabled: Boolean,
)

/** REST connection details for a key. */
data class RestProtocolInfo(val baseUrl: String, val scopes: List<String>)

/** WS connection details for a key. [tokenSet] == a WS token has been provisioned (rotate re-issues it). */
data class WsProtocolInfo(val url: String, val subs: List<String>, val tokenSet: Boolean)

/** FIX session connection details for a key. */
data class FixProtocolInfo(
    val senderCompId: String,
    val targetCompId: String,
    val host: String,
    val port: Int?,
    val username: String,
    val msgTypes: List<String>,
    val status: String,
)

/** Binary (me_wire) connection details for a key. [keySet] == an HMAC key/secret has been provisioned. */
data class BinaryProtocolInfo(
    val endpoint: String,
    val hmacScheme: String,
    val ops: List<String>,
    val keySet: Boolean,
)

/**
 * MULTI-PROTOCOL — a key's per-protocol connection credentials (from GET ui/api_keys/{id}/protocols). A null
 * section means that protocol is not enabled for the key. Secrets are never carried here (only *set flags).
 */
data class KeyProtocols(
    val rest: RestProtocolInfo? = null,
    val ws: WsProtocolInfo? = null,
    val fix: FixProtocolInfo? = null,
    val binary: BinaryProtocolInfo? = null,
) {
    val hasAny: Boolean get() = rest != null || ws != null || fix != null || binary != null
}
