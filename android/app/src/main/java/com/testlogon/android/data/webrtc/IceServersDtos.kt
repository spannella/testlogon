package com.testlogon.android.data.webrtc

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-291 — wire DTOs for the TURN/STUN credential fetch.
 *
 * Shape VERIFIED against reference openapi.pretty.json (TurnCredentialsOut L76482 / TurnIceServerOut
 * L76508) and reference/src/api/endpoints/messaging.ts (TurnCredentialsResp / TurnIceServer, L1053).
 * All three top-level fields are required; each ice_servers[] entry has required urls[] (always an
 * array), username, and credential. `ttl_seconds` and `expires_at` are epoch SECONDS integers (Long).
 */

@JsonClass(generateAdapter = true)
data class TurnCredentialsDto(
    @Json(name = "ice_servers") val iceServers: List<TurnIceServerDto> = emptyList(),
    @Json(name = "ttl_seconds") val ttlSeconds: Long = 0,
    @Json(name = "expires_at") val expiresAtEpochSeconds: Long = 0,
)

@JsonClass(generateAdapter = true)
data class TurnIceServerDto(
    @Json(name = "urls") val urls: List<String> = emptyList(),
    @Json(name = "username") val username: String,
    @Json(name = "credential") val credential: String,
)
