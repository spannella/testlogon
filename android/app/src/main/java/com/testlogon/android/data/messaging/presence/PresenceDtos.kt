package com.testlogon.android.data.messaging.presence

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-145 — presence wire DTOs + domain model.
 *
 * Verified against reference/src/api/endpoints/messaging.ts and openapi.index.txt:
 *  - POST messaging/presence/heartbeat  (req PresenceHeartbeatIn {device?, status?})
 *      -> 200 { ok, user_id, online, last_seen_at }   (no ttl_seconds — cadence is a client constant)
 *  - GET  messaging/presence?user_ids=a,b,c
 *      -> 200 BARE ARRAY of { user_id, online, last_seen_at }  (PresenceStatus[])
 * SSE `presence:update` carries one user per event: { user_id, online, last_seen_at }.
 * `last_seen_at` is an epoch INTEGER (seconds assumed; unconfirmed unit — see spec open assumptions).
 */

/** Heartbeat request body — PresenceHeartbeatIn { device?, status? }. Web sends { device }. */
@JsonClass(generateAdapter = true)
data class HeartbeatReq(
    @Json(name = "device") val device: String? = null,
    @Json(name = "status") val status: String? = null,
)

/** Heartbeat 200 body (untyped in OpenAPI; web declares this shape). No ttl_seconds. */
@JsonClass(generateAdapter = true)
data class HeartbeatResp(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "user_id") val userId: String? = null,
    @Json(name = "online") val online: Boolean = true,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null,
)

/** A single presence record from GET messaging/presence or an SSE presence:update. */
@JsonClass(generateAdapter = true)
data class PresenceDto(
    @Json(name = "user_id") val userId: String,
    @Json(name = "online") val online: Boolean = false,
    @Json(name = "last_seen_at") val lastSeenAt: Long? = null,
)

/** Read-side presence status — online/offline only (the read schema has no AWAY). */
enum class PresenceStatus { ONLINE, OFFLINE }

/**
 * Domain presence for one tracked user. [stale] is set true while SSE is disconnected so the UI can
 * dim the dot rather than flipping everyone offline on a flaky network.
 */
data class Presence(
    val userId: String,
    val status: PresenceStatus,
    val lastSeenAtEpochSeconds: Long?,
    val stale: Boolean = false,
) {
    companion object {
        /** Default OFFLINE presence for an untracked user. */
        fun offline(userId: String): Presence =
            Presence(userId, PresenceStatus.OFFLINE, lastSeenAtEpochSeconds = null)
    }
}

/** Maps a wire [PresenceDto] to the domain [Presence]; status derives purely from `online`. */
fun PresenceDto.toPresence(): Presence = Presence(
    userId = userId,
    status = if (online) PresenceStatus.ONLINE else PresenceStatus.OFFLINE,
    lastSeenAtEpochSeconds = lastSeenAt,
)
