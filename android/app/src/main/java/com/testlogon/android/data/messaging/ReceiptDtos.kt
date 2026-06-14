package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-147 — read-receipt / message-view wire DTOs.
 *
 * Endpoints (verified against reference/openapi.index.txt lines 365-366 + schemas):
 *  - POST messaging/conversations/{cid}/messages/{mid}/view  req=ViewMessageIn  resp=ViewAckOut
 *  - GET  messaging/conversations/{cid}/messages/{mid}/views?limit=  resp=List<MessageViewOut> (BARE array)
 *
 * Timestamps are epoch-INTEGER seconds (NOT ISO-8601), per the OpenAPI schemas (ViewAckOut.viewed_at,
 * MessageViewOut.last_viewed_at). The roster payload carries NO display_name / avatar_url — identity
 * is resolved client-side from the participant cache.
 */

/** Report-view request body. `viewed_at` is optional (may be null/omitted); server stamps its own. */
@JsonClass(generateAdapter = true)
data class ViewMessageIn(
    @Json(name = "viewed_at") val viewedAt: Long? = null,
)

/** Report-view ack (ViewAckOut): echoes ok + conversation/message/viewer ids + epoch viewed_at. */
@JsonClass(generateAdapter = true)
data class ViewAckOut(
    val ok: Boolean = false,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "viewer_id") val viewerId: String = "",
    @Json(name = "viewed_at") val viewedAt: Long = 0L,
)

/** One viewer-roster element (MessageViewOut): exactly user_id + last_viewed_at + view_count. */
@JsonClass(generateAdapter = true)
data class MessageViewOut(
    @Json(name = "user_id") val userId: String,
    @Json(name = "last_viewed_at") val lastViewedAt: Long,
    @Json(name = "view_count") val viewCount: Int,
)
