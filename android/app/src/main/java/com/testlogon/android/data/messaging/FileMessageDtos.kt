package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-132 — wire DTOs for file messages, file-share, and the once-media attachment download
 * grant/consume flow.
 *
 * Verified against the live OpenAPI + reference/src/api/endpoints/messaging.ts (2026-06-06):
 *  - send       POST messaging/conversations/{id}/messages/file        body=CreateFileMessageIn{path,kind,...}
 *               -> MessageOut (kind="file"/"audio"/"video", `file` object)         [op create_file_message]
 *  - share      POST messaging/conversations/{id}/messages/file-share  body=CreateFileShareMessageIn
 *               {file_path,permission,text?,send_at?} -> MessageOut (kind="file_share")
 *  - grant      POST .../messages/{message_id}/attachment/grant         empty body -> AttachmentGrantOut
 *               {grant_token, expires_at(epoch int), conversation_id, message_id}
 *  - consume    POST .../messages/{message_id}/attachment/consume       body=ConsumeAttachmentIn
 *               {consumption_attempt_id(8..128), trigger(open|play), playback_seconds?}; grant_token is a
 *               QUERY param -> ConsumeAttachmentOut (metadata only; NOT the bytes)
 *  - bytes      GET  .../messages/{message_id}/attachment?grant_token=...  -> raw bytes
 *
 * The file object on MessageOut is free-form (additionalProperties:true); the field names below mirror
 * reference/src/api/types.ts `MessageFile` (path/name/size/content_type/url/duration_seconds).
 */

/** CreateFileMessageIn. Required: `path` (a VFS storage key from the fs complete-upload). */
@JsonClass(generateAdapter = true)
data class CreateFileMessageReq(
    @Json(name = "path") val path: String,
    @Json(name = "kind") val kind: String = "file",
    @Json(name = "consumption_policy") val consumptionPolicy: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Int? = null,
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    // C9 — gating options (parity with image/text; Backend B2 accepts these on file messages).
    @Json(name = "view_once") val viewOnce: Boolean = false,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
    @Json(name = "lock_price_cents") val lockPriceCents: Long? = null,
    @Json(name = "lock_description") val lockDescription: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** CreateFileShareMessageIn. Required: `file_path` (1..1000). */
@JsonClass(generateAdapter = true)
data class CreateFileShareReq(
    @Json(name = "file_path") val filePath: String,
    @Json(name = "permission") val permission: String = "read",
    @Json(name = "text") val text: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** MessageOut.file (and .file_share). All inner fields are optional per the free-form schema. */
@JsonClass(generateAdapter = true)
data class MessageFileDto(
    val path: String? = null,
    val name: String? = null,
    val size: Long? = null,
    @Json(name = "content_type") val contentType: String? = null,
    val url: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Int? = null,
    // file_share-only metadata.
    val permission: String? = null,
    val owner: String? = null,
)

/** AttachmentGrantOut. `expires_at` is epoch SECONDS. */
@JsonClass(generateAdapter = true)
data class AttachmentGrantResp(
    @Json(name = "grant_token") val grantToken: String,
    @Json(name = "expires_at") val expiresAt: Long = 0L,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
)

/** ConsumeAttachmentIn. `consumption_attempt_id` is 8..128 chars; `trigger` is "open" | "play". */
@JsonClass(generateAdapter = true)
data class ConsumeAttachmentReq(
    @Json(name = "consumption_attempt_id") val consumptionAttemptId: String,
    @Json(name = "trigger") val trigger: String,
    @Json(name = "playback_seconds") val playbackSeconds: Double? = null,
)

/** ConsumeAttachmentOut — metadata only (no bytes). */
@JsonClass(generateAdapter = true)
data class ConsumeAttachmentResp(
    val ok: Boolean = true,
    @Json(name = "conversation_id") val conversationId: String = "",
    @Json(name = "message_id") val messageId: String = "",
    @Json(name = "consumption_state") val consumptionState: String? = null,
    @Json(name = "consumed_at") val consumedAt: Long? = null,
    @Json(name = "consumption_attempt_id") val consumptionAttemptId: String? = null,
)
