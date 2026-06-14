package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-133 — wire DTOs for the dedicated voice-message endpoint pair.
 *
 * Verified against the live OpenAPI + reference/src/api/endpoints/messaging.ts (2026-06-06):
 *  - presign  POST messaging/conversations/{id}/voice-message/presign  body=PresignVoiceMessageRequest
 *             {content_type(^audio/(webm|mp4|ogg|wav)), size_bytes(1..52428800), duration_seconds(0.5..300)}
 *             -> {message_id(^m_[a-f0-9]{32}$), upload_url, s3_key}     [op presign_voice_message]
 *  - PUT      upload_url with Content-Type:<content_type> (AND-129 cookieless transport)
 *  - create   POST messaging/conversations/{id}/voice-message          body=CreateVoiceMessageRequest
 *             {message_id, s3_key, content_type, size_bytes, duration_seconds, waveform_data[10..200],
 *              consumption_policy(none|listen_once)?, reply_to_message_id?, send_at?}
 *             -> MessageOut (kind="voice_message", `voice_message` object)   [op create_voice_message]
 *
 * `waveform_data` is a JSON number[] of floats 0..1 (NOT base64). `duration_seconds` is a float on the
 * wire. The created message echoes the voice payload under MessageOut.voice_message (audio_url,
 * audio_content_type, audio_size_bytes, duration_seconds, waveform_data).
 */

/** PresignVoiceMessageRequest. */
@JsonClass(generateAdapter = true)
data class PresignVoiceReq(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    @Json(name = "duration_seconds") val durationSeconds: Double,
)

/** Presign response (untyped in OpenAPI; shape from the web client). */
@JsonClass(generateAdapter = true)
data class PresignVoiceResp(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "s3_key") val s3Key: String,
)

/** CreateVoiceMessageRequest. */
@JsonClass(generateAdapter = true)
data class CreateVoiceReq(
    @Json(name = "message_id") val messageId: String,
    @Json(name = "s3_key") val s3Key: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "size_bytes") val sizeBytes: Long,
    @Json(name = "duration_seconds") val durationSeconds: Double,
    @Json(name = "waveform_data") val waveformData: List<Float>,
    @Json(name = "consumption_policy") val consumptionPolicy: String = "none",
    @Json(name = "reply_to_message_id") val replyToMessageId: String? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** MessageOut.voice_message (free-form object; field names from reference types.ts). */
@JsonClass(generateAdapter = true)
data class VoiceMessageDto(
    @Json(name = "audio_url") val audioUrl: String? = null,
    @Json(name = "audio_content_type") val audioContentType: String? = null,
    @Json(name = "audio_size_bytes") val audioSizeBytes: Long? = null,
    @Json(name = "duration_seconds") val durationSeconds: Double? = null,
    @Json(name = "waveform_data") val waveformData: List<Float>? = null,
)
