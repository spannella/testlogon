package com.testlogon.android.data.call.recording

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-302 — wire DTOs for the call-recording consent + upload endpoints under the
 * messages/calls/{call_id}/recording namespace (request, consent, decline, upload presign, complete).
 *
 * Every shape VERIFIED against the AND-302 contract (request/consent/decline + upload presign/complete).
 * snake_case field names via [Json]; absent optionals fall back to Kotlin defaults (lenient decode). Epoch
 * timestamps are Long SECONDS; durations on complete are a JSON number -> Float. Mirrors the AND-295
 * [com.testlogon.android.data.call.CallDtos] idiom (Moshi `@JsonClass(generateAdapter = true)`).
 *
 * The storage PUT (to upload_url) carries the file body only and is performed by the reused AND-129
 * transport ([com.testlogon.android.data.upload.StorageUploadClient]); no DTO is modeled for it.
 */

// ─── Consent protocol (request / consent / decline) ─────────────────────────────────────────────────

/** RecordingRequestOut — the requester opened a consent prompt (status typically "requested"/"pending"). */
@JsonClass(generateAdapter = true)
data class RecordingRequestOutDto(
    @Json(name = "recording_id") val recordingId: String,
    @Json(name = "status") val status: String,
    @Json(name = "created_at") val createdAtEpochSeconds: Long,
)

/** RecordingConsentOut — the callee accepted; capture may begin (status typically "granted"/"started"). */
@JsonClass(generateAdapter = true)
data class RecordingConsentOutDto(
    @Json(name = "recording_id") val recordingId: String,
    @Json(name = "status") val status: String,
    @Json(name = "started_at") val startedAtEpochSeconds: Long,
)

/** RecordingDeclineOut — the callee declined; capture must NOT begin. */
@JsonClass(generateAdapter = true)
data class RecordingDeclineOutDto(
    @Json(name = "ok") val ok: Boolean = false,
)

// ─── Upload (presign -> PUT -> complete) ────────────────────────────────────────────────────────────

/**
 * RecordingUploadPresignIn — body for the presign call. content_type MUST match `^video/(webm|mp4)$`
 * (this client uses "video/mp4", MediaRecorder MPEG_4); the field is `file_size_bytes` (NOT size_bytes),
 * and there is NO duration on presign.
 */
@JsonClass(generateAdapter = true)
data class RecordingUploadPresignInDto(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "file_size_bytes") val fileSizeBytes: Long,
)

/** RecordingUploadPresignOut — the presigned PUT target + the s3 key + expiry (epoch seconds). */
@JsonClass(generateAdapter = true)
data class RecordingUploadPresignOutDto(
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "recording_id") val recordingId: String,
    @Json(name = "s3_key") val s3Key: String,
    @Json(name = "expires_at") val expiresAtEpochSeconds: Long,
)

/**
 * RecordingUploadCompleteIn — body for the complete call (the endpoint is "complete", not "confirm").
 * duration_seconds is a JSON number -> Float.
 */
@JsonClass(generateAdapter = true)
data class RecordingUploadCompleteInDto(
    @Json(name = "recording_id") val recordingId: String,
    @Json(name = "duration_seconds") val durationSeconds: Float,
)

/** RecordingUploadCompleteOut — terminal recording state + an optional, expiring download URL. */
@JsonClass(generateAdapter = true)
data class RecordingUploadCompleteOutDto(
    @Json(name = "recording_id") val recordingId: String,
    @Json(name = "status") val status: String,
    @Json(name = "download_url") val downloadUrl: String? = null,
    @Json(name = "download_expires_at") val downloadExpiresAtEpochSeconds: Long? = null,
)
