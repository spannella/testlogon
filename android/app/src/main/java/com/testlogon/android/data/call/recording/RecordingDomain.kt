package com.testlogon.android.data.call.recording

/**
 * AND-302 — pure (DTO-free) domain models for the call-recording consent + upload flow.
 *
 * The repository maps wire DTOs -> these before returning a typed ApiResult (never leaks raw DTOs). No
 * android.* types (JVM-unit-testable on minSdk 24); epoch timestamps are Long SECONDS, the complete
 * duration is a Float SECONDS. Mirrors the AND-295 [com.testlogon.android.data.call.CallDomain] idiom.
 */

/** Result of opening a consent prompt (POST .../recording/request -> RecordingRequestOut). */
data class RecordingRequest(
    val recordingId: String,
    val status: String,
    val createdAtEpochSeconds: Long,
)

/**
 * Result of the callee accepting (POST .../recording/consent -> RecordingConsentOut). [startedAtEpochSeconds]
 * present (and a granted-style [status]) is the server CONSENT GATE: capture must NEVER begin before this.
 */
data class RecordingConsent(
    val recordingId: String,
    val status: String,
    val startedAtEpochSeconds: Long,
) {
    /** True when the server confirms consent was granted and recording may start. */
    val isGranted: Boolean
        get() = startedAtEpochSeconds > 0L &&
            (status.equals("granted", ignoreCase = true) || status.equals("started", ignoreCase = true))
}

/** Presigned PUT target for the recording artifact (POST .../upload/presign -> RecordingUploadPresignOut). */
data class RecordingPresign(
    val uploadUrl: String,
    val recordingId: String,
    val s3Key: String,
    val expiresAtEpochSeconds: Long,
)

/** Terminal upload result (POST .../upload/complete -> RecordingUploadCompleteOut). */
data class RecordingComplete(
    val recordingId: String,
    val status: String,
    val downloadUrl: String?,
    val downloadExpiresAtEpochSeconds: Long?,
)

// ─── DTO -> domain mappers ───────────────────────────────────────────────────────────────────────

internal fun RecordingRequestOutDto.toDomain(): RecordingRequest = RecordingRequest(
    recordingId = recordingId,
    status = status,
    createdAtEpochSeconds = createdAtEpochSeconds,
)

internal fun RecordingConsentOutDto.toDomain(): RecordingConsent = RecordingConsent(
    recordingId = recordingId,
    status = status,
    startedAtEpochSeconds = startedAtEpochSeconds,
)

internal fun RecordingUploadPresignOutDto.toDomain(): RecordingPresign = RecordingPresign(
    uploadUrl = uploadUrl,
    recordingId = recordingId,
    s3Key = s3Key,
    expiresAtEpochSeconds = expiresAtEpochSeconds,
)

internal fun RecordingUploadCompleteOutDto.toDomain(): RecordingComplete = RecordingComplete(
    recordingId = recordingId,
    status = status,
    downloadUrl = downloadUrl,
    downloadExpiresAtEpochSeconds = downloadExpiresAtEpochSeconds,
)
