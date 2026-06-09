package com.testlogon.android.data.upload

import android.net.Uri

/**
 * AND-129 — public model surface for the reusable attachment-upload pipeline
 * (presign to storage-PUT to confirm).
 *
 * The pipeline is feature-agnostic: a caller hands it a content [Uri], a MIME type, the resolved
 * size, and the concrete presign/confirm routes for its domain (image, video, profile, ...). The
 * REAL backend has NO generic attachments endpoint — presign/confirm are per-domain, so the route
 * is supplied by the consumer via [UploadRequest.presignPath]/[UploadRequest.confirmPath]
 * (Retrofit `@Url`). Verified against reference/src/api/endpoints/messaging.ts (images/presign),
 * files.ts (fs presign/complete), and videos.ts (vod presign/complete).
 *
 * The image flow has NO confirm endpoint: [UploadRequest.confirmPath] is null and the consumer
 * "confirms" by posting a message carrying the presign bucket/key (owned by AND-130).
 */
data class UploadRequest(
    val uri: Uri,
    val mimeType: String,
    /** Logical category: "message" | "avatar" | "cover" | ... (telemetry/debug only). */
    val category: String,
    val sizeBytes: Long,
    val displayName: String? = null,
    /** Concrete presign route, e.g. "messaging/conversations/{id}/images/presign". */
    val presignPath: String,
    /** Concrete confirm route, e.g. "v1/fs/complete-upload"; null for the image flow. */
    val confirmPath: String? = null,
    /** Logical fs path used in presign/complete bodies (fs flow only). */
    val remotePath: String? = null,
)

/** Phase of the three-step pipeline; carried by [UploadProgress.Failed] for retry routing. */
enum class UploadPhase { PRESIGN, PUT, CONFIRM }

/**
 * Cold-flow progress model. Terminal states ([Succeeded]/[Failed]/[Cancelled]) complete the flow;
 * nothing is emitted after a terminal value.
 */
sealed interface UploadProgress {
    /** Presign request in flight. */
    data object Preparing : UploadProgress

    /** Storage PUT in flight; [fraction] is clamped to 0..1. */
    data class Uploading(
        val bytesSent: Long,
        val totalBytes: Long,
    ) : UploadProgress {
        val fraction: Float
            get() = if (totalBytes <= 0L) 0f else (bytesSent.toFloat() / totalBytes).coerceIn(0f, 1f)
    }

    /** Confirm request in flight (consumers with a confirmPath only). */
    data object Confirming : UploadProgress

    data class Succeeded(val attachment: AttachmentRef) : UploadProgress

    data class Failed(val error: UploadError, val phase: UploadPhase) : UploadProgress

    data object Cancelled : UploadProgress
}

/**
 * App-side projection returned on success, synthesized from the presign `key`/`bucket` plus the
 * confirm result (the backend confirm does NOT return an id/url/width/height — see AND-129 §5.3).
 * `width`/`height` are supplied by the caller (read locally before upload), not the API.
 */
data class AttachmentRef(
    val id: String,
    val bucket: String,
    val key: String,
    val url: String,
    val contentType: String,
    val sizeBytes: Long,
    val width: Int? = null,
    val height: Int? = null,
    /** Retained so a confirm-resume retry can replay confirm without re-uploading bytes. */
    val ticketId: String? = null,
    val remotePath: String? = null,
)

/**
 * Structured upload failure. [kind] aligns with the AND-117 reconnect affordances so a consuming
 * screen can render localized retry/offline text without string-matching.
 */
data class UploadError(
    val kind: Kind,
    val httpStatus: Int? = null,
    val message: String? = null,
) {
    enum class Kind {
        /** Presigned URL expired/invalid (403 on PUT) — retry restarts at presign. */
        EXPIRED,

        /** Storage PUT failed with a non-403 HTTP status (no FastAPI body). */
        STORAGE,

        /** Presign/confirm returned a FastAPI error (4xx/5xx with a `detail` body). */
        SERVER,

        /** Request validation failure (422). */
        VALIDATION,

        /** Connect/read/write timed out. */
        TIMEOUT,

        /** No HTTP response: DNS/connect/offline. */
        NETWORK,
    }
}
