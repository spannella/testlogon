package com.testlogon.android.data.upload

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-129 — wire DTOs for the generic presign/confirm pair, modelled as a SUPERSET of the real
 * per-domain shapes so one [AttachmentApi] serves image / fs / video presign without a hardcoded
 * path that does not exist on the backend.
 *
 * Verified against (see AND-129 §16):
 *  - image presign  `SendImagePresignIn`  = { content_type, filename }            -> `PresignOut`
 *    (reference/src/api/endpoints/messaging.ts: sendImageMessage)
 *  - fs presign     `PresignUploadIn`      = { path, content_type }               -> `PresignUploadOut`
 *  - confirm        `CompleteUploadIn`     = { path, key, ticket_id, content_type } (fs only)
 *
 * Nulls are omitted by Moshi so each consumer sends only the fields its route requires.
 */

/** Presign request body. Image uses {content_type, filename}; fs uses {path, content_type}. */
@JsonClass(generateAdapter = true)
data class PresignBody(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "filename") val filename: String? = null,
    @Json(name = "path") val path: String? = null,
)

/**
 * Presign response. `upload_url`/`bucket`/`key`/`content_type` are always present; `ticket_id`/`path`
 * only on the fs/video flows. There is NO `method` and NO `headers` map — the HTTP method (PUT) and
 * the lone `Content-Type` header are client conventions.
 */
@JsonClass(generateAdapter = true)
data class PresignResponse(
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "bucket") val bucket: String,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "ticket_id") val ticketId: String? = null,
    @Json(name = "path") val path: String? = null,
)

/** Confirm/complete request = `CompleteUploadIn`. Required: path, key, ticket_id. */
@JsonClass(generateAdapter = true)
data class ConfirmBody(
    @Json(name = "path") val path: String,
    @Json(name = "key") val key: String,
    @Json(name = "ticket_id") val ticketId: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "encrypted") val encrypted: Boolean = false,
)

/** fs `complete-upload` response = { ok, path, size, content_type }. */
@JsonClass(generateAdapter = true)
data class ConfirmResponse(
    @Json(name = "ok") val ok: Boolean = true,
    @Json(name = "path") val path: String? = null,
    @Json(name = "size") val size: Long? = null,
    @Json(name = "content_type") val contentType: String? = null,
)
