package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * C6 — wire DTOs for multi-image (gallery) messages.
 *
 * Backend (verified app/routers/messaging.py):
 *   POST messaging/conversations/{id}/messages/gallery  body = CreateGalleryMessageIn
 *     { free_images:[GalleryImageItemIn], locked_images:[...], text?, lock_price_cents?,
 *       expires_in_seconds?, send_at? }  -> MessageOut(kind="gallery", free_images:[...])
 *
 * Each GalleryImageItemIn shares the bucket/key/content_type/width/height shape produced by the
 * existing conversation image presign (POST .../images/presign + PUT), so a multi-image send is:
 * presign+PUT each picked image, collect the refs into free_images, POST once.
 */

/** GalleryImageItemIn — one uploaded image referenced by bucket+key (+ optional metadata). */
@JsonClass(generateAdapter = true)
data class GalleryImageItemReq(
    @Json(name = "bucket") val bucket: String,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
    @Json(name = "filename") val filename: String? = null,
    @Json(name = "filesize") val filesize: Long? = null,
)

/** CreateGalleryMessageIn — at least one free_images entry; the optional text becomes the caption. */
@JsonClass(generateAdapter = true)
data class CreateGalleryMessageReq(
    @Json(name = "free_images") val freeImages: List<GalleryImageItemReq>,
    @Json(name = "text") val text: String? = null,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
)

/** One image projected back on a kind="gallery" MessageOut (url is server-relative in dev). */
@JsonClass(generateAdapter = true)
data class GalleryImageDto(
    @Json(name = "url") val url: String? = null,
    @Json(name = "bucket") val bucket: String? = null,
    @Json(name = "key") val key: String? = null,
    @Json(name = "content_type") val contentType: String? = null,
    // NOTE: width/height are intentionally omitted — the DDB thread-GET path serializes them as
    // STRINGS ("1") while the create response uses ints, which Moshi cannot coerce uniformly. The
    // gallery grid renders as fixed squares, so per-image dimensions are unnecessary.
)
