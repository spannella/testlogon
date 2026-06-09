package com.testlogon.android.data.messaging

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-130 — wire DTOs for image messages.
 *
 * Flow (verified, reference/src/api/endpoints/messaging.ts: sendImageMessage):
 *   1. POST messaging/conversations/{id}/images/presign  body = SendImagePresignIn{content_type,filename}
 *      -> PresignOut{upload_url,bucket,key,content_type}
 *   2. PUT bytes to upload_url (AND-129 cookieless transport)
 *   3. POST messaging/conversations/{id}/messages/image   body = CreateImageMessageIn (required bucket,key)
 *      -> MessageOut (kind="image", carries an `image` object)
 * There is NO confirm endpoint and NO attachment_id. The create body references the object by
 * bucket+key.
 */

/** SendImagePresignIn = { content_type, filename }. */
@JsonClass(generateAdapter = true)
data class ImagePresignReq(
    @Json(name = "content_type") val contentType: String,
    @Json(name = "filename") val filename: String,
)

/** PresignOut = { upload_url, bucket, key, content_type }. */
@JsonClass(generateAdapter = true)
data class ImagePresignResp(
    @Json(name = "upload_url") val uploadUrl: String,
    @Json(name = "bucket") val bucket: String,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String,
)

/** CreateImageMessageIn. Required: bucket, key. The rest are optional metadata. */
@JsonClass(generateAdapter = true)
data class CreateImageMessageReq(
    @Json(name = "bucket") val bucket: String,
    @Json(name = "key") val key: String,
    @Json(name = "content_type") val contentType: String? = null,
    @Json(name = "kind") val kind: String = "image",
    @Json(name = "filename") val filename: String? = null,
    @Json(name = "filesize") val filesize: Long? = null,
    @Json(name = "width") val width: Int? = null,
    @Json(name = "height") val height: Int? = null,
)
