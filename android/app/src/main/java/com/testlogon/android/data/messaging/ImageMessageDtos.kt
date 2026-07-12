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
    // C5 — optional caption (Backend B1: request field `caption`; read back as MessageOut.text).
    @Json(name = "caption") val caption: String? = null,
    // Gating options (parity with text): server accepts these on image messages.
    @Json(name = "consumption_policy") val consumptionPolicy: String? = null,
    @Json(name = "view_once") val viewOnce: Boolean = false,
    @Json(name = "expires_in_seconds") val expiresInSeconds: Long? = null,
    @Json(name = "lock_price_cents") val lockPriceCents: Long? = null,
    @Json(name = "send_at") val sendAt: Long? = null,
    @Json(name = "encryption") val encryption: MessageEncryptionEnvelopeDto? = null,
    // TIP-106 - attach a tip to this message on send (money-path via charge_tip on the backend).
    // tip_recipient_id is required only for a GROUP attached tip (backend 400 otherwise); a DM
    // resolves the other participant server-side. Not combinable with lock_price_cents (backend 400).
    @Json(name = "tip_amount_cents") val tipAmountCents: Long? = null,
    @Json(name = "tip_payment_method_id") val tipPaymentMethodId: String? = null,
    @Json(name = "tip_recipient_id") val tipRecipientId: String? = null,
)
