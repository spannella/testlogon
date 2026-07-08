package com.testlogon.android.data.feed

import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-173 / AND-174 / AND-175 — wire DTOs for feed content-engagement (like, comment, hide).
 *
 * Verified against reference/src/api/endpoints/newsfeed.ts and reference/src/api/types.ts:
 *  - like/unlike      -> POST /posts/{post_id}/like, POST /posts/{post_id}/unlike;
 *    body none; 200 is an untyped ack { ok: boolean } (NO liked / like_count). See AND-173 §5.
 *  - list comments    -> GET  /posts/{post_id}/comments?cursor=&limit=  -> { items[], next_cursor? }.
 *  - add comment      -> POST /posts/{post_id}/comments  CreateCommentReq -> 200 FeedComment (NOT 201).
 *  - delete comment   -> DELETE /posts/{post_id}/comments/{comment_id}  -> 200 { ok: boolean }.
 *  - hide / unhide    -> POST /feed/hide, POST /feed/unhide  HidePostReq{post_id} -> 200 { ok: boolean }.
 *
 * Comment field facts (FeedComment): id is "comment_id"; flat "author_id" (NO nested author); parent
 * pointer is "parent_comment_id"; body is nullable on the wire; there is NO reply_count / can_delete.
 * Unknown rich/gif/sticker fields are ignored by Moshi codegen.
 */

// ---- Comments ----

@JsonClass(generateAdapter = true)
data class CommentPageDto(
    @Json(name = "items") val items: List<CommentDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class CommentDto(
    @Json(name = "comment_id") val commentId: String,
    @Json(name = "post_id") val postId: String = "",
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
    @Json(name = "author_id") val authorId: String = "",
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_plain") val bodyPlain: String? = null,
    @Json(name = "created_at") val createdAt: String = "",
    @Json(name = "updated_at") val updatedAt: String? = null,
    @Json(name = "deleted") val deleted: Boolean = false,
    @Json(name = "tip_total_cents") val tipTotalCents: Int = 0,
    // Rich-comment payloads (kind "gif" / "sticker" / "image"); absent on plain text comments.
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "gif_url") val gifUrl: String? = null,
    @Json(name = "sticker_url") val stickerUrl: String? = null,
    // #24 — user-uploaded image comments (kind == "image").
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "image_alt_text") val imageAltText: String? = null,
    // #23 — emoji reactions on comments (mirrors post reactions; legacy comments lack these).
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int>? = null,
    @Json(name = "my_reactions") val myReactions: List<String>? = null,
)

/**
 * POST /posts/{post_id}/comments request. Plain text comment: { body, parent_comment_id }. A GIF comment
 * sets kind="gif" + gif_url; a sticker comment sets kind="sticker" + sticker_id + sticker_collection_id.
 */
@JsonClass(generateAdapter = true)
data class CreateCommentRequest(
    @Json(name = "body") val body: String,
    @Json(name = "parent_comment_id") val parentCommentId: String? = null,
    @Json(name = "kind") val kind: String? = null,
    @Json(name = "gif_url") val gifUrl: String? = null,
    @Json(name = "gif_alt_text") val gifAltText: String? = null,
    @Json(name = "sticker_id") val stickerId: String? = null,
    @Json(name = "sticker_collection_id") val stickerCollectionId: String? = null,
    @Json(name = "sticker_url") val stickerUrl: String? = null,
    @Json(name = "sticker_alt_text") val stickerAltText: String? = null,
    // #24 — image comment (kind="image"); image_url must be a platform upload URL or https.
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "image_alt_text") val imageAltText: String? = null,
    // TIP-302 — comment-CARRYING tip: when tipAmountCents is present the backend charges the tip
    // (content_type="comment", recipient = the post author) BEFORE writing the comment, then stamps it.
    @Json(name = "tip_amount_cents") val tipAmountCents: Int? = null,
    @Json(name = "tip_currency") val tipCurrency: String? = null,
    @Json(name = "tip_payment_method_id") val tipPaymentMethodId: String? = null,
)

/** POST /posts/{id}/reactions and /posts/{id}/comments/{cid}/reactions request — a single emoji. */
@JsonClass(generateAdapter = true)
data class ReactionRequest(
    @Json(name = "emoji") val emoji: String,
)

/** POST /posts/{post_id}/comments/{comment_id}/tip request — amount in integer cents. */
@JsonClass(generateAdapter = true)
data class TipRequest(
    @Json(name = "amount_cents") val amountCents: Int,
    @Json(name = "currency") val currency: String = "USD",
    // TIP-301 — name an explicit / tip-default payment method so charge_tip can resolve the tippers PM.
    @Json(name = "payment_method_id") val paymentMethodId: String? = null,
)

/**
 * PATCH /posts/{post_id}/comments/{comment_id} request — edit an own comment's body and/or image (#5).
 *
 * Per the backend B-COMMENT2 edit contract: OMIT [imageUrl] (null) to KEEP the existing image
 * (default Moshi serializeNulls=false drops the key), send an empty string "" to REMOVE the image,
 * or a new URL to REPLACE it.
 */
@JsonClass(generateAdapter = true)
data class EditCommentRequest(
    @Json(name = "body") val body: String,
    @Json(name = "image_url") val imageUrl: String? = null,
    @Json(name = "image_alt_text") val imageAltText: String? = null,
)

// ---- Hide / not-interested ----

/** POST /feed/hide and /feed/unhide request: { "post_id": "<id>" } (schema HidePostRequest). */
@JsonClass(generateAdapter = true)
data class HidePostRequest(
    @Json(name = "post_id") val postId: String,
)
