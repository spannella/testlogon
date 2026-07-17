package com.testlogon.android.data.feed

import com.testlogon.android.data.ads.CtaActionDto
import com.squareup.moshi.Json
import com.squareup.moshi.JsonClass

/**
 * AND-097 — wire DTOs for the consumer newsfeed.
 *
 * Verified against reference/src/api/types.ts (FeedPost), reference/src/api/endpoints/newsfeed.ts
 * (getFeed -> GET /feed, getPost -> GET /posts/{post_id}), and reference/src/pages/feed/PostCard.tsx.
 *
 * Key field facts (review-corrected contract):
 *  - id is "post_id" (NOT "id"); author is a flat "author_id" (NO nested author object).
 *  - text is "body" / "body_plain" (NOT "text"); plain projection is body_plain ?? body.
 *  - media is "image_urls": string[] + a SINGLE "video" object (NO "media[]" array).
 *  - lock state is FLAT: locked, unlocked, lock_type ("fixed_price"|"tip_lottery"),
 *    unlock_price_cents, unlock_limit/_count/_limit_reached, lock_expired.
 *    Web rule: isLocked = !!post.locked && !post.unlocked. There is NO currency field (USD assumed).
 *  - envelope is { items, next_cursor } — NO has_more; end-of-feed == next_cursor null/absent.
 *
 * Only post_id/author_id/created_at are server-required for our read; everything else is defaulted so
 * unknown/missing fields never crash the page (Moshi codegen ignores unknown JSON keys by default).
 */
@JsonClass(generateAdapter = true)
data class FeedPageDto(
    @Json(name = "items") val items: List<PostDto> = emptyList(),
    @Json(name = "next_cursor") val nextCursor: String? = null,
)

@JsonClass(generateAdapter = true)
data class TipReactionBadgeDto(
    @Json(name = "tipper_id") val tipperId: String? = null,
    @Json(name = "emoji") val emoji: String? = null,
    @Json(name = "amount_cents") val amountCents: Int = 0,
    @Json(name = "tip_payment_id") val tipPaymentId: String? = null,
    @Json(name = "created_at") val createdAt: String? = null,
)

@JsonClass(generateAdapter = true)
data class PostDto(
    @Json(name = "post_id") val postId: String,
    @Json(name = "author_id") val authorId: String = "",
    @Json(name = "created_at") val createdAt: String = "",
    @Json(name = "body") val body: String? = null,
    @Json(name = "body_plain") val bodyPlain: String? = null,
    @Json(name = "image_urls") val imageUrls: List<String>? = null,
    @Json(name = "video") val video: VideoDto? = null,
    // #2 (B-FEEDMEDIA) — the FULL ordered list of attached videos (mixed media: images AND videos may
    // coexist). `video` stays as the first video for back-compat; this array is authoritative when present.
    @Json(name = "videos") val videos: List<VideoDto>? = null,
    @Json(name = "tags") val tags: List<String>? = null,
    // #4 (B-GROUPUNIFY) — set when this post was authored to a GROUP audience. The backend bridges
    // group posts into the unified feed/my-posts (GSI1 FEEDREF + GSI2 author) and projects group_id on
    // them; null for a normal post. Lets the feed/my-posts surface a "Posted in <group>" chip.
    @Json(name = "group_id") val groupId: String? = null,
    @Json(name = "like_count") val likeCount: Int = 0,
    @Json(name = "comment_count") val commentCount: Int = 0,
    @Json(name = "liked_by_me") val likedByMe: Boolean = false,
    // SOCIAL-002 (public reposting) — repost tally + per-viewer state, plus, when THIS feed row was
    // sourced from a repost FEEDREF, the reposter attribution + optional quote/commentary. All defaulted
    // so an organic (never-reposted) post maps cleanly.
    @Json(name = "repost_count") val repostCount: Int = 0,
    @Json(name = "reposted_by_me") val repostedByMe: Boolean = false,
    @Json(name = "reposted_by") val repostedBy: RepostedByDto? = null,
    @Json(name = "repost_quote") val repostQuote: String? = null,
    // #20 — full emoji reactions (distinct from like). Per-emoji counts + the viewer's own reactions.
    @Json(name = "reactions_counts") val reactionsCounts: Map<String, Int>? = null,
    @Json(name = "my_reactions") val myReactions: List<String>? = null,
    // TIP-204 - money-reaction (tip) badges surfaced by the backend feed/post serializer.
    @Json(name = "tip_reactions") val tipReactions: List<TipReactionBadgeDto>? = null,
    // TIPX-C1 - running total of DIRECT (non-reaction) tips on this post; rendered as a badge.
    @Json(name = "tip_total_cents") val tipTotalCents: Int = 0,
    // --- flat lock / paywall fields (mirror FeedPost) ---
    @Json(name = "locked") val locked: Boolean = false,
    @Json(name = "unlocked") val unlocked: Boolean = false,
    @Json(name = "lock_type") val lockType: String? = null,
    @Json(name = "unlock_price_cents") val unlockPriceCents: Int? = null,
    @Json(name = "unlock_limit") val unlockLimit: Int? = null,
    @Json(name = "unlock_count") val unlockCount: Int? = null,
    @Json(name = "unlock_limit_reached") val unlockLimitReached: Boolean? = null,
    @Json(name = "lock_expired") val lockExpired: Boolean? = null,
    // --- SUB-E3-2 subscriber-only gating (per-post; emitted by newsfeed _post_to_dict) ---
    // subscriber_only = the post is marked subscriber-gated; subscriber_locked = THIS viewer is a
    // non-subscriber and the body/media were withheld (a lock marker, not deletion). creator_id (below,
    // reused from the sponsored block) carries the author id for the Subscribe CTA.
    @Json(name = "subscriber_only") val subscriberOnly: Boolean = false,
    @Json(name = "subscriber_locked") val subscriberLocked: Boolean = false,
    // SUBX-31: the minimum tier LEVEL this subscriber-only post requires (0 = any
    // active sub - the pre-tier binary default) + the display NAME of that tier so
    // the lock card can name the required tier and upsell to it.
    @Json(name = "required_tier_level") val requiredTierLevel: Int = 0,
    @Json(name = "required_tier_name") val requiredTierName: String? = null,
    // --- ADV-105 sponsored (paid) unit fields (injected by newsfeed sponsored path; ADV-104) ---
    // A server-injected sponsored post carries is_sponsored=true plus the creative + serving metadata.
    // All defaulted so an organic post (no sponsored keys) maps cleanly.
    @Json(name = "is_sponsored") val isSponsored: Boolean = false,
    @Json(name = "sponsor_label") val sponsorLabel: String? = null,
    @Json(name = "headline") val headline: String? = null,
    @Json(name = "cta_text") val ctaText: String? = null,
    @Json(name = "cta_url") val ctaUrl: String? = null,
    // Serving/attribution ids: creative_id + campaign_id + account_id identify the paid unit; ad_click_id
    // is the per-serve CPA id (ADV-103) echoed on the track call. surface/slot_type/creator_id/content_id
    // mirror what serve_ad used, so the client can round-trip them to /ui/ads/track unchanged.
    @Json(name = "creative_id") val creativeId: String? = null,
    @Json(name = "campaign_id") val campaignId: String? = null,
    @Json(name = "account_id") val accountId: String? = null,
    @Json(name = "ad_click_id") val adClickId: String? = null,
    @Json(name = "surface") val surface: String? = null,
    @Json(name = "slot_type") val slotType: String? = null,
    // ADV2-207 (F2) — structured click-through CTA targets served with the sponsored unit.
    @Json(name = "ctas") val ctas: List<CtaActionDto>? = null,
    @Json(name = "creator_id") val creatorId: String? = null,
    @Json(name = "content_id") val contentId: String? = null,
    // --- ADV2-403/409 (F4) sponsored-as-creator (paid partnership) fields ---
    // A DISTINCT flag from is_sponsored above: the post is AUTHORED BY THE CREATOR (they approved it), so
    // it stays a NORMAL creator post (tippable/likeable/commentable, NO forced "Sponsored" label). These
    // drive advertiser BILLING + attribution ONLY (per-impression/click via the placement mint), never the
    // post UI. All defaulted so an organic post maps cleanly.
    @Json(name = "paid_partnership") val paidPartnership: Boolean = false,
    @Json(name = "paid_partnership_disclosure") val paidPartnershipDisclosure: String? = null,
    // --- AND-179 embedded poll (present for post_type "poll"/"survey") ---
    @Json(name = "poll_data") val pollData: PollDataDto? = null,
    @Json(name = "poll_vote_counts") val pollVoteCounts: Map<String, Map<String, Int>>? = null,
    @Json(name = "poll_my_votes") val pollMyVotes: Map<String, List<String>>? = null,
)

/** SOCIAL-002 — reposter attribution attached to a feed row sourced from a repost FEEDREF. */
@JsonClass(generateAdapter = true)
data class RepostedByDto(
    @Json(name = "user_id") val userId: String = "",
    @Json(name = "display_name") val displayName: String? = null,
)

@JsonClass(generateAdapter = true)
data class VideoDto(
    @Json(name = "video_id") val videoId: String,
    @Json(name = "title") val title: String? = null,
    @Json(name = "thumbnail_url") val thumbnailUrl: String? = null,
    @Json(name = "duration_seconds") val durationSeconds: Long? = null,
    @Json(name = "hls_manifest_url") val hlsManifestUrl: String? = null,
    // #2 — short-lived playback token; appended to the manifest url ("?token=") for the player
    // (mirrors the messaging VideoShare / web VideoPlayerPage). Null in dev (mock-S3 ignores it).
    @Json(name = "playback_token") val playbackToken: String? = null,
)
