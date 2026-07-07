package com.testlogon.android.data.feed

/**
 * AND-097 / AND-099 / AND-101 — domain model + mapping for the newsfeed (framework-free, JVM-unit-test
 * safe). No android.* / java.time(API26) here so the mapper is minSdk24-safe and pure-unit-testable;
 * timestamps are epoch SECONDS (Long) and relative-time formatting is a UI concern.
 *
 * Locked posts are REDACTED at the mapper: body is dropped, media is emptied, so this layer can never
 * hand protected text or a paid media URL to the UI or cache (defense in depth — stricter than the web
 * client, which keeps the URL and CSS-blurs it). See AND-101 §6/§8.
 */

/** A single feed/detail post as consumed by the feature layer. */
data class FeedPost(
    val id: String,
    val authorId: String,
    /** Epoch SECONDS (0 = unknown/epoch). */
    val createdAtEpochSeconds: Long,
    /** Plain-text body (body_plain ?? body); null when blank OR when the post is locked (redacted). */
    val body: String?,
    /** Synthesized from image_urls + video; EMPTY when the post is locked (redacted). */
    val media: List<Media>,
    val tags: List<String>,
    val likeCount: Int,
    val commentCount: Int,
    val likedByMe: Boolean,
    /**
     * #4 (B-GROUPUNIFY) — the group this post was posted to, or null for a normal (personal) post. Group
     * posts are bridged into the unified feed/my-posts server-side; this lets the UI badge them
     * ("Posted in a group") so group + normal posts coexist in one list.
     */
    val groupId: String? = null,
    /** #20 — full emoji reaction tallies (empty when none); distinct from the like toggle. */
    val reactions: List<ReactionTally> = emptyList(),
    /** Never null at domain level; derived from the flat lock fields. */
    val paywall: Paywall,
    /** AND-179 — embedded poll, or null when the post carries no poll_data. */
    val poll: Poll? = null,
    /**
     * #3 (B-FEEDMEDIA) — the RAW lock state of the post, independent of whether THIS viewer can see the
     * body. The server marks a locked post `locked:true` even for the author (who gets `unlocked:true` so
     * they see their own content). This lets the author's own view of a locked post show a "Locked · $X"
     * badge while still rendering the body. Non-null only when the post is monetized/locked; carries the
     * unlock price in cents (null = locked with no fixed price, e.g. a tip-lottery).
     */
    val authorLock: AuthorLock? = null,
    /**
     * ADV-105 — non-null when this row is a server-injected SPONSORED (paid) unit (newsfeed sponsored
     * path, ADV-104). Carries the ad label/CTA + the serving+attribution ids used to render the
     * distinct Sponsored card and to fire impression/click tracking (ADV-106). Organic posts leave it
     * null. A sponsored unit is never locked, so [body]/[media] populate normally.
     */
    val sponsored: SponsoredInfo? = null,
) {
    val isLocked: Boolean get() = paywall is Paywall.Locked
}

/**
 * ADV-105 — the paid-unit payload for a sponsored feed row. [creativeId]/[campaignId]/[accountId]
 * identify the ad for billing; [adClickId] is the per-serve CPA id (ADV-103). [surface]/[slotType]/
 * [creatorId]/[contentId] round-trip back to /ui/ads/track unchanged (ADV-106).
 */
data class SponsoredInfo(
    val label: String,
    val headline: String?,
    val ctaText: String?,
    val ctaUrl: String?,
    val adClickId: String?,
    val creativeId: String,
    val campaignId: String,
    val accountId: String,
    val surface: String,
    val slotType: String,
    val creatorId: String,
    val contentId: String,
)

/** #3 — raw lock info used to badge a locked post on its AUTHOR's own (un-redacted) view. */
data class AuthorLock(
    val priceCents: Int?,
    val lockType: LockType,
)

/** One page of feed posts + the opaque cursor for the next page (null = terminal). */
data class FeedPage(
    val posts: List<FeedPost>,
    val nextCursor: String?,
)

enum class MediaType { IMAGE, VIDEO, UNKNOWN }

data class Media(
    /** Stable key: image url or video_id. */
    val id: String,
    val type: MediaType,
    /** Image url, or video thumbnail/hls. */
    val url: String?,
    /** Video poster (for VIDEO items); null for images. */
    val thumbnailUrl: String? = null,
    /** Video length in seconds; null for images / unknown. */
    val durationSeconds: Long? = null,
    /**
     * #2 — the ready-to-play video URL (hls_manifest_url with the short-lived playback token already
     * appended, "?token=..."). Non-null only for a playable VIDEO item; the feed video cell builds an
     * ExoPlayer source from this. Null for images / a video missing a manifest.
     */
    val playbackUrl: String? = null,
)

enum class LockType { FIXED_PRICE, TIP_LOTTERY, UNKNOWN }

/** Paywall state. [Unlocked] covers never-locked, already-unlocked, and purchased posts. */
sealed interface Paywall {
    data object Unlocked : Paywall
    data class Locked(
        val lockType: LockType,
        /** unlock_price_cents (cents, USD assumed by the UI); null => generic CTA. */
        val priceCents: Int?,
        val unlockCount: Int?,
        val unlockLimit: Int?,
        val unlockLimitReached: Boolean,
        val lockExpired: Boolean,
    ) : Paywall
}

// ---- Mapping (pure, side-effect free) ----

internal fun FeedPageDto.toDomain(): FeedPage = FeedPage(
    posts = items.map { it.toDomain() },
    nextCursor = nextCursor,
)

internal fun PostDto.toDomain(): FeedPost {
    val paywall = toPaywall()
    val locked = paywall is Paywall.Locked
    return FeedPost(
        id = postId,
        authorId = authorId,
        createdAtEpochSeconds = parseIsoToEpochSeconds(createdAt),
        body = if (locked) null else (bodyPlain ?: body)?.takeIf { it.isNotBlank() },
        media = if (locked) emptyList() else toMedia(),
        tags = if (locked) emptyList() else tags.orEmpty(),
        likeCount = likeCount,
        commentCount = commentCount,
        likedByMe = likedByMe,
        groupId = groupId?.takeIf { it.isNotBlank() },
        reactions = reactionTallies(reactionsCounts, myReactions),
        paywall = paywall,
        // Polls are content, not protected media: only surface when the post is not locked.
        poll = if (locked) null else toPoll(),
        // #3 — surface the raw lock (price + type) whenever the post itself is locked, even if THIS
        // viewer sees it unlocked (the author, or a paid viewer). The UI shows the badge only on the
        // author's own post.
        authorLock = if (this.locked) {
            AuthorLock(
                priceCents = unlockPriceCents,
                lockType = when (lockType) {
                    "fixed_price" -> LockType.FIXED_PRICE
                    "tip_lottery" -> LockType.TIP_LOTTERY
                    else -> if ((unlockPriceCents ?: 0) > 0) LockType.FIXED_PRICE else LockType.UNKNOWN
                },
            )
        } else {
            null
        },
        sponsored = toSponsored(),
    )
}

/**
 * ADV-105 — build [SponsoredInfo] when the wire post is a sponsored unit. Requires the creative + the
 * campaign id (a sponsored row without them can't be rendered/tracked, so it degrades to a plain post).
 * surface/slot_type/creator_id/content_id fall back to the newsfeed sponsored-slot constants so the
 * track call is always well-formed even if an older server omits them.
 */
internal fun PostDto.toSponsored(): SponsoredInfo? {
    if (!isSponsored) return null
    val creative = creativeId?.takeIf { it.isNotBlank() } ?: return null
    val campaign = campaignId?.takeIf { it.isNotBlank() } ?: return null
    return SponsoredInfo(
        label = sponsorLabel?.takeIf { it.isNotBlank() } ?: "Sponsored",
        headline = headline?.takeIf { it.isNotBlank() },
        ctaText = ctaText?.takeIf { it.isNotBlank() },
        ctaUrl = ctaUrl?.takeIf { it.isNotBlank() },
        adClickId = adClickId?.takeIf { it.isNotBlank() },
        creativeId = creative,
        campaignId = campaign,
        accountId = accountId?.takeIf { it.isNotBlank() } ?: "",
        surface = surface?.takeIf { it.isNotBlank() } ?: "newsfeed",
        slotType = slotType?.takeIf { it.isNotBlank() } ?: "sponsored_post",
        creatorId = creatorId?.takeIf { it.isNotBlank() } ?: "platform",
        contentId = contentId?.takeIf { it.isNotBlank() } ?: postId,
    )
}

/**
 * Effective-locked predicate mirrors web `isLocked = !!post.locked && !post.unlocked`. Not effectively
 * locked => [Paywall.Unlocked] (never-locked, unlocked, or purchased). A non-lottery locked post that
 * has a price but no/unknown lock_type is treated as FIXED_PRICE (web parity).
 */
internal fun PostDto.toPaywall(): Paywall {
    val effectivelyLocked = locked && !unlocked
    if (!effectivelyLocked) return Paywall.Unlocked
    val type = when (lockType) {
        "fixed_price" -> LockType.FIXED_PRICE
        "tip_lottery" -> LockType.TIP_LOTTERY
        else -> if ((unlockPriceCents ?: 0) > 0) LockType.FIXED_PRICE else LockType.UNKNOWN
    }
    return Paywall.Locked(
        lockType = type,
        priceCents = unlockPriceCents,
        unlockCount = unlockCount,
        unlockLimit = unlockLimit,
        unlockLimitReached = unlockLimitReached == true,
        lockExpired = lockExpired == true,
    )
}

/**
 * Builds [Media] from image_urls (IMAGE) + ALL attached videos (VIDEO keyed on video_id). #2
 * (B-FEEDMEDIA): a post may carry MULTIPLE videos plus images (mixed media). The authoritative source is
 * the `videos[]` array; the legacy single `video` is merged in (and de-duped by video_id) for back-compat
 * with older posts/servers. Videos render after images, preserving the array order.
 */
internal fun PostDto.toMedia(): List<Media> {
    val images = imageUrls.orEmpty().mapNotNull { url ->
        url.takeIf { it.isNotBlank() }?.let { Media(id = it, type = MediaType.IMAGE, url = it) }
    }
    // Merge legacy single `video` first (it is `videos[0]` server-side), then the full array; de-dup.
    val videoDtos = buildList {
        video?.let { add(it) }
        videos.orEmpty().forEach { add(it) }
    }.distinctBy { it.videoId }
    val videoItems = videoDtos.map { v ->
        Media(
            id = v.videoId,
            type = MediaType.VIDEO,
            url = v.hlsManifestUrl ?: v.thumbnailUrl,
            thumbnailUrl = v.thumbnailUrl,
            durationSeconds = v.durationSeconds,
            // #2 — append the short-lived playback token to the manifest (web/messaging parity:
            // "${url}?token=${token}", "&" if a query already exists). Mock-S3 ignores the query
            // in dev (token is null), so this is the raw object url the player can fetch directly.
            playbackUrl = v.hlsManifestUrl?.let { base ->
                val tok = v.playbackToken?.takeIf { it.isNotBlank() }
                if (tok == null) base else base + (if (base.contains('?')) "&" else "?") + "token=" + tok
            },
        )
    }
    return images + videoItems
}

/**
 * Parses an ISO-8601 instant (e.g. "2026-06-04T18:22:10Z" or with millis / offset) to epoch SECONDS
 * WITHOUT java.time (minSdk24 / JVM-unit-test safe). On any failure returns 0L (epoch) rather than
 * throwing, so one bad timestamp never drops a whole page.
 */
internal fun parseIsoToEpochSeconds(iso: String?): Long {
    if (iso.isNullOrBlank()) return 0L
    return try {
        // Normalize fractional seconds and timezone designator to a form SimpleDateFormat handles.
        var s = iso.trim()
        // Strip fractional seconds (".123") — we only need second precision.
        val dotIdx = s.indexOf('.')
        if (dotIdx >= 0) {
            var end = dotIdx + 1
            while (end < s.length && s[end].isDigit()) end++
            s = s.substring(0, dotIdx) + s.substring(end)
        }
        val tz: String
        val core: String
        when {
            s.endsWith("Z") -> {
                core = s.dropLast(1)
                tz = "UTC"
            }
            else -> {
                // Handle a trailing +HH:MM / -HH:MM offset. Search AFTER the date ("yyyy-MM-dd",
                // length 10) so the date's own '-' separators are never mistaken for an offset.
                val timePart = if (s.length > 10) s.substring(11) else ""
                val rel = timePart.indexOfFirst { it == '+' || it == '-' }
                if (rel >= 0) {
                    val offsetIdx = 11 + rel
                    core = s.substring(0, offsetIdx)
                    tz = "GMT" + s.substring(offsetIdx)
                } else {
                    core = s
                    tz = "UTC"
                }
            }
        }
        val fmt = java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss", java.util.Locale.US)
        fmt.timeZone = java.util.TimeZone.getTimeZone(tz)
        fmt.isLenient = false
        val date = fmt.parse(core) ?: return 0L
        date.time / 1000L
    } catch (_: Exception) {
        0L
    }
}
