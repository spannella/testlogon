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
    /** Never null at domain level; derived from the flat lock fields. */
    val paywall: Paywall,
) {
    val isLocked: Boolean get() = paywall is Paywall.Locked
}

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
        paywall = paywall,
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

/** Builds [Media] from image_urls (IMAGE) + a single video (VIDEO keyed on video_id). */
internal fun PostDto.toMedia(): List<Media> {
    val images = imageUrls.orEmpty().mapNotNull { url ->
        url.takeIf { it.isNotBlank() }?.let { Media(id = it, type = MediaType.IMAGE, url = it) }
    }
    val videoItem = video?.let { v ->
        Media(
            id = v.videoId,
            type = MediaType.VIDEO,
            url = v.hlsManifestUrl ?: v.thumbnailUrl,
            thumbnailUrl = v.thumbnailUrl,
            durationSeconds = v.durationSeconds,
        )
    }
    return if (videoItem != null) images + videoItem else images
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
