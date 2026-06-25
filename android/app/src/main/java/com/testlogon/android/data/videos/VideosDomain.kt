package com.testlogon.android.data.videos

import com.testlogon.android.feature.player.MediaSourceResolver
import kotlin.math.roundToInt

/**
 * AND-189 / AND-190 — domain models + DTO mappers for the Videos feature.
 *
 * Pure data + pure mapping (no Android / Media3 types) so it is fully JVM-unit-testable. The playable
 * URL is derived with the shared, JVM-tested [MediaSourceResolver.tokenizedManifestUrl] (AND-167) so
 * the `?token=` append rule lives in exactly one place.
 */

/**
 * AND-189 — a tile in the library/VOD grid. `durationSec` is rounded for the mm:ss badge.
 * `status` is the server-side pipeline state (probing/encoding/published/...) — drives the
 * "Processing"/"Ready" badge + open-gating on the My Videos screen. Blank for the VOD catalog
 * (which only ever returns playable titles).
 */
data class VideoSummary(
    val id: String,
    val title: String,
    val thumbnailUrl: String?,
    val durationSec: Int?,
    val status: String = "",
) {
    /** True while the asset is still being prepared server-side (no playable manifest yet). */
    val isProcessing: Boolean get() = status.isNotBlank() && status in VideoDetail.PROCESSING_STATUSES
}

/** AND-189 — one cursor-paged page of summaries. `cursor` is null/absent on the terminal page. */
data class VideoPage(
    val items: List<VideoSummary>,
    val cursor: String?,
)

/**
 * AND-190 — the full video-detail domain model. [playbackUrl] is the tokenized HLS manifest, or null
 * when either `hls_manifest_url` or `playback_token` is missing (→ no playable source). [isProcessing]
 * mirrors the web gate: the manifest is not ready while the video is still encoding/probing.
 */
data class VideoDetail(
    val id: String,
    val ownerUserId: String,
    val title: String,
    val description: String?,
    val status: String,
    val visibility: String,
    val durationSec: Int?,
    val thumbnailUrl: String?,
    val playbackUrl: String?,
    val publishedAtEpochSeconds: Long?,
    val reviewStatus: String?,
    val isEntitled: Boolean,
    val accessMode: String?,
    // AND-197 — flat pay-per-view / subscription gating fields (consumed by EntitlementResolver).
    val priceCentsOrNull: Int? = null,
    val purchaseAvailableOrFalse: Boolean = false,
    val subscriptionAvailableOrFalse: Boolean = false,
    val subscriptionUpsellOrFalse: Boolean = false,
) {
    /** True while the asset is still being prepared server-side; no manifest yet. */
    val isProcessing: Boolean get() = status in PROCESSING_STATUSES

    /** True when there is a usable HLS source to hand the player. */
    val isPlayable: Boolean get() = playbackUrl != null

    companion object {
        /** Statuses where playback must be gated (verified in VideoPlayerPage.tsx isProcessing). */
        val PROCESSING_STATUSES = setOf("created", "probing", "pending_encoding", "encoding")
    }
}

/**
 * AND-197 — the per-video access decision (mapped from VodAccessOut). Pure data (no Android types).
 * [reason] is carried verbatim for telemetry/debug but the entitlement resolver keys off [entitled] +
 * [accessMode] + the purchase/subscription flags, never [reason].
 */
data class VideoAccess(
    val entitled: Boolean,
    val reason: String,
    val accessMode: String?,
    val priceCents: Int?,
    val purchaseAvailable: Boolean,
    val subscriptionAvailable: Boolean,
    val subscriptionUpsell: Boolean,
    val expiresAtEpochSeconds: Long?,
    val viewsRemaining: Int,
)

// ---- Mappers ----

fun VodAccessDto.toDomain(): VideoAccess = VideoAccess(
    entitled = entitled,
    reason = reason,
    accessMode = accessMode?.takeIf { it.isNotBlank() },
    priceCents = priceCents,
    purchaseAvailable = purchaseAvailable,
    subscriptionAvailable = subscriptionAvailable,
    subscriptionUpsell = subscriptionUpsell,
    expiresAtEpochSeconds = expiresAt,
    viewsRemaining = viewsRemaining,
)

fun VideoListItemDto.toSummary(): VideoSummary = VideoSummary(
    id = videoId,
    title = title,
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    durationSec = durationSeconds?.takeIf { it > 0 }?.roundToInt(),
    status = status,
)

fun VideoListResponseDto.toDomain(): VideoPage = VideoPage(
    // Drop malformed rows (blank video_id) defensively rather than failing the whole page.
    items = items.asSequence().filter { it.videoId.isNotBlank() }.map { it.toSummary() }.toList(),
    cursor = cursor,
)

fun SimilarVideosResponseDto.toDomain(): List<VideoSummary> =
    videos.asSequence().filter { it.videoId.isNotBlank() }.map { it.toSummary() }.toList()

/** Builds the tokenized HLS URL, requiring BOTH a non-blank manifest and token (else null). */
internal fun resolvePlaybackUrl(manifestUrl: String?, playbackToken: String?): String? {
    val manifest = manifestUrl?.takeIf { it.isNotBlank() } ?: return null
    val token = playbackToken?.takeIf { it.isNotBlank() } ?: return null
    return MediaSourceResolver.tokenizedManifestUrl(manifest, token)
}

fun VideoDetailDto.toDomain(): VideoDetail = VideoDetail(
    id = videoId,
    ownerUserId = ownerUserId,
    title = title,
    description = description?.takeIf { it.isNotBlank() },
    status = status,
    visibility = visibility,
    durationSec = durationSeconds?.takeIf { it > 0 }?.roundToInt(),
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    // Web parity (VideoPlayerPage.tsx): BOTH hls_manifest_url AND playback_token must be present, else
    // there is no playable URL. The shared resolver appends the token; null inputs yield null here.
    playbackUrl = resolvePlaybackUrl(hlsManifestUrl, playbackToken),
    publishedAtEpochSeconds = publishedAt,
    reviewStatus = reviewStatus?.takeIf { it.isNotBlank() },
    isEntitled = isEntitled ?: true,
    accessMode = accessMode?.takeIf { it.isNotBlank() },
    priceCentsOrNull = priceCents,
    purchaseAvailableOrFalse = purchaseAvailable ?: false,
    subscriptionAvailableOrFalse = subscriptionAvailable ?: false,
    subscriptionUpsellOrFalse = subscriptionUpsell ?: false,
)
