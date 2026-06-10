package com.testlogon.android.data.clips

import kotlin.math.roundToInt

/**
 * AND-196 — domain models + DTO mappers + pure status helpers for the Clips feature.
 *
 * Pure data + pure mapping (no Android / Media3 / java.time types) so it is fully JVM-unit-testable.
 * A clip references a source [videoId] + a [thumbnailUrl]; it carries NO stream URL (the playable HLS
 * is resolved separately from the source video's detail — see ClipsRepository). [durationSeconds] is a
 * float-seconds value rounded for the badge.
 */

/** A clip's processing lifecycle (verified ClipOut.status enum). Unknown strings normalize to FAILED. */
enum class ClipStatus {
    PROCESSING,
    READY,
    FAILED,
    DELETED,
    ;

    companion object {
        /** Maps the free-form server string to the enum; an unrecognized value is treated as FAILED. */
        fun from(raw: String): ClipStatus = when (raw.trim().lowercase()) {
            "processing" -> PROCESSING
            "ready" -> READY
            "deleted" -> DELETED
            else -> FAILED
        }
    }
}

/**
 * AND-196 — the clip domain model. [broadcasterDisplayName]/[profileId] are populated only for a public
 * clip (PublicClipOut); they are blank for the authed gallery/single shapes. [isPlayable] is true only
 * for a READY clip with a source [videoId] from which a stream URL can be resolved.
 */
data class Clip(
    val clipId: String,
    val sessionId: String,
    val videoId: String,
    val creatorUserId: String,
    val creatorDisplayName: String,
    val broadcasterUserId: String,
    val title: String,
    val startSeconds: Double,
    val endSeconds: Double,
    val durationSeconds: Double,
    val status: ClipStatus,
    val viewCount: Int,
    val shareCount: Int,
    val thumbnailUrl: String?,
    val createdAtEpochSeconds: Long,
    // Public-only attribution (blank for authed shapes).
    val broadcasterDisplayName: String = "",
    val profileId: String = "",
) {
    /** Rounded duration in whole seconds for the mm:ss badge (null when non-positive). */
    val durationSec: Int? get() = durationSeconds.takeIf { it > 0.0 }?.roundToInt()

    /** True when the clip is READY and has a source video to resolve a stream URL from. */
    val isPlayable: Boolean get() = status == ClipStatus.READY && videoId.isNotBlank()

    /** True while the clip is still being cut/encoded server-side; render a poster, not the player. */
    val isProcessing: Boolean get() = status == ClipStatus.PROCESSING
}

/** One cursor-paged clips feed page. [nextCursor] is null/absent on the terminal page. */
data class ClipsPage(
    val items: List<Clip>,
    val nextCursor: String?,
)

// ---- Mappers ----

fun ClipDto.toDomain(): Clip = Clip(
    clipId = clipId,
    sessionId = sessionId,
    videoId = videoId,
    creatorUserId = creatorUserId,
    creatorDisplayName = creatorDisplayName,
    broadcasterUserId = broadcasterUserId,
    title = title,
    startSeconds = startSeconds,
    endSeconds = endSeconds,
    durationSeconds = durationSeconds,
    status = ClipStatus.from(status),
    viewCount = viewCount,
    shareCount = shareCount,
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    createdAtEpochSeconds = createdAt,
)

fun PublicClipDto.toDomain(): Clip = Clip(
    clipId = clipId,
    sessionId = sessionId,
    videoId = videoId,
    creatorUserId = creatorUserId,
    creatorDisplayName = creatorDisplayName,
    broadcasterUserId = broadcasterUserId,
    title = title,
    startSeconds = startSeconds,
    endSeconds = endSeconds,
    durationSeconds = durationSeconds,
    status = ClipStatus.from(status),
    viewCount = viewCount,
    shareCount = shareCount,
    thumbnailUrl = thumbnailUrl?.takeIf { it.isNotBlank() },
    createdAtEpochSeconds = createdAt,
    broadcasterDisplayName = broadcasterDisplayName,
    profileId = profileId,
)

fun ClipListResponseDto.toDomain(): ClipsPage = ClipsPage(
    // Drop malformed rows (blank clip_id) defensively rather than failing the whole page.
    items = clips.asSequence().filter { it.clipId.isNotBlank() }.map { it.toDomain() }.toList(),
    nextCursor = nextCursor,
)
