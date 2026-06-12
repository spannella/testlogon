package com.testlogon.android.data.broadcast

import java.time.Instant
import java.time.format.DateTimeParseException

/**
 * AND-278 — pure DTO -> domain mappers. Side-effect-free; never throw on recoverable shape variance:
 *  - unknown / absent `status` -> [BroadcastSessionStatus.UNKNOWN];
 *  - absent optionals fall back to null / defaults;
 *  - absent `cloudfront_playback_url` on a LIVE session -> null playbackUrl (no fabricated URL, R-2);
 *  - unparseable ISO timestamps degrade to null (createdAt/updatedAt fall back to Instant.EPOCH so the
 *    domain's non-null contract holds rather than throwing);
 *  - `scheduled_at` / `expires_at` are epoch-SECOND integers (Instant.ofEpochSecond), NOT ISO strings.
 */

internal fun parseInstantOrNull(value: String?): Instant? {
    if (value.isNullOrBlank()) return null
    return try {
        Instant.parse(value)
    } catch (_: DateTimeParseException) {
        null
    }
}

internal fun Long?.epochSecondToInstant(): Instant? = this?.let { Instant.ofEpochSecond(it) }

internal fun String?.toBroadcastStatus(): BroadcastSessionStatus = when (this?.lowercase()) {
    "draft" -> BroadcastSessionStatus.DRAFT
    "scheduled" -> BroadcastSessionStatus.SCHEDULED
    "provisioning" -> BroadcastSessionStatus.PROVISIONING
    "ready" -> BroadcastSessionStatus.READY
    "live" -> BroadcastSessionStatus.LIVE
    "stopping" -> BroadcastSessionStatus.STOPPING
    "stopped" -> BroadcastSessionStatus.STOPPED
    "cancelled", "canceled" -> BroadcastSessionStatus.CANCELLED
    "error" -> BroadcastSessionStatus.ERROR
    else -> BroadcastSessionStatus.UNKNOWN
}

fun BroadcastSessionDto.toDomain(): BroadcastSession = BroadcastSession(
    id = id,
    profileId = profileId,
    name = name,
    description = description,
    status = status.toBroadcastStatus(),
    createdBy = createdBy,
    scheduledAt = scheduledAt.epochSecondToInstant(),
    scheduleStatus = scheduleStatus,
    startedAt = parseInstantOrNull(startedAt),
    stoppedAt = parseInstantOrNull(stoppedAt),
    cancelledAt = parseInstantOrNull(cancelledAt),
    playbackUrl = cloudfrontPlaybackUrl,
    thumbnailUrl = thumbnailUrl,
    tipTotalCents = tipTotalCents,
    tipCount = tipCount,
    createdAt = parseInstantOrNull(createdAt) ?: Instant.EPOCH,
    updatedAt = parseInstantOrNull(updatedAt) ?: Instant.EPOCH,
)

fun BroadcastSessionListRespDto.toDomain(): BroadcastSessionPage =
    BroadcastSessionPage(items = items.map { it.toDomain() }, hasMore = hasMore)

fun BroadcastScheduledListRespDto.toDomain(): BroadcastScheduledPage =
    BroadcastScheduledPage(items = items.map { it.toDomain() }, count = count)

fun BroadcastPlaybackUrlDto.toDomain(): BroadcastPlaybackUrl = BroadcastPlaybackUrl(
    sessionId = sessionId,
    playbackUrl = playbackUrl,
    expiresAt = Instant.ofEpochSecond(expiresAt),
)
