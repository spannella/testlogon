package com.testlogon.android.feature.share.model

import com.testlogon.android.core.model.files.PublicShareDto
import com.testlogon.android.core.model.files.ShareLinkOutDto
import java.time.Instant

/**
 * AND-335 - domain models + DTO -> domain mappers for shareable file links.
 *
 * The transport DTOs (core-model ShareDtos.kt) carry epoch-millis timestamps and loose boolean flags;
 * these mappers convert epoch -> [Instant] and DERIVE the terminal [PublicShareState] from the public
 * flags. Mapping happens BEFORE the typed ApiResult is produced in ShareRepository, so the rest of the
 * app never sees a raw DTO.
 */

/** An owner-visible share link (mapped from [ShareLinkOutDto]). */
data class ShareLink(
    val linkId: String,
    val fileNodeId: String?,
    val shareUrl: String,
    val expiresAt: Instant?,
    val maxDownloads: Int?,
    val downloadCount: Int?,
    val passwordProtected: Boolean,
    val createdAt: Instant?,
    val revoked: Boolean,
)

/** Owner-chosen options for a new link. Validated in ShareRepository before the request is built. */
data class ShareLinkOptions(
    val expiryHours: Int,
    val maxDownloads: Int,
    val password: String?,
)

/** The terminal/available state of a public link, derived from the public info flags. */
enum class PublicShareState {
    AVAILABLE,
    EXPIRED,
    REVOKED,
    EXHAUSTED,
    UNAVAILABLE,
}

/** A recipient-visible public share (mapped from [PublicShareDto]; state derived from flags). */
data class PublicShare(
    val linkId: String,
    val fileName: String?,
    val sizeBytes: Long?,
    val contentType: String?,
    val expiresAt: Instant?,
    val passwordRequired: Boolean,
    val state: PublicShareState,
)

/** Maps an epoch-millis Long to an [Instant] (null passes through). */
private fun epochMillisToInstant(value: Long?): Instant? =
    value?.let { Instant.ofEpochMilli(it) }

/** Maps a [ShareLinkOutDto] to its [ShareLink] domain model (epoch -> Instant; revoked defaults false). */
fun ShareLinkOutDto.toDomain(): ShareLink = ShareLink(
    linkId = link_id,
    fileNodeId = file_node_id,
    shareUrl = share_url,
    expiresAt = epochMillisToInstant(expires_at),
    maxDownloads = max_downloads,
    downloadCount = download_count,
    passwordProtected = password_protected,
    createdAt = epochMillisToInstant(created_at),
    revoked = revoked ?: false,
)

/**
 * Maps a [PublicShareDto] to its [PublicShare] domain model. The terminal [PublicShareState] is DERIVED
 * from the flags with a fixed precedence: revoked, then expired, then used/exhausted, else available. The
 * UNAVAILABLE state is reserved for callers that cannot resolve a link at all (e.g. a 404).
 *
 * AND-392 CORRECTED CONTRACT: the verified `ShareLinkPublicInfoOut` carries `file_size_bytes`,
 * `requires_password`, `is_revoked` / `is_expired` / `is_used` (the consumed / download-limit case) and
 * `remaining_downloads`. This mapper PREFERS those corrected fields and falls back to the AND-335 legacy
 * keys (`size`, `password_required`, `revoked` / `expired` / `exhausted`) so an older backend / the
 * existing fakes still resolve. `is_used` maps to EXHAUSTED (the same "no longer available" terminal the
 * web `unavailableMessage()` renders for the consumed / limit-reached case).
 */
fun PublicShareDto.toDomain(): PublicShare = PublicShare(
    linkId = link_id.orEmpty(),
    fileName = file_name,
    sizeBytes = file_size_bytes ?: size,
    contentType = content_type,
    expiresAt = epochMillisToInstant(expires_at),
    passwordRequired = requires_password || password_required,
    state = when {
        is_revoked || revoked == true -> PublicShareState.REVOKED
        is_expired || expired == true -> PublicShareState.EXPIRED
        is_used || exhausted == true -> PublicShareState.EXHAUSTED
        else -> PublicShareState.AVAILABLE
    },
)
