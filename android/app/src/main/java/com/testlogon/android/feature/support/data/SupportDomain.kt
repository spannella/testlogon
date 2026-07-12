package com.testlogon.android.feature.support.data

import com.testlogon.android.core.network.support.SupportAdminSummaryDto
import com.testlogon.android.core.network.support.SupportTicketDto
import com.testlogon.android.core.network.support.SupportTicketMediaDto
import com.testlogon.android.core.network.support.SupportTicketMessageDto

/**
 * B-SUP (batch 7) — domain models for the role-aware Support surface. Kept deliberately small; the screens
 * read these directly.
 */

/** A support ticket's lifecycle status. UNKNOWN tolerates a server value the client doesn't model. */
enum class SupportTicketStatus(val wire: String) {
    OPEN("open"),
    IN_PROGRESS("in_progress"),
    WAITING_ON_USER("waiting_on_user"),
    DONE("done"),
    REOPENED("reopened"),
    CANCELLED("cancelled"),
    UNKNOWN("");

    companion object {
        fun from(value: String?): SupportTicketStatus =
            entries.firstOrNull { it.wire == value } ?: UNKNOWN
    }
}

data class SupportTicket(
    val ticketId: String,
    val subject: String,
    val ownerSub: String,
    val status: SupportTicketStatus,
    val rawStatus: String,
    val priority: String?,
    val caseNumber: String?,
    val assignedAdminSub: String?,
    val createdAt: Long,
    val updatedAt: Long,
    val messages: List<SupportTicketMessage>,
) {
    val isAssigned: Boolean get() = !assignedAdminSub.isNullOrBlank()
    val lastMessagePreview: String? get() = messages.lastOrNull()?.body
    /** B8 #15 — a terminal ticket (resolved/cancelled) hides the user close/cancel action. */
    val isTerminal: Boolean
        get() = status == SupportTicketStatus.DONE || status == SupportTicketStatus.CANCELLED
}



/**
 * B10 B-HELPMEDIA #5 — the kind of one media/attachment item on a ticket message. UNKNOWN tolerates a
 * server value the client doesn't model (rendered as a generic file row).
 */
enum class SupportMediaKind(val wire: String) {
    IMAGE("image"),
    VIDEO("video"),
    FILE("file"),
    FILE_REF("file_ref"),
    UNKNOWN("");

    companion object {
        fun from(value: String?): SupportMediaKind =
            entries.firstOrNull { it.wire == value } ?: UNKNOWN
    }
}

/**
 * B10 B-HELPMEDIA #5 — one rendered media/attachment on a ticket message. [url] is a platform upload URL
 * (image/video/file); [path] is a file-manager VFS path (file_ref). The server resolves a file_ref's
 * name / contentType / sizeBytes / thumbnail on read, so those are populated for both kinds where known.
 */
data class SupportMediaItem(
    val kind: SupportMediaKind,
    val url: String? = null,
    val path: String? = null,
    val name: String? = null,
    val contentType: String? = null,
    val sizeBytes: Long? = null,
    val width: Int? = null,
    val height: Int? = null,
    val thumbnail: String? = null,
) {
    /** True when this item should render as an inline image (an image upload or an image file_ref). */
    val isImage: Boolean
        get() = kind == SupportMediaKind.IMAGE ||
            (contentType?.startsWith("image/") == true)

    /** True when this item is a playable/openable video. */
    val isVideo: Boolean
        get() = kind == SupportMediaKind.VIDEO ||
            (contentType?.startsWith("video/") == true)

    /** A best-effort URL for displaying/opening this item (the upload URL, or a file_ref thumbnail). */
    val displayUrl: String? get() = url ?: thumbnail

    /** A human label for a file/video row (falls back to the trailing path segment, else a generic). */
    val displayName: String
        get() = name
            ?: path?.substringAfterLast('/')?.takeIf { it.isNotBlank() }
            ?: url?.substringAfterLast('/')?.substringBefore('?')?.takeIf { it.isNotBlank() }
            ?: when {
                isVideo -> "Video"
                kind == SupportMediaKind.IMAGE -> "Image"
                else -> "Attachment"
            }
}

data class SupportTicketMessage(
    val messageId: String,
    val senderSub: String,
    val senderRole: String,
    val body: String,
    val createdAt: Long,
    /** Helpdesk #14 — an image attached to this message (rendered in the thread), or null. */
    val imageUrl: String? = null,
    /** B10 B-HELPMEDIA #5 — the ordered media/attachment list on this message (may be empty). */
    val media: List<SupportMediaItem> = emptyList(),
) {
    val isFromAdmin: Boolean get() = senderRole.equals("admin", ignoreCase = true)
}

data class SupportAdminSummary(
    val byStatus: Map<String, Int>,
    val unassignedCount: Int,
    val staleCount: Int,
    val totalCount: Int,
)

fun SupportTicketMediaDto.toDomain(): SupportMediaItem = SupportMediaItem(
    kind = SupportMediaKind.from(kind),
    url = url?.takeIf { it.isNotBlank() },
    path = path?.takeIf { it.isNotBlank() },
    name = name?.takeIf { it.isNotBlank() },
    contentType = contentType?.takeIf { it.isNotBlank() },
    sizeBytes = sizeBytes,
    width = width,
    height = height,
    thumbnail = thumbnail?.takeIf { it.isNotBlank() },
)

fun SupportTicketMessageDto.toDomain(): SupportTicketMessage {
    val legacyImage = imageUrl?.takeIf { it.isNotBlank() }
    // B10 B-HELPMEDIA #5 — unify the legacy single image_url and the new media[] into ONE render list,
    // de-duping the legacy image if it is already present as an image item in media[].
    val items = (media.orEmpty()).map { it.toDomain() }
    val mergedMedia = if (legacyImage != null && items.none { it.url == legacyImage }) {
        listOf(SupportMediaItem(kind = SupportMediaKind.IMAGE, url = legacyImage)) + items
    } else {
        items
    }
    return SupportTicketMessage(
        messageId = messageId.orEmpty(),
        senderSub = senderSub.orEmpty(),
        senderRole = senderRole.orEmpty(),
        body = body.orEmpty(),
        createdAt = createdAt ?: 0L,
        imageUrl = legacyImage,
        media = mergedMedia,
    )
}

fun SupportTicketDto.toDomain(): SupportTicket = SupportTicket(
    ticketId = ticketId.orEmpty(),
    subject = subject.orEmpty(),
    ownerSub = ownerSub.orEmpty(),
    status = SupportTicketStatus.from(status),
    rawStatus = status.orEmpty(),
    priority = priority,
    caseNumber = caseNumber,
    assignedAdminSub = assignedAdminSub,
    createdAt = createdAt ?: 0L,
    updatedAt = updatedAt ?: 0L,
    messages = messages.map { it.toDomain() },
)

fun SupportAdminSummaryDto.toDomain(): SupportAdminSummary = SupportAdminSummary(
    byStatus = byStatus,
    unassignedCount = unassignedCount,
    staleCount = staleCount,
    totalCount = totalCount,
)
