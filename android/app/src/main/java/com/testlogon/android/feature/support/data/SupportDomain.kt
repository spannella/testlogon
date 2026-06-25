package com.testlogon.android.feature.support.data

import com.testlogon.android.core.network.support.SupportAdminSummaryDto
import com.testlogon.android.core.network.support.SupportTicketDto
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
}

data class SupportTicketMessage(
    val messageId: String,
    val senderSub: String,
    val senderRole: String,
    val body: String,
    val createdAt: Long,
) {
    val isFromAdmin: Boolean get() = senderRole.equals("admin", ignoreCase = true)
}

data class SupportAdminSummary(
    val byStatus: Map<String, Int>,
    val unassignedCount: Int,
    val staleCount: Int,
    val totalCount: Int,
)

fun SupportTicketMessageDto.toDomain(): SupportTicketMessage = SupportTicketMessage(
    messageId = messageId.orEmpty(),
    senderSub = senderSub.orEmpty(),
    senderRole = senderRole.orEmpty(),
    body = body.orEmpty(),
    createdAt = createdAt ?: 0L,
)

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
