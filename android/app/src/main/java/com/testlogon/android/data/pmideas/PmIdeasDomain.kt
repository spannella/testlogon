package com.testlogon.android.data.pmideas

import java.util.Locale

/**
 * Framework-free PM-idea triage domain models + total DTO -> domain mappers.
 *
 * Mirrors the web FeatureIdeasPage (pending / approved / rejected / archived tabs + approve/reject/
 * archive). Enum folds keep the UI resilient to unknown server values; [canTriage] gates the row
 * actions to `pending` ideas exactly like the web.
 */
enum class PmIdeaStatus {
    PENDING, APPROVED, REJECTED, ARCHIVED, UNKNOWN;

    val serverValue: String get() = name.lowercase(Locale.US)

    companion object {
        fun from(raw: String?): PmIdeaStatus = when (raw?.lowercase(Locale.US)) {
            "pending" -> PENDING
            "approved" -> APPROVED
            "rejected" -> REJECTED
            "archived" -> ARCHIVED
            else -> UNKNOWN
        }
    }
}

data class PmIdea(
    val id: String,
    val title: String,
    val description: String,
    val category: String,
    val prioritySuggestion: String,
    val userImpact: String,
    val mockupDescription: String?,
    val status: PmIdeaStatus,
    val rejectionReason: String?,
    val createdTicketId: String?,
) {
    val canTriage: Boolean get() = status == PmIdeaStatus.PENDING
}

data class PmIdeasPage(
    val ideas: List<PmIdea>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = ideas.isEmpty()
}

// ---- Mappers (DTO -> domain) ----

internal fun FeatureIdeaDto.toDomain(): PmIdea = PmIdea(
    id = ideaId,
    title = title,
    description = description,
    category = category,
    prioritySuggestion = prioritySuggestion,
    userImpact = userImpact,
    mockupDescription = mockupDescription?.takeIf { it.isNotBlank() },
    status = PmIdeaStatus.from(status),
    rejectionReason = rejectionReason?.takeIf { it.isNotBlank() },
    createdTicketId = createdTicketId?.takeIf { it.isNotBlank() },
)

internal fun FeatureIdeaListDto.toDomain(): PmIdeasPage = PmIdeasPage(
    ideas = ideas.map { it.toDomain() },
    nextCursor = nextCursor,
)
