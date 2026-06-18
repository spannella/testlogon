package com.testlogon.android.data.ideas

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free product-ideas domain models + total DTO -> domain mappers.
 *
 * [Idea.createdAtSeconds] / [Idea.updatedAtSeconds] are epoch-seconds timestamps; mapping is total
 * (absent optionals default per the schema). [IdeaStatus] folds the server string into a closed enum
 * (+ UNKNOWN). Time formatting uses SimpleDateFormat/Date (core-library desugaring is off, so java.time
 * is unavailable) and stays JVM-unit-testable.
 */
enum class IdeaStatus {
    SUBMITTED,
    TRIAGING,
    ACCEPTED,
    REJECTED,
    CONVERTED,
    UNKNOWN;

    companion object {
        fun from(raw: String?): IdeaStatus = when (raw?.lowercase(Locale.US)) {
            "submitted" -> SUBMITTED
            "triaging" -> TRIAGING
            "accepted" -> ACCEPTED
            "rejected" -> REJECTED
            "converted" -> CONVERTED
            else -> UNKNOWN
        }
    }
}

data class Idea(
    val id: String,
    val title: String,
    val description: String,
    val status: IdeaStatus,
    val prioritySuggestion: String?,
    val rejectionReason: String?,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
) {
    /** Human-readable submission date, e.g. "Jun 17, 2026". */
    fun formattedCreated(): String =
        if (createdAtSeconds <= 0L) "" else DATE_FORMAT.format(Date(createdAtSeconds * 1000L))

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    }
}

data class IdeasPage(
    val ideas: List<Idea>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = ideas.isEmpty()
}

// ---- Mappers (DTO -> domain) ----

internal fun IdeaDto.toDomain(): Idea = Idea(
    id = ideaId,
    title = title,
    description = description,
    status = IdeaStatus.from(status),
    prioritySuggestion = prioritySuggestion?.takeIf { it.isNotBlank() },
    rejectionReason = rejectionReason?.takeIf { it.isNotBlank() },
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
)

internal fun IdeaListDto.toDomain(): IdeasPage = IdeasPage(
    ideas = ideas.map { it.toDomain() },
    nextCursor = nextCursor,
)
