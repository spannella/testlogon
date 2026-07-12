package com.testlogon.android.data.appeals

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free appeals domain models + total DTO -> domain mappers.
 *
 * [Appeal.createdAtSeconds] / [Appeal.decidedAtSeconds] are epoch-seconds timestamps; mapping is total
 * (absent optionals default per the schema). [AppealStatus] folds the server string into a closed enum
 * (+ UNKNOWN); [Appeal.canWithdraw] is true only while submitted / under review. Time formatting uses
 * SimpleDateFormat/Date (core-library desugaring is off, so java.time is unavailable) and stays
 * JVM-unit-testable.
 */
enum class AppealStatus {
    SUBMITTED,
    UNDER_REVIEW,
    UPHELD,
    MODIFIED,
    REVERSED,
    WITHDRAWN,
    UNKNOWN;

    val isDecided: Boolean
        get() = this == UPHELD || this == MODIFIED || this == REVERSED

    companion object {
        fun from(raw: String?): AppealStatus = when (raw?.lowercase(Locale.US)) {
            "submitted" -> SUBMITTED
            "under_review" -> UNDER_REVIEW
            "upheld" -> UPHELD
            "modified" -> MODIFIED
            "reversed" -> REVERSED
            "withdrawn" -> WITHDRAWN
            else -> UNKNOWN
        }
    }
}

data class Appeal(
    val id: String,
    val enforcementId: String,
    val enforcementType: String?,
    val sourceTicketId: String?,
    val appealText: String,
    val status: AppealStatus,
    val createdAtSeconds: Long,
    val updatedAtSeconds: Long,
    val decidedAtSeconds: Long?,
    val decisionNote: String?,
    val modifiedEnforcementType: String?,
    val modifiedDurationDays: Int?,
) {
    /** Submitted / under-review appeals may still be withdrawn by the member. */
    val canWithdraw: Boolean
        get() = status == AppealStatus.SUBMITTED || status == AppealStatus.UNDER_REVIEW

    val hasDecision: Boolean
        get() = status.isDecided && !decisionNote.isNullOrBlank()

    /** Human-readable submission date, e.g. "Jun 17, 2026". */
    fun formattedCreated(): String =
        if (createdAtSeconds <= 0L) "" else DATE_FORMAT.format(Date(createdAtSeconds * 1000L))

    /** Human-readable decision date, blank when undecided. */
    fun formattedDecided(): String =
        decidedAtSeconds?.takeIf { it > 0L }?.let { DATE_FORMAT.format(Date(it * 1000L)) } ?: ""

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    }
}

data class AppealsPage(
    val appeals: List<Appeal>,
    val nextCursor: String?,
) {
    val isEmpty: Boolean get() = appeals.isEmpty()
}

// ---- Mappers (DTO -> domain) ----

internal fun AppealDto.toDomain(): Appeal = Appeal(
    id = appealId,
    enforcementId = enforcementId,
    enforcementType = enforcementType?.takeIf { it.isNotBlank() },
    sourceTicketId = sourceTicketId?.takeIf { it.isNotBlank() },
    appealText = appealText,
    status = AppealStatus.from(status),
    createdAtSeconds = createdAt,
    updatedAtSeconds = updatedAt,
    decidedAtSeconds = decidedAt,
    decisionNote = decisionNote?.takeIf { it.isNotBlank() },
    modifiedEnforcementType = modifiedEnforcementType?.takeIf { it.isNotBlank() },
    modifiedDurationDays = modifiedDurationDays,
)

internal fun AppealListDto.toDomain(): AppealsPage = AppealsPage(
    appeals = items.map { it.toDomain() },
    nextCursor = nextCursor,
)
