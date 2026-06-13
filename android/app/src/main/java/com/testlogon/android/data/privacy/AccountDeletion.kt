package com.testlogon.android.data.privacy

/**
 * AND-386 - the domain view of the account-deletion state (spec §4).
 *
 * The server is the source of truth; the active vs pending distinction is derived from the deletion
 * requests list (the entry whose wire `status == "pending"`). [Active] is the empty / no-pending state.
 * All timestamps are epoch MILLISECONDS here (built from the wire epoch SECONDS * 1000); the wire never
 * sends ISO strings (spec §6 / §16 claim 9).
 */
sealed interface DeletionStatus {

    /** No pending deletion request - the account is active and a request can be initiated. */
    data object Active : DeletionStatus

    /**
     * A pending deletion request. [canCancel] gates the Cancel CTA (mirrors the web client, which
     * disables Cancel on `!can_cancel`). [scheduledForEpochMs] may be null -> render "soon".
     */
    data class Pending(
        val requestId: String,
        val createdAtEpochMs: Long,
        val scheduledForEpochMs: Long?,
        val graceDaysRemaining: Int?,
        val canCancel: Boolean,
    ) : DeletionStatus
}

/** AND-386 - the wire `status` value that marks the single active/pending deletion request. */
const val DELETION_STATUS_PENDING = "pending"

/** AND-386 - DTO -> domain mappers (kept in :app per the module contract). */

/** Epoch SECONDS -> epoch MILLISECONDS (null-tolerant). */
private fun Long?.deletionSecondsToMillis(): Long? = this?.let { it * 1000L }

/** Maps a pending [AccountDeletionStatusDto] to the [DeletionStatus.Pending] domain shape. */
fun AccountDeletionStatusDto.toPending(): DeletionStatus.Pending = DeletionStatus.Pending(
    requestId = requestId,
    createdAtEpochMs = createdAt * 1000L,
    scheduledForEpochMs = scheduledFor.deletionSecondsToMillis(),
    graceDaysRemaining = graceDaysRemaining,
    canCancel = canCancel,
)

/**
 * Derives the authoritative [DeletionStatus] from the requests list: the first entry whose wire status is
 * "pending" becomes [DeletionStatus.Pending]; otherwise the account is [DeletionStatus.Active]. Matches the
 * web client's `requests.find(r => r.status === "pending")` (spec §5 / §16 claim 2).
 */
fun AccountDeletionListDto.toDeletionStatus(): DeletionStatus {
    val pending = requests.firstOrNull { it.status.trim().equals(DELETION_STATUS_PENDING, ignoreCase = true) }
    return pending?.toPending() ?: DeletionStatus.Active
}
