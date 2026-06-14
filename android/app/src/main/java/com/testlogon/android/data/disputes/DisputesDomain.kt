package com.testlogon.android.data.disputes

/**
 * AND-245 — framework-free dispute domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/invoices, data/refunds):
 *  - Money is integer cents + ISO-4217 currency. No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time); created_at/updated_at/deadline_at == 0 -> null.
 *  - DisputeStatus uses an UNKNOWN fallback (the backend `status` is a free string; observed values are
 *    open/under_review/resolved — AND-245 §4.2). `reason` is free text (no enum). admin_notes/user_id
 *    are internal and intentionally omitted from the user-facing model.
 *
 * Mapping is TOTAL: unknown status strings -> UNKNOWN; no exceptions thrown.
 */

/** Integer cents + ISO-4217 currency. */
data class DisputeMoney(val cents: Long, val currency: String)

/** Dispute status. Observed web vocabulary; UNKNOWN is the forward-compat fallback. */
enum class DisputeStatus {
    OPEN,
    UNDER_REVIEW,
    RESOLVED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): DisputeStatus = when (value?.lowercase()?.trim()) {
            "open" -> OPEN
            "under_review" -> UNDER_REVIEW
            "resolved" -> RESOLVED
            else -> UNKNOWN
        }
    }
}

/** A single dispute (list row and detail are the same shape — DisputeOut). */
data class Dispute(
    val id: String,
    val provider: String,
    val providerDisputeId: String?,
    val status: DisputeStatus,
    val reason: String,
    val amount: DisputeMoney,
    val evidenceSubmitted: Boolean,
    val evidenceText: String?,
    val resolution: String?,
    val transactionEntryId: String?,
    val createdAtEpochSeconds: Long?,
    val updatedAtEpochSeconds: Long?,
    val deadlineAtEpochSeconds: Long?,
)

/** Input for filing (opening) a dispute (mirrors DisputeFileIn). evidenceText is the user's note. */
data class FileDisputeInput(
    val transactionEntryId: String?,
    val amountCents: Long,
    val currency: String?,
    val reason: String,
)

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun DisputeDto.toDomain(): Dispute = Dispute(
    id = disputeId,
    provider = provider,
    providerDisputeId = providerDisputeId?.takeIf { it.isNotBlank() },
    status = DisputeStatus.fromWire(status),
    reason = reason,
    amount = DisputeMoney(amountCents, currency),
    evidenceSubmitted = evidenceSubmitted,
    evidenceText = evidenceText?.takeIf { it.isNotBlank() },
    resolution = resolution?.takeIf { it.isNotBlank() },
    transactionEntryId = transactionEntryId?.takeIf { it.isNotBlank() },
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt?.epochSecondsOrNull(),
    deadlineAtEpochSeconds = deadlineAt?.epochSecondsOrNull(),
)

internal fun FileDisputeInput.toDto(): DisputeFileInDto = DisputeFileInDto(
    transactionEntryId = transactionEntryId,
    amountCents = amountCents,
    currency = currency,
    reason = reason,
)
