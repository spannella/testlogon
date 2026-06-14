package com.testlogon.android.data.refunds

/**
 * AND-244 — framework-free refund domain models + total DTO -> domain mappers.
 *
 * Conventions (matching data/invoices, data/billing):
 *  - Money is integer cents + ISO-4217 currency. No BigDecimal.
 *  - Timestamps are epoch-seconds Longs (NOT java.time) so this stays JVM-unit-testable; the screen
 *    formats via a pure helper. created_at/completed_at == 0 (the server default) maps to null.
 *  - RefundStatus uses an UNKNOWN fallback for forward compatibility (the backend `status` is a free
 *    string; observed values are pending/approved/completed/denied — AND-244 §4.2).
 *
 * Mapping is TOTAL: unknown status strings -> UNKNOWN; no exceptions thrown.
 */

/** Integer cents + ISO-4217 currency. */
data class RefundMoney(val cents: Long, val currency: String)

/** Refund request status. Observed web vocabulary; UNKNOWN is the forward-compat fallback. */
enum class RefundStatus {
    PENDING,
    APPROVED,
    COMPLETED,
    DENIED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): RefundStatus = when (value?.lowercase()?.trim()) {
            "pending" -> PENDING
            "approved" -> APPROVED
            "completed" -> COMPLETED
            "denied" -> DENIED
            else -> UNKNOWN
        }
    }
}

/** A single refund request (the list row and the detail are the same shape — RefundRequestOut). */
data class RefundRequest(
    val id: String,
    val transactionEntryId: String?,
    val status: RefundStatus,
    val reason: String,
    val amount: RefundMoney,
    val transactionType: String?,
    val adminNotes: String?,
    val createdAtEpochSeconds: Long?,
    val completedAtEpochSeconds: Long?,
)

/** Input for a refund submission (mirrors RefundRequestIn). amountCents null => full refund. */
data class SubmitRefundInput(
    val transactionEntryId: String,
    val reason: String,
    val amountCents: Long?,
)

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun RefundRequestOutDto.toDomain(): RefundRequest = RefundRequest(
    id = refundRequestId,
    transactionEntryId = transactionEntryId?.takeIf { it.isNotBlank() },
    status = RefundStatus.fromWire(status),
    reason = reason,
    amount = RefundMoney(amountCents, currency),
    transactionType = transactionType?.takeIf { it.isNotBlank() },
    adminNotes = adminNotes?.takeIf { it.isNotBlank() },
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    completedAtEpochSeconds = completedAt?.epochSecondsOrNull(),
)

internal fun SubmitRefundInput.toDto(): RefundRequestInDto = RefundRequestInDto(
    transactionEntryId = transactionEntryId,
    reason = reason,
    amountCents = amountCents,
)
