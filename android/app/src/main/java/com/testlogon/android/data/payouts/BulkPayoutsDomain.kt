package com.testlogon.android.data.payouts

/**
 * AND-261 — framework-free bulk/batch payout domain models + DTO -> domain mappers.
 *
 * REUSES AND-258's [PayoutMoney] (integer cents + currency) and [PayoutStatus] (per-item status, with
 * the mandatory UNKNOWN fallback). Mirrors the conventions in PayoutsDomain.kt:
 *  - Money is integer cents; the batch object carries NO currency field, so "USD" is the constant
 *    default (matching the web fmtCents which hard-codes "$").
 *  - Timestamps stay epoch-SECONDS Longs (NOT java.time.Instant, API-26+) so mapping is JVM-unit-testable;
 *    the feature-layer formatter renders dates.
 *  - The batch `status` is a free string on the wire mapped to [PayoutBatchStatus]; an unrecognized value
 *    folds to [PayoutBatchStatus.UNKNOWN] so it never throws.
 */

/**
 * Bulk batch status. The OpenAPI types `status` as a free-form string (no enum), so [UNKNOWN] is the
 * mandatory guard. The string set is a best-effort guess pending live data (AND-261 §13 R2).
 */
enum class PayoutBatchStatus {
    DRAFT,
    PENDING,
    PROCESSING,
    COMPLETED,
    PARTIALLY_FAILED,
    FAILED,
    CANCELED,
    UNKNOWN,
    ;

    companion object {
        fun from(raw: String?): PayoutBatchStatus = when (raw?.trim()?.lowercase()) {
            "draft" -> DRAFT
            "pending", "queued" -> PENDING
            "processing", "in_progress", "running" -> PROCESSING
            "completed", "succeeded", "success", "done" -> COMPLETED
            "partially_failed", "partial" -> PARTIALLY_FAILED
            "failed", "error" -> FAILED
            "canceled", "cancelled" -> CANCELED
            else -> UNKNOWN
        }
    }
}

/** A bulk payout/refund batch (BulkBatchOut) including its embedded line items. */
data class PayoutBatch(
    val id: String,
    /** Server kind string, e.g. "payout" | "refund". */
    val kind: String,
    val status: PayoutBatchStatus,
    val itemCount: Int,
    val total: PayoutMoney,
    val successCount: Int,
    val failureCount: Int,
    /** Epoch seconds; null when absent. */
    val createdAtEpochSeconds: Long?,
    val createdBy: String?,
    val items: List<PayoutBatchItem>,
)

/** A single line item inside a batch (BulkBatchItem). */
data class PayoutBatchItem(
    val refId: String,
    val amount: PayoutMoney,
    val status: PayoutStatus,
    val recipient: String,
    val reason: String,
)

// ---- Mappers (DTO -> domain) ----

internal fun PayoutBatchDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): PayoutBatch = PayoutBatch(
    id = batchId,
    kind = kind,
    status = PayoutBatchStatus.from(status),
    itemCount = itemCount,
    total = PayoutMoney(totalCents, currency),
    successCount = successCount,
    failureCount = failureCount,
    createdAtEpochSeconds = createdAtEpochSeconds,
    createdBy = createdBy,
    items = items.map { it.toDomain(currency) },
)

internal fun PayoutBatchItemDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): PayoutBatchItem =
    PayoutBatchItem(
        refId = refId,
        amount = PayoutMoney(amountCents, currency),
        status = PayoutStatus.from(status),
        recipient = recipient,
        reason = reason,
    )
