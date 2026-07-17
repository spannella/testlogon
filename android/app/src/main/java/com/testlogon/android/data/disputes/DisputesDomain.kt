package com.testlogon.android.data.disputes

/**
 * AND-245 + DISP-021/023 — framework-free dispute domain models + total DTO -> domain mappers.
 *
 * Conventions:
 *  - Money is integer cents + ISO-4217 currency. No BigDecimal.
 *  - Timestamps are epoch-seconds Longs; 0 -> null.
 *  - DisputeStatus uses an UNKNOWN fallback; the E2 vocabulary adds needs_response / escalated /
 *    withdrawn on top of open / under_review / resolved.
 *  - Mapping is TOTAL: unknown status strings -> UNKNOWN; no exceptions thrown.
 */

/** Integer cents + ISO-4217 currency. */
data class DisputeMoney(val cents: Long, val currency: String)

/** Dispute status. Full E2 vocabulary; UNKNOWN is the forward-compat fallback. */
enum class DisputeStatus {
    OPEN,
    NEEDS_RESPONSE,
    UNDER_REVIEW,
    ESCALATED,
    RESOLVED,
    WITHDRAWN,
    UNKNOWN,
    ;

    /** Terminal states carry no further action. */
    val isTerminal: Boolean get() = this == RESOLVED || this == WITHDRAWN

    companion object {
        fun fromWire(value: String?): DisputeStatus = when (value?.lowercase()?.trim()) {
            "open" -> OPEN
            "needs_response" -> NEEDS_RESPONSE
            "under_review" -> UNDER_REVIEW
            "escalated" -> ESCALATED
            "resolved" -> RESOLVED
            "withdrawn" -> WITHDRAWN
            else -> UNKNOWN
        }
    }
}

/** A single dispute (list row and detail share the DisputeOut shape). */
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
    // DISP-021/023 E2 additions (defaulted so pre-E2 constructor callers stay valid).
    val reasonDetail: String? = null,
    val chargeType: String? = null,
    val movedCents: Long? = null,
    val creatorResponse: String? = null,
    val recipientId: String? = null,
    val respondByEpochSeconds: Long? = null,
) {
    /** DISP-024: the creator can still submit a rebuttal only while needs_response. */
    val creatorCanRespond: Boolean get() = status == DisputeStatus.NEEDS_RESPONSE
}

/** Input for filing (opening) a dispute (mirrors DisputeFileIn). */
data class FileDisputeInput(
    val transactionEntryId: String?,
    val amountCents: Long,
    val currency: String?,
    val reason: String,
    val reasonDetail: String? = null,
    val chargeType: String? = null,
    val chargeRef: String? = null,
    val recipientId: String? = null,
)

/** DISP-021: a creator/seller rebuttal. */
data class CreatorRespondInput(
    val disputeId: String,
    val responseText: String,
    val evidenceFiles: List<String>? = null,
)

/** Result of a creator rebuttal. */
data class CreatorRespondResult(
    val ok: Boolean,
    val disputeId: String,
    val status: DisputeStatus,
    val creatorResponse: String?,
)

// ---- Mappers (DTO -> domain) ----

private fun Long.epochSecondsOrNull(): Long? = takeIf { it > 0 }

internal fun DisputeDto.toDomain(): Dispute = Dispute(
    id = disputeId,
    provider = provider,
    providerDisputeId = providerDisputeId?.takeIf { it.isNotBlank() },
    status = DisputeStatus.fromWire(status),
    reason = reason,
    reasonDetail = reasonDetail?.takeIf { it.isNotBlank() },
    chargeType = chargeType?.takeIf { it.isNotBlank() },
    amount = DisputeMoney(amountCents, currency),
    evidenceSubmitted = evidenceSubmitted,
    evidenceText = evidenceText?.takeIf { it.isNotBlank() },
    resolution = resolution?.takeIf { it.isNotBlank() },
    movedCents = movedCents?.takeIf { it > 0 },
    creatorResponse = creatorResponse?.takeIf { it.isNotBlank() },
    recipientId = recipientId?.takeIf { it.isNotBlank() },
    transactionEntryId = transactionEntryId?.takeIf { it.isNotBlank() },
    respondByEpochSeconds = respondBy?.epochSecondsOrNull(),
    createdAtEpochSeconds = createdAt.epochSecondsOrNull(),
    updatedAtEpochSeconds = updatedAt?.epochSecondsOrNull(),
    deadlineAtEpochSeconds = deadlineAt?.epochSecondsOrNull(),
)

internal fun FileDisputeInput.toDto(): DisputeFileInDto = DisputeFileInDto(
    transactionEntryId = transactionEntryId,
    amountCents = amountCents,
    currency = currency,
    reason = reason,
    reasonDetail = reasonDetail,
    chargeType = chargeType,
    chargeRef = chargeRef,
    recipientId = recipientId,
)

internal fun CreatorRespondInput.toDto(): CreatorDisputeRespondReqDto = CreatorDisputeRespondReqDto(
    responseText = responseText,
    evidenceFiles = evidenceFiles,
)

internal fun CreatorDisputeRespondResultDto.toDomain(): CreatorRespondResult = CreatorRespondResult(
    ok = ok,
    disputeId = disputeId,
    status = DisputeStatus.fromWire(status),
    creatorResponse = creatorResponse?.takeIf { it.isNotBlank() },
)
