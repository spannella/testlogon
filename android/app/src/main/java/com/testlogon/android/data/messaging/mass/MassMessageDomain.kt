package com.testlogon.android.data.messaging.mass

/**
 * AND-160 — domain models + pure mappers for mass-message campaigns.
 *
 * Kept JVM-pure (no android.* / java.time API-26 deps) so the mapper is unit-testable on the JVM.
 * Timestamps stay as epoch-SECONDS Longs; the UI layer formats them with the locale-aware formatter.
 */

/** Campaign status enum (mirrors the wire `status` strings). */
enum class CampaignStatus {
    PENDING,
    SCHEDULED,
    PROCESSING,
    COMPLETED,
    FAILED,
    CANCELLED,
    UNKNOWN,
    ;

    /** Non-terminal -> can be cancelled by the creator. */
    val isCancellable: Boolean
        get() = this == PENDING || this == SCHEDULED || this == PROCESSING

    companion object {
        fun fromWire(value: String?): CampaignStatus = when (value?.lowercase()) {
            "pending" -> PENDING
            "scheduled" -> SCHEDULED
            "processing" -> PROCESSING
            "completed" -> COMPLETED
            "failed" -> FAILED
            "cancelled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/** Campaign send mode. */
enum class CampaignMode {
    IMMEDIATE,
    SCHEDULED,
    ;

    fun wire(): String = when (this) {
        IMMEDIATE -> "immediate"
        SCHEDULED -> "scheduled"
    }

    companion object {
        fun fromWire(value: String?): CampaignMode =
            if (value?.lowercase() == "scheduled") SCHEDULED else IMMEDIATE
    }
}

/** Progress counters derived from MassMessageCampaignCounters. */
data class CampaignCounters(
    val total: Int = 0,
    val queued: Int = 0,
    val sent: Int = 0,
    val failed: Int = 0,
    val cancelled: Int = 0,
)

/** Domain campaign (list row / mutation result). */
data class MassCampaign(
    val id: String,
    val status: CampaignStatus,
    val mode: CampaignMode,
    val sendAtEpochSeconds: Long?,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
    val counters: CampaignCounters,
) {
    val isCancellable: Boolean get() = status.isCancellable
}

/** Result of a create call: the new campaign plus any non-fatal rejected destinations. */
data class MassCampaignCreateResult(
    val campaign: MassCampaign,
    val acceptedCount: Int,
    val acceptedConversationIds: List<String>,
    val rejected: List<RejectedDestination>,
)

data class RejectedDestination(
    val conversationId: String,
    val reason: String,
)

// ---- pure mappers ----

internal fun MassMessageCountersDto.toDomain(): CampaignCounters = CampaignCounters(
    total = total,
    queued = queued,
    sent = sent,
    failed = failed,
    cancelled = cancelled,
)

internal fun MassMessageCampaignSummaryDto.toDomain(): MassCampaign = MassCampaign(
    id = campaignId,
    status = CampaignStatus.fromWire(status),
    mode = CampaignMode.fromWire(mode),
    sendAtEpochSeconds = sendAt,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
    counters = counters.toDomain(),
)

internal fun MassMessageCreateCampaignResponseDto.toResult(): MassCampaignCreateResult =
    MassCampaignCreateResult(
        campaign = MassCampaign(
            id = campaignId,
            status = CampaignStatus.fromWire(status),
            mode = CampaignMode.fromWire(mode),
            sendAtEpochSeconds = sendAt,
            createdAtEpochSeconds = createdAt,
            updatedAtEpochSeconds = updatedAt,
            counters = counters.toDomain(),
        ),
        acceptedCount = acceptedCount,
        acceptedConversationIds = acceptedConversationIds,
        rejected = rejected.map { RejectedDestination(it.conversationId, it.reason) },
    )

/**
 * Cancel responds with a partial summary (no mode/created_at). [prior] supplies those fields so the
 * reconciled domain object is complete; when no prior is known the missing fields default sensibly.
 */
internal fun MassMessageCancelCampaignResponseDto.toDomain(prior: MassCampaign? = null): MassCampaign =
    MassCampaign(
        id = campaignId,
        status = CampaignStatus.fromWire(status),
        mode = prior?.mode ?: CampaignMode.IMMEDIATE,
        sendAtEpochSeconds = prior?.sendAtEpochSeconds,
        createdAtEpochSeconds = prior?.createdAtEpochSeconds ?: 0L,
        updatedAtEpochSeconds = updatedAt,
        counters = counters.toDomain(),
    )
