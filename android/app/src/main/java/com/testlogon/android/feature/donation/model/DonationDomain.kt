package com.testlogon.android.feature.donation.model

import com.testlogon.android.core.network.donation.DonationDto
import com.testlogon.android.core.network.donation.DonationReceiptDto
import com.testlogon.android.core.network.donation.PublicFundraiserDto

/**
 * AND-393 - domain models + DTO -> domain mappers for the public donation flow.
 *
 * The wire DTOs (core-network DonationDtos.kt) carry raw snake_case fields and raw status strings; these
 * mappers convert them into typed domain models with UNKNOWN-tolerant status enums (never throw on an
 * unrecognised wire value). Mapping happens in DonationRepository BEFORE the typed ApiResult is produced,
 * so the rest of the app never sees a raw DTO. Money stays as integer cents (Long); timestamps stay as
 * epoch-seconds Longs (formatted at the edge).
 */

/** Whether a fundraiser is open for donations - derived from the wire `status` enum, NOT a boolean. */
enum class FundraiserStatus {
    ACTIVE,
    PAUSED,
    COMPLETED,
    CANCELLED,
    UNKNOWN,
    ;

    /** Open iff ACTIVE (the web client gates on `status === "active"`). */
    val isOpen: Boolean get() = this == ACTIVE

    companion object {
        /** Maps a raw wire status to the enum, tolerating any unknown value as [UNKNOWN]. */
        fun fromWire(value: String?): FundraiserStatus = when (value?.lowercase()) {
            "active" -> ACTIVE
            "paused" -> PAUSED
            "completed" -> COMPLETED
            "cancelled", "canceled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/** The lifecycle status of a single donation. UNKNOWN-tolerant. */
enum class DonationStatus {
    PENDING,
    COMPLETED,
    FAILED,
    REFUNDED,
    UNKNOWN,
    ;

    companion object {
        fun fromWire(value: String?): DonationStatus = when (value?.lowercase()) {
            "pending" -> PENDING
            "completed" -> COMPLETED
            "failed" -> FAILED
            "refunded" -> REFUNDED
            else -> UNKNOWN
        }
    }
}

/** A public fundraiser summary (mapped from [PublicFundraiserDto]). Money is integer cents. */
data class Fundraiser(
    val fundraiserId: String,
    val groupId: String,
    val groupName: String,
    val title: String,
    val status: FundraiserStatus,
    val description: String?,
    val currency: String,
    val goalCents: Long?,
    val raisedCents: Long,
    val donationCount: Int,
    val coverImageUrl: String?,
    val endsAt: Long?,
) {
    /** Fraction raised toward the goal in 0f..1f, or null when there is no positive goal. */
    val progress: Float?
        get() = goalCents?.takeIf { it > 0L }?.let { (raisedCents.toFloat() / it).coerceIn(0f, 1f) }
}

/** The donor-entered request payload (validated in the ViewModel; donor fields optional). */
data class DonationRequest(
    val amountCents: Long,
    val donorName: String?,
    val donorEmail: String?,
)

/**
 * The terminal confirmation/receipt shown after a successful donation. Built EITHER from the receipt GET
 * ([DonationReceiptDto]) OR, when that call fails transiently, from the donation 201 alone (the
 * soft-fallback, §5/AC-2) - hence the receipt-only fields are nullable.
 */
data class DonationReceipt(
    val donationId: String,
    val amountCents: Long,
    val status: DonationStatus,
    val createdAt: Long,
    val currency: String,
    val donorName: String?,
    val groupName: String?,
    val fundraiserTitle: String?,
)

/** Maps a [PublicFundraiserDto] to its [Fundraiser] domain model (status derived, money in cents). */
fun PublicFundraiserDto.toDomain(): Fundraiser = Fundraiser(
    fundraiserId = fundraiserId,
    groupId = groupId,
    groupName = groupName,
    title = title,
    status = FundraiserStatus.fromWire(status),
    description = description,
    currency = currency,
    goalCents = goalCents,
    raisedCents = raisedCents,
    donationCount = donationCount,
    coverImageUrl = coverImageUrl,
    endsAt = endsAt,
)

/**
 * Builds a [DonationReceipt] from the receipt GET response (the rich, preferred path).
 * [currencyFallback] supplies the currency the receipt itself omits only when the wire default is wrong;
 * the receipt DTO already defaults `currency` to "usd".
 */
fun DonationReceiptDto.toDomain(): DonationReceipt = DonationReceipt(
    donationId = donationId,
    amountCents = amountCents,
    status = DonationStatus.fromWire(status),
    createdAt = createdAt,
    currency = currency,
    donorName = donorName,
    groupName = groupName,
    fundraiserTitle = fundraiserTitle,
)

/**
 * Soft-fallback: builds a minimal [DonationReceipt] from the donation 201 alone when the receipt GET
 * fails transiently (§5/AC-2). [currency] and [fundraiserTitle]/[groupName] come from the already-loaded
 * fundraiser so the confirmation still reads sensibly without the receipt endpoint.
 */
fun DonationDto.toReceiptFallback(
    currency: String,
    groupName: String?,
    fundraiserTitle: String?,
): DonationReceipt = DonationReceipt(
    donationId = donationId,
    amountCents = amountCents,
    status = DonationStatus.fromWire(status),
    createdAt = createdAt,
    currency = currency,
    donorName = donorName,
    groupName = groupName,
    fundraiserTitle = fundraiserTitle,
)
