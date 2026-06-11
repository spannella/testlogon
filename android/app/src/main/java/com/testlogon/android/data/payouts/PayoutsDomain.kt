package com.testlogon.android.data.payouts

/**
 * AND-258/260 — framework-free payout domain models + DTO -> domain mappers.
 *
 * Conventions (matching this codebase + the spec gotchas):
 *  - Money is integer cents + ISO-4217 currency (the backend's `*_cents`). No BigDecimal/float here.
 *  - Timestamps are epoch-SECONDS Longs (NOT java.time.Instant, which is API-26+) so mapping stays
 *    JVM-unit-testable; a pure formatter renders dates in the feature layer.
 *  - PayoutOut carries no per-payout currency; the mapper sources it from the balance currency (or
 *    "USD"). The `status` vocabulary is a free string on the wire: [PayoutStatus.UNKNOWN] is the
 *    mandatory fallback so an unrecognized server value never throws.
 *
 * Status vocabulary verified against reference/src/pages/payouts/PayoutDashboard.tsx STATUS_BADGE_VARIANT:
 * requested / approved / processing / completed / rejected / cancelled (British spelling).
 */

/** Integer cents + ISO-4217 currency. */
data class PayoutMoney(val cents: Long, val currency: String)

/**
 * The wire `status` string mapped to a typed enum. AND-260 §FR-2: the real set is
 * requested/approved/processing/completed/rejected/cancelled; anything else -> [UNKNOWN].
 * `paid`/`completed`/`succeeded` all fold to [COMPLETED]; `canceled`/`cancelled` both fold to
 * [CANCELLED] defensively; `pending` (the create-response default) folds to [REQUESTED].
 */
enum class PayoutStatus {
    REQUESTED,
    APPROVED,
    PROCESSING,
    COMPLETED,
    REJECTED,
    CANCELLED,
    UNKNOWN,
    ;

    companion object {
        fun from(raw: String?): PayoutStatus = when (raw?.trim()?.lowercase()) {
            "requested", "pending" -> REQUESTED
            "approved" -> APPROVED
            "processing" -> PROCESSING
            "completed", "paid", "succeeded" -> COMPLETED
            "rejected", "failed" -> REJECTED
            "cancelled", "canceled" -> CANCELLED
            else -> UNKNOWN
        }
    }
}

/** Best-effort normalization of the free-string `method`; raw value is retained on [Payout.method]. */
enum class PayoutMethodType {
    BANK_TRANSFER,
    PAYPAL,
    CARD,
    UNKNOWN,
    ;

    companion object {
        fun from(raw: String?): PayoutMethodType = when (raw?.trim()?.lowercase()) {
            "bank_transfer", "bank", "bank_account" -> BANK_TRANSFER
            "paypal" -> PAYPAL
            "card" -> CARD
            else -> UNKNOWN
        }
    }
}

data class Payout(
    val payoutId: String,
    val userId: String,
    val amount: PayoutMoney,
    val status: PayoutStatus,
    /** Raw server method string (e.g. "bank_transfer"); see [methodType] for the normalized enum. */
    val method: String,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
    val completedAtEpochSeconds: Long?,
    val notes: String,
    val rejectReason: String,
    val approvedBy: String,
) {
    val methodType: PayoutMethodType get() = PayoutMethodType.from(method)

    /** The date a row should display: completed_at if present, else created_at (matches the web). */
    val displayEpochSeconds: Long get() = completedAtEpochSeconds ?: createdAtEpochSeconds
}

/** PayoutListOut domain shape: items + opaque next cursor (null/absent = end of pagination). */
data class PayoutPage(val items: List<Payout>, val nextCursor: String?)

/** PayoutBalanceOut domain shape. [minimumPayoutCents]/[availableCents] gate AND-259 request validation. */
data class PayoutBalance(
    val availableCents: Long,
    val pendingCents: Long,
    val totalEarnedCents: Long,
    val holdCents: Long,
    val currency: String,
    val minimumPayoutCents: Long,
)

/** Result of a successful POST ui/payouts/request (201 PayoutCreateOut). */
data class PayoutCreateResult(
    val ok: Boolean,
    val payoutId: String,
    val amount: PayoutMoney,
    val status: PayoutStatus,
)

/** Result of a cancel action (PayoutActionOut). */
data class PayoutActionResult(
    val ok: Boolean,
    val payoutId: String,
    val status: PayoutStatus,
)

// ---- Mappers (DTO -> domain) ----

internal fun PayoutDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): Payout = Payout(
    payoutId = payoutId,
    userId = userId,
    amount = PayoutMoney(amountCents, currency),
    status = PayoutStatus.from(status),
    method = method,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
    completedAtEpochSeconds = completedAt,
    notes = notes,
    rejectReason = rejectReason,
    approvedBy = approvedBy,
)

internal fun PayoutListDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): PayoutPage = PayoutPage(
    items = items.map { it.toDomain(currency) },
    nextCursor = nextCursor,
)

internal fun PayoutBalanceDto.toDomain(): PayoutBalance = PayoutBalance(
    availableCents = availableCents,
    pendingCents = pendingCents,
    totalEarnedCents = totalEarnedCents,
    holdCents = holdCents,
    currency = currency,
    minimumPayoutCents = minimumPayoutCents,
)

internal fun PayoutCreateRespDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): PayoutCreateResult =
    PayoutCreateResult(
        ok = ok,
        payoutId = payoutId,
        amount = PayoutMoney(amountCents, currency),
        status = PayoutStatus.from(status),
    )

internal fun PayoutActionRespDto.toDomain(): PayoutActionResult = PayoutActionResult(
    ok = ok,
    payoutId = payoutId,
    status = PayoutStatus.from(status),
)
