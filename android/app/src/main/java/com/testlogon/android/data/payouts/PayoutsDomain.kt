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
 * The wire `status` string mapped to a typed enum. PAY-52/53 §FR-2 extends the AND-260 set to the full
 * PAY-D lifecycle vocabulary so the money-OUT surface shows honest status chips:
 * requested/approved/processing/paid/completed/failed/returned/cancelled + held (the manual-hold flag,
 * surfaced as a status on the statement). Anything else -> [UNKNOWN].
 *  - `paid`/`succeeded` -> [PAID]; `completed` -> [COMPLETED] (both success-styled).
 *  - `failed` -> [FAILED]; `returned` -> [RETURNED]; `rejected` -> [REJECTED] (all error-styled).
 *  - `held`/`on_hold` -> [HELD]; `canceled`/`cancelled` -> [CANCELLED].
 *  - `pending` (the create-response default) folds to [REQUESTED].
 */
enum class PayoutStatus {
    REQUESTED,
    APPROVED,
    PROCESSING,
    PAID,
    COMPLETED,
    FAILED,
    RETURNED,
    HELD,
    REJECTED,
    CANCELLED,
    UNKNOWN,
    ;

    companion object {
        fun from(raw: String?): PayoutStatus = when (raw?.trim()?.lowercase()) {
            "requested", "pending" -> REQUESTED
            "approved" -> APPROVED
            "processing" -> PROCESSING
            "paid", "succeeded" -> PAID
            "completed" -> COMPLETED
            "failed" -> FAILED
            "returned" -> RETURNED
            "held", "on_hold" -> HELD
            "rejected" -> REJECTED
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

/**
 * PAY-50 WalletSummaryOut domain shape — the money-OUT wallet home. [availableCents] reconciles to
 * PAY-A get_available_balance; [heldReleaseAtEpochSeconds] is the earliest 7-day-hold release (the
 * "held until" date); [pendingCents]/[pendingCount] are in-flight payouts; [lifetimePaidCents] is the
 * total ever paid out. Money is integer cents; timestamps are epoch-SECONDS.
 */
data class WalletSummary(
    val availableCents: Long,
    val heldCents: Long,
    val heldCount: Int,
    val heldReleaseAtEpochSeconds: Long?,
    val pendingCents: Long,
    val pendingCount: Int,
    val lifetimePaidCents: Long,
    val totalEarnedCents: Long,
    val currency: String,
    val minimumPayoutCents: Long,
) {
    fun money(cents: Long): PayoutMoney = PayoutMoney(cents, currency)
}

/** PAY-50 one lifecycle event on a payout statement timeline. [status] is a raw wire status string. */
data class PayoutTimelineEntry(
    val status: String,
    val tsEpochSeconds: Long,
    val note: String,
) {
    /** True when the event has a stored timestamp (approved/processing carry ts=0 but still order). */
    val hasTimestamp: Boolean get() = tsEpochSeconds > 0L
}

/**
 * PAY-50 PayoutDetailOut domain shape — the statement/detail for ONE payout. Adds the transfer ref,
 * resolved method last-4, fail/return/hold reason, debit-reversed flag and the lifecycle [timeline]
 * to the base payout fields.
 */
data class PayoutDetail(
    val payoutId: String,
    val userId: String,
    val amount: PayoutMoney,
    val status: PayoutStatus,
    val method: String,
    val methodId: String,
    val methodLast4: String,
    val createdAtEpochSeconds: Long,
    val updatedAtEpochSeconds: Long,
    val completedAtEpochSeconds: Long?,
    val notes: String,
    val rejectReason: String,
    val failReason: String,
    val approvedBy: String,
    val manualHold: Boolean,
    val holdReason: String,
    val debitReversed: Boolean,
    val transferProvider: String,
    val transferRef: String,
    val transferAttempts: Int,
    val timeline: List<PayoutTimelineEntry>,
) {
    val methodType: PayoutMethodType get() = PayoutMethodType.from(method)

    /** The chip status: a manual hold is surfaced as HELD unless the payout already terminated. */
    val displayStatus: PayoutStatus
        get() = if (manualHold && status !in TERMINAL_STATUSES) PayoutStatus.HELD else status

    /** The best failure explanation for a failed/returned/rejected payout (fail_reason preferred). */
    val failureReason: String
        get() = failReason.ifBlank { rejectReason }

    private companion object {
        val TERMINAL_STATUSES = setOf(
            PayoutStatus.PAID, PayoutStatus.COMPLETED, PayoutStatus.FAILED,
            PayoutStatus.RETURNED, PayoutStatus.REJECTED, PayoutStatus.CANCELLED,
        )
    }
}

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

internal fun WalletSummaryDto.toDomain(): WalletSummary = WalletSummary(
    availableCents = availableCents,
    heldCents = heldCents,
    heldCount = heldCount,
    heldReleaseAtEpochSeconds = heldReleaseAt,
    pendingCents = pendingCents,
    pendingCount = pendingCount,
    lifetimePaidCents = lifetimePaidCents,
    totalEarnedCents = totalEarnedCents,
    currency = currency,
    minimumPayoutCents = minimumPayoutCents,
)

internal fun PayoutTimelineEventDto.toDomain(): PayoutTimelineEntry = PayoutTimelineEntry(
    status = status,
    tsEpochSeconds = ts,
    note = note,
)

internal fun PayoutDetailDto.toDomain(currency: String = DEFAULT_PAYOUT_CURRENCY): PayoutDetail = PayoutDetail(
    payoutId = payoutId,
    userId = userId,
    amount = PayoutMoney(amountCents, currency),
    status = PayoutStatus.from(status),
    method = method,
    methodId = methodId,
    methodLast4 = methodLast4,
    createdAtEpochSeconds = createdAt,
    updatedAtEpochSeconds = updatedAt,
    completedAtEpochSeconds = completedAt,
    notes = notes,
    rejectReason = rejectReason,
    failReason = failReason,
    approvedBy = approvedBy,
    manualHold = manualHold,
    holdReason = holdReason,
    debitReversed = debitReversed,
    transferProvider = transferProvider,
    transferRef = transferRef,
    transferAttempts = transferAttempts,
    timeline = timeline.map { it.toDomain() },
)
