package com.testlogon.android.data.exchange

/** Order side for trader-submitted orders. */
enum class OrderSide(val wire: String) {
    BUY("buy"),
    SELL("sell"),
}

/** An immediate fill on an order. */
data class Fill(
    val price: Long,
    val qty: Long,
    val tsNs: Long,
    val side: OrderSide?,
)

/** Result of a place/amend order. [accepted] reflects status == "ack". */
data class OrderAck(
    val accepted: Boolean,
    val clordid: String,
    val orderId: Long?,
    val symbolId: Int?,
    val fills: List<Fill>,
    val message: String?,
)

/** Result of a cancel. */
data class CancelAck(
    val accepted: Boolean,
    val clordid: String,
    val cancelledQty: Long,
    val message: String?,
)

/** A net position within the margin account (single position per account today). */
data class PositionSnapshot(
    val symbolId: Int,
    val qty: Long,
    val entryPrice: Long,
    val liquidationPrice: Long,
    val unrealizedPnl: Long,
) {
    val side: OrderSide? get() = when {
        qty > 0 -> OrderSide.BUY
        qty < 0 -> OrderSide.SELL
        else -> null
    }
}

/** Margin account snapshot: cash wallet, reserved margin, position, and risk/liq state. */
data class MarginAccount(
    val balance: Long,
    val availableBalance: Long,
    val reservedMargin: Long,
    val numPositions: Int,
    val position: PositionSnapshot?,
    val distressLevel: Int,
    val isLiquidating: Boolean,
    val mpid: String,
) {
    /** Fraction of balance currently locked as margin (0..1), or 0 when there's no balance. */
    val marginUsedFraction: Float
        get() = if (balance > 0) (reservedMargin.toFloat() / balance.toFloat()).coerceIn(0f, 1f) else 0f
}

// ---- mappers ----

private fun sideOf(s: String?): OrderSide? = when (s?.lowercase()) {
    "buy" -> OrderSide.BUY
    "sell" -> OrderSide.SELL
    else -> null
}

fun FillDto.toDomain(): Fill = Fill(
    price = price ?: 0L,
    qty = qty ?: 0L,
    tsNs = tsNs ?: 0L,
    side = sideOf(side ?: aggressor),
)

fun OrderAckDto.toOrderAck(fallbackClordid: String): OrderAck = OrderAck(
    accepted = status == "ack",
    clordid = clordid ?: fallbackClordid,
    orderId = orderid,
    symbolId = symbolid,
    fills = fills.orEmpty().map { it.toDomain() },
    message = detail ?: error ?: note ?: reason,
)

fun OrderAckDto.toCancelAck(fallbackClordid: String): CancelAck = CancelAck(
    accepted = status == "ack",
    clordid = clordid ?: fallbackClordid,
    cancelledQty = cancelledQty ?: 0L,
    message = detail ?: error,
)

fun MarginAccountDto.toDomain(): MarginAccount {
    val posQtyVal = posQty ?: 0L
    val position = if ((numPositions ?: 0) > 0 || posQtyVal != 0L) {
        PositionSnapshot(
            symbolId = posSymbolIdx ?: 0,
            qty = posQtyVal,
            entryPrice = posEntryPrice ?: 0L,
            liquidationPrice = posLiquidationPrice ?: 0L,
            unrealizedPnl = posUnrealizedPnl ?: 0L,
        )
    } else {
        null
    }
    return MarginAccount(
        balance = balance ?: 0L,
        availableBalance = availableBalance ?: 0L,
        reservedMargin = reservedMargin ?: 0L,
        numPositions = numPositions ?: 0,
        position = position,
        distressLevel = distressLevel ?: 0,
        isLiquidating = (isLiquidating ?: 0) != 0,
        mpid = mpid.orEmpty(),
    )
}

/** Result of an admin margin-config apply. [applied] reflects status == "ack" && result == 0. */
data class MarginConfigAck(
    val applied: Boolean,
    val symbolId: Int?,
    val result: Int?,
    val message: String?,
)

fun MarginConfigAckDto.toDomain(): MarginConfigAck = MarginConfigAck(
    applied = status == "ack" && (result ?: -1) == 0,
    symbolId = symbolId,
    result = result,
    message = detail ?: error ?: note,
)

/** Result of a collateral deposit. */
data class DepositAck(
    val accepted: Boolean,
    val newBalance: Long,
    val availableBalance: Long,
    val message: String?,
)

fun MarginDepositAckDto.toDomain(): DepositAck = DepositAck(
    accepted = status == "ack",
    newBalance = newBalance ?: 0L,
    availableBalance = availableBalance ?: 0L,
    message = detail ?: error,
)

/** Result of a cancel-all. */
data class BulkCancelResult(val accepted: Boolean, val cancelledCount: Int, val message: String?)

/** Result of a two-sided quote. */
data class QuoteAck(
    val accepted: Boolean,
    val quoteId: String?,
    val bidOrderId: Long?,
    val askOrderId: Long?,
    val fills: List<Fill>,
    val message: String?,
)

/** Result of an algo (conditional) order. */
data class AlgoAck(val accepted: Boolean, val algoId: Long?, val clordid: String?, val message: String?)

/** Result of a one-triggers-other order. */
data class OtoAck(
    val accepted: Boolean,
    val otoId: Long?,
    val parentOrderId: Long?,
    val fills: List<Fill>,
    val message: String?,
)

private fun codeMsg(detail: String?, error: String?, note: String?, code: Int?): String? =
    detail ?: error ?: note ?: code?.let { "rejected (code $it)" }

fun BulkCancelAckDto.toDomain(): BulkCancelResult =
    BulkCancelResult(accepted = status == "ack", cancelledCount = cancelledCount ?: 0, message = null)

fun QuoteAckDto.toDomain(): QuoteAck = QuoteAck(
    accepted = status == "ack",
    quoteId = quoteId,
    bidOrderId = bidOrderId,
    askOrderId = askOrderId,
    fills = fills.orEmpty().map { it.toDomain() },
    message = codeMsg(detail, error, note, reasonCode),
)

fun AlgoAckDto.toDomain(): AlgoAck = AlgoAck(
    accepted = status == "ack",
    algoId = algoId,
    clordid = clordid,
    message = codeMsg(detail, error, note, reasonCode),
)

fun OtoAckDto.toDomain(): OtoAck = OtoAck(
    accepted = status == "ack",
    otoId = otoId,
    parentOrderId = parentOrderId,
    fills = fills.orEmpty().map { it.toDomain() },
    message = codeMsg(detail, error, note, reasonCode),
)

/** Drained async exec events. */
data class ExecEvents(val fills: List<Fill>, val triggeredCount: Int, val otoTriggeredCount: Int) {
    val isEmpty: Boolean get() = fills.isEmpty() && triggeredCount == 0 && otoTriggeredCount == 0
}

fun ExecEventsDto.toDomain(): ExecEvents = ExecEvents(
    fills = fills.orEmpty().map { it.toDomain() },
    triggeredCount = triggered.orEmpty().size,
    otoTriggeredCount = otoTriggered.orEmpty().size,
)

// ==== Pre-staged advanced surfaces (behind TradingFeatures flags) ====

data class OcoAck(val accepted: Boolean, val ocoId: Long?, val fills: List<Fill>, val message: String?)
data class FundingAck(val accepted: Boolean, val fundingId: Long?, val message: String?)
data class SpotAsset(val asset: Int, val symbol: String, val balance: Long, val available: Long)
data class SpotBalance(val assets: List<SpotAsset>, val mpid: String)
data class SpotDepositAck(val accepted: Boolean, val newBalance: Long, val availableBalance: Long, val message: String?)

fun OcoAckDto.toDomain(): OcoAck = OcoAck(
    accepted = status == "ack",
    ocoId = ocoId,
    fills = fills.orEmpty().map { it.toDomain() },
    message = detail ?: error ?: note ?: reasonCode?.let { "rejected (code $it)" },
)

fun FundingAckDto.toDomain(): FundingAck = FundingAck(
    accepted = status == "ack",
    fundingId = fundingId,
    message = detail ?: error ?: note ?: (reason ?: reasonCode)?.let { "rejected (code $it)" },
)

fun SpotAssetDto.toDomain(): SpotAsset = SpotAsset(
    asset = asset ?: 0,
    symbol = symbol.orEmpty(),
    balance = balance ?: 0L,
    available = available ?: 0L,
)

fun SpotBalanceDto.toDomain(): SpotBalance = SpotBalance(
    assets = balances.orEmpty().map { it.toDomain() },
    mpid = mpid.orEmpty(),
)

fun SpotDepositAckDto.toDomain(): SpotDepositAck = SpotDepositAck(
    accepted = status == "ack",
    newBalance = newBalance ?: 0L,
    availableBalance = availableBalance ?: 0L,
    message = detail ?: error,
)

/**
 * A binary prediction market: the symbol trades in [0, faceValue] where price = implied YES
 * probability x faceValue. YES = buy/long (pays faceValue on YES), NO = sell/short.
 */
data class PmState(
    val symbolId: Int,
    val isBinary: Boolean,
    val resolved: Boolean,
    val outcomeYes: Boolean?,   // when resolved: true = YES won, false = NO
    val faceValue: Long,
    val resolverId: String,
) {
    /** Implied YES probability (0..1) at [price], or null when faceValue is unknown. */
    fun impliedYes(price: Long?): Float? {
        if (faceValue <= 0 || price == null) return null
        return (price.toFloat() / faceValue.toFloat()).coerceIn(0f, 1f)
    }
}

fun PmStateDto.toDomain(): PmState = PmState(
    symbolId = symbolid ?: 0,
    isBinary = isBinary == true,
    resolved = state == "resolved",
    outcomeYes = if (state == "resolved") (outcome ?: 0) == 1 else null,
    faceValue = faceValue ?: 0L,
    resolverId = resolverId.orEmpty(),
)

// ==== Fees (custody-exchange-gaps) ====

/** Venue default bps used when the backend/stub omits an explicit fee. */
private const val DEFAULT_MAKER_BPS = 10
private const val DEFAULT_TAKER_BPS = 20
private const val DEFAULT_LIQ_BPS = 100

/**
 * The caller's fee schedule: maker/taker/liquidation in basis points. [isStub] is true when the value
 * is the venue default (source == "stub") rather than a real per-caller/per-symbol quote — the UI
 * labels it so the number isn't mistaken for a negotiated rate.
 */
data class FeeSchedule(
    val makerFeeBps: Int,
    val takerFeeBps: Int,
    val liquidationFeeBps: Int,
    val isStub: Boolean,
) {
    /** bps -> a percent string, e.g. 20 -> "0.20%". */
    fun makerPct(): String = bpsToPct(makerFeeBps)
    fun takerPct(): String = bpsToPct(takerFeeBps)
    fun liquidationPct(): String = bpsToPct(liquidationFeeBps)

    /** Fee for a notional (price*qty) at the taker rate, using the stub'"'"'s round(notional*bps/10000). */
    fun takerFeeFor(price: Long, qty: Long): Long = feeFor(price * qty, takerFeeBps)

    companion object {
        fun default(): FeeSchedule = FeeSchedule(DEFAULT_MAKER_BPS, DEFAULT_TAKER_BPS, DEFAULT_LIQ_BPS, isStub = true)
    }
}

/** round(notional * bps / 10000), matching the backend fee_formula. */
fun feeFor(notional: Long, bps: Int): Long =
    Math.round(notional.toDouble() * bps.toDouble() / 10000.0)

private fun bpsToPct(bps: Int): String = String.format(java.util.Locale.US, "%.2f%%", bps / 100.0)

fun FeeScheduleDto.toDomain(): FeeSchedule {
    val row = schedule.orEmpty().firstOrNull()
    val maker = row?.makerFeeBps ?: makerFeeBps ?: DEFAULT_MAKER_BPS
    val taker = row?.takerFeeBps ?: takerFeeBps ?: DEFAULT_TAKER_BPS
    val liq = row?.liquidationFeeBps ?: liquidationFeeBps ?: DEFAULT_LIQ_BPS
    return FeeSchedule(
        makerFeeBps = maker,
        takerFeeBps = taker,
        liquidationFeeBps = liq,
        isStub = stub == true || (source?.trim()?.lowercase() == "stub"),
    )
}

/** One fill enriched with a fee. When the server feed is empty the UI computes [fee] client-side. */
data class FillFee(
    val price: Long,
    val qty: Long,
    val fee: Long,
    val tsNs: Long,
    val side: OrderSide?,
)

/**
 * The enriched fills-fees feed. [fills] is empty today (engine exposes no per-fill fee); [takerFeeBps]
 * + [feeFormula] let the UI compute fees for its own session fills. [isStub] marks that honesty.
 */
data class FillsFees(
    val fills: List<FillFee>,
    val takerFeeBps: Int,
    val feeFormula: String?,
    val isStub: Boolean,
    val note: String?,
)

fun FillFeeDto.toDomain(): FillFee = FillFee(
    price = price ?: 0L,
    qty = qty ?: 0L,
    fee = fee ?: 0L,
    tsNs = tsNs ?: 0L,
    side = when (side?.lowercase()) { "buy" -> OrderSide.BUY; "sell" -> OrderSide.SELL; else -> null },
)

fun FillsFeesDto.toDomain(): FillsFees = FillsFees(
    fills = fills.orEmpty().map { it.toDomain() },
    takerFeeBps = takerFeeBps ?: DEFAULT_TAKER_BPS,
    feeFormula = feeFormula?.takeIf { it.isNotBlank() },
    isStub = stub == true || (source?.trim()?.lowercase() == "stub"),
    note = note?.takeIf { it.isNotBlank() },
)
