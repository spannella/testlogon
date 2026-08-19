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
    /** "engine" (a configured rate) or "venue_default". */
    val source: String,
    /** Whether this symbol has an explicit fee override (vs. inheriting the venue default). */
    val configured: Boolean,
) {
    /** True when these are the venue defaults (not a configured per-caller/engine rate). */
    val isVenueDefault: Boolean get() = source.equals("venue_default", ignoreCase = true) || !configured
    /** Human label for the source ("engine" / "venue default"). */
    val sourceLabel: String get() = if (isVenueDefault) "venue default" else "engine"
    /** bps -> a percent string, e.g. 20 -> "0.20%". */
    fun makerPct(): String = bpsToPct(makerFeeBps)
    fun takerPct(): String = bpsToPct(takerFeeBps)
    fun liquidationPct(): String = bpsToPct(liquidationFeeBps)

    /** Fee for a notional (price*qty) at the taker rate, using the stub'"'"'s round(notional*bps/10000). */
    fun takerFeeFor(price: Long, qty: Long): Long = feeFor(price * qty, takerFeeBps)

    companion object {
        fun default(): FeeSchedule = FeeSchedule(DEFAULT_MAKER_BPS, DEFAULT_TAKER_BPS, DEFAULT_LIQ_BPS, source = "venue_default", configured = false)
    }
}

/** round(notional * bps / 10000), matching the backend fee_formula. */
fun feeFor(notional: Long, bps: Int): Long =
    Math.round(notional.toDouble() * bps.toDouble() / 10000.0)

private fun bpsToPct(bps: Int): String = String.format(java.util.Locale.US, "%.2f%%", bps / 100.0)

fun FeeScheduleDto.toDomain(): FeeSchedule {
    val src = source?.trim()?.takeIf { it.isNotBlank() }?.lowercase() ?: "venue_default"
    return FeeSchedule(
        makerFeeBps = makerFeeBps ?: DEFAULT_MAKER_BPS,
        takerFeeBps = takerFeeBps ?: DEFAULT_TAKER_BPS,
        liquidationFeeBps = liquidationFeeBps ?: DEFAULT_LIQ_BPS,
        source = src,
        configured = configured ?: (src == "engine"),
    )
}

/** Maker vs. taker liquidity flag on a fill. */
enum class Liquidity(val label: String) { MAKER("maker"), TAKER("taker"), UNKNOWN("--") }

private fun liquidityOf(s: String?): Liquidity = when (s?.lowercase()) {
    "maker" -> Liquidity.MAKER
    "taker" -> Liquidity.TAKER
    else -> Liquidity.UNKNOWN
}

/** One fill enriched with the engine's REAL [fee] + [liquidity]. [tsNs] is a nanosecond timestamp. */
data class FillFee(
    val symbolId: Int,
    val price: Long,
    val qty: Long,
    val side: OrderSide?,
    val liquidity: Liquidity,
    val fee: Long,
    val feeAsset: Int,
    val tsNs: Long,
)

/** The REAL enriched fills-fees feed (GET me/fills/fees). [count] is the server-reported row count. */
data class FillsFees(
    val fills: List<FillFee>,
    val count: Int,
) {
    val isEmpty: Boolean get() = fills.isEmpty()
}

fun FillFeeDto.toDomain(): FillFee = FillFee(
    symbolId = symbolId ?: 0,
    price = price ?: 0L,
    qty = qty ?: 0L,
    side = sideOf(side),
    liquidity = liquidityOf(liquidity),
    fee = fee ?: 0L,
    feeAsset = feeAsset ?: 0,
    tsNs = ts ?: 0L,
)

fun FillsFeesDto.toDomain(): FillsFees = FillsFees(
    fills = fills.orEmpty().map { it.toDomain() },
    count = count ?: fills.orEmpty().size,
)

// ==== Liquidations (me/liquidations) — REAL ====

/** One forced-liquidation event. [realizedPnl] is signed (green when >=0). [tsNs] is nanoseconds. */
data class Liquidation(
    val symbolId: Int,
    val qty: Long,
    val markPrice: Long,
    val realizedPnl: Long,
    val fee: Long,
    val tsNs: Long,
)

data class Liquidations(val events: List<Liquidation>, val count: Int) {
    val isEmpty: Boolean get() = events.isEmpty()
}

fun LiquidationDto.toDomain(): Liquidation = Liquidation(
    symbolId = symbolId ?: 0,
    qty = qty ?: 0L,
    markPrice = markPrice ?: 0L,
    realizedPnl = realizedPnl ?: 0L,
    fee = fee ?: 0L,
    tsNs = ts ?: 0L,
)

fun LiquidationsDto.toDomain(): Liquidations = Liquidations(
    events = liquidations.orEmpty().map { it.toDomain() },
    count = count ?: liquidations.orEmpty().size,
)

// ==== Funding payments (me/funding/payments) — REAL ====

/**
 * One perpetual funding payment. [payment] is SIGNED: negative = paid out, positive = received;
 * [received] mirrors that. [fundingRateBps] is the applied rate, [positionQty] the charged position.
 */
data class FundingPayment(
    val symbolId: Int,
    val fundingRateBps: Int,
    val markPrice: Long,
    val positionQty: Long,
    val payment: Long,
    val received: Boolean,
    val tsNs: Long,
)

data class FundingPayments(val payments: List<FundingPayment>, val count: Int) {
    val isEmpty: Boolean get() = payments.isEmpty()
}

fun FundingPaymentDto.toDomain(): FundingPayment = FundingPayment(
    symbolId = symbolId ?: 0,
    fundingRateBps = fundingRateBps ?: 0,
    markPrice = markPrice ?: 0L,
    positionQty = positionQty ?: 0L,
    payment = payment ?: 0L,
    // Trust the explicit flag when present, else derive from the sign of the signed amount.
    received = received ?: ((payment ?: 0L) > 0L),
    tsNs = ts ?: 0L,
)

fun FundingPaymentsDto.toDomain(): FundingPayments = FundingPayments(
    payments = funding.orEmpty().map { it.toDomain() },
    count = count ?: funding.orEmpty().size,
)

/**
 * Result of an admin engine-config apply (matching_algo / spread_config / trading_params / risk_config
 * / spot_index / spot_config). [applied] is true when status == "ack" and, if the engine returns a
 * [result], it is 0. [message] surfaces any detail/error/note the engine sent back.
 */
data class EngineConfigAck(
    val applied: Boolean,
    val symbolId: Int?,
    val result: Int?,
    val message: String?,
)

fun EngineConfigAckDto.toDomain(): EngineConfigAck = EngineConfigAck(
    applied = status == "ack" && (result ?: 0) == 0,
    symbolId = symbolId,
    result = result,
    message = detail ?: error ?: note,
)


// ==== Admin prediction-markets (exchange-admin-config) — domain + mappers ====

/**
 * Result of an admin PM config/resolve apply (pm_config / pm_group_config / pm_resolve /
 * pm_group_resolve). [applied] is true when status == "ack" and, if a [result] is present, it is 0.
 * [message] surfaces any detail/error/note (e.g. the resolver 403 message on pm_resolve).
 */
data class PmConfigAck(
    val applied: Boolean,
    val symbolId: Int?,
    val groupId: Int?,
    val result: Int?,
    val message: String?,
)

fun PmConfigAckDto.toDomain(): PmConfigAck = PmConfigAck(
    applied = status == "ack" && (result ?: 0) == 0,
    symbolId = symbolId,
    groupId = groupId,
    result = result,
    message = detail ?: error ?: note,
)

/**
 * One PM resolution audit row. [isGroup] is true for a categorical resolution (carries [groupId] +
 * [winningSymbolId]); otherwise it is a binary resolution (carries [symbolId] + [outcomeYes]).
 */
data class PmResolution(
    val symbolId: Int?,
    val groupId: Int?,
    val winningSymbolId: Int?,
    val outcome: String?,
    val resolverId: String,
    val ts: Long,
    val source: String,
) {
    val isGroup: Boolean get() = groupId != null
    /** For a binary row: true = YES won, false = NO, null when the outcome string is absent/unknown. */
    val outcomeYes: Boolean? get() = when (outcome?.lowercase()) {
        "yes" -> true
        "no" -> false
        else -> null
    }
    /** A compact human label for the resolved market ("#<sym>" or "group <id>"). */
    val marketLabel: String get() = if (isGroup) "group $groupId" else "#" + (symbolId ?: 0)
    /** A compact human label for the outcome (YES/NO for binary; the winning symbol for categorical). */
    val outcomeLabel: String get() = if (isGroup) "#" + (winningSymbolId ?: 0) else (outcome?.uppercase() ?: "--")
}

fun PmResolutionDto.toDomain(): PmResolution = PmResolution(
    symbolId = symbolId,
    groupId = groupId,
    winningSymbolId = winningSymbolId,
    outcome = outcome,
    resolverId = resolverId.orEmpty(),
    ts = ts ?: 0L,
    source = source.orEmpty(),
)

// ==== Trader staking + auctions (peer mechanisms) — domain + mapper ====

/** Which peer mechanism produced an ack (drives the id label the UI surfaces). */
enum class StakeAuctionKind { STAKE_REQUEST, STAKE_OFFER, AUCTION_REQUEST, AUCTION_BID }

/**
 * Result of a staking/auction action. [accepted] is true when the engine acked (status ack/ok and,
 * if a numeric result is present, it is 0). [createdId] is the most relevant id the engine returned
 * for [kind] (request_id / auction_id / offer_id / bid_id), surfaced prominently by the UI. [message]
 * carries any engine detail/error/note.
 */
data class StakeAuctionAck(
    val accepted: Boolean,
    val kind: StakeAuctionKind,
    val createdId: Long?,
    val message: String?,
) {
    /** Human label for [createdId], e.g. "Request #42" / "Auction #7" (null when no id came back). */
    val idLabel: String? get() = createdId?.let {
        when (kind) {
            StakeAuctionKind.STAKE_REQUEST -> "Request #$it"
            StakeAuctionKind.STAKE_OFFER -> "Offer #$it"
            StakeAuctionKind.AUCTION_REQUEST -> "Auction #$it"
            StakeAuctionKind.AUCTION_BID -> "Bid #$it"
        }
    }
}

private fun ackAccepted(status: String?, result: Int?): Boolean {
    val ok = when (status?.lowercase()) {
        "ack", "ok", "accepted", "created" -> true
        else -> false
    }
    return ok && (result ?: 0) == 0
}

fun StakeAuctionAckDto.toDomain(kind: StakeAuctionKind): StakeAuctionAck {
    val createdId = when (kind) {
        StakeAuctionKind.STAKE_REQUEST -> requestId
        StakeAuctionKind.STAKE_OFFER -> offerId ?: requestId
        StakeAuctionKind.AUCTION_REQUEST -> auctionId
        StakeAuctionKind.AUCTION_BID -> bidId ?: auctionId
    }
    return StakeAuctionAck(
        accepted = ackAccepted(status, result),
        kind = kind,
        createdId = createdId,
        message = detail ?: error ?: note ?: reason,
    )
}
