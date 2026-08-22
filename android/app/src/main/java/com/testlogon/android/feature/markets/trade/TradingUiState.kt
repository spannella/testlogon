package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.Fill
import com.testlogon.android.data.exchange.FeeSchedule
import com.testlogon.android.data.exchange.FillsFees
import com.testlogon.android.data.exchange.LiveOrders
import com.testlogon.android.data.exchange.LiveOrder
import com.testlogon.android.data.exchange.Liquidations
import com.testlogon.android.data.exchange.FundingPayments
import com.testlogon.android.data.exchange.feeFor
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.SpotBalance
import com.testlogon.android.data.exchange.MarginConfigAck
import com.testlogon.android.data.exchange.EngineConfigAck
import com.testlogon.android.core.model.ApiResult

/** Order entry type. LIMIT is the plain resting limit; the rest map to advanced engine endpoints. */
enum class OrderType(val label: String) {
    LIMIT("Limit"),
    MARKET("Market"),
    STOP("Stop"),
    STOP_LIMIT("Stop-Limit"),
    TAKE_PROFIT("Take-Profit"),
    QUOTE("Quote"),
    OTO("OTO"),
    OCO("OCO"),
    FUNDING("Funding"),
}

/**
 * Pre-staged surfaces that depend on backend routes not yet live through the prod edge. Flip a flag
 * to true once the corresponding backend port lands. Everything behind these is wired + build-green.
 */
object TradingFeatures {
    const val OCO_ENABLED = false      // POST /me/oco (edge returns no_response today)
    const val FUNDING_ENABLED = false  // POST /me/funding_order (rejects reason 30 today)
    const val SPOT_ENABLED = false     // GET /me/spot_balance + POST /me/spot_deposit (needs asset-id map)
}

/** Whether an order type is exposed in the selector (advanced ones gate on [TradingFeatures]). */
fun OrderType.isAvailable(): Boolean = when (this) {
    OrderType.OCO -> TradingFeatures.OCO_ENABLED
    OrderType.FUNDING -> TradingFeatures.FUNDING_ENABLED
    else -> true
}

/** The order-tab is split into these sections so entry isn't buried under positions/orders/fills. */
enum class TicketSection(val label: String) {
    TRADE("Trade"),
    POSITIONS("Positions"),
    ORDERS("Orders"),
    FILLS("Fills"),
    LIQUIDATIONS("Liq"),
    FUNDING("Funding"),
}

/** A working order this session placed (the engine has no server-side list, so we track our own). */
data class WorkingOrder(
    val clordid: String,
    val side: OrderSide,
    val price: Long,
    val qty: Long,
    val orderId: Long?,
)

/**
 * Order-ticket + working-orders state for one symbol. Prices/qty are raw integers (scaler = 1).
 * [message] carries the last place/cancel result (green) or rejection/error (red via [messageIsError]).
 */
data class TradingUiState(
    val side: OrderSide = OrderSide.BUY,
    val priceText: String = "",
    val qtyText: String = "",
    val placing: Boolean = false,
    val message: String? = null,
    val messageIsError: Boolean = false,
    val account: MarginAccount? = null,
    val workingOrders: List<WorkingOrder> = emptyList(),
    val sessionFills: List<Fill> = emptyList(),
    val amendingClordid: String? = null,
    val depositText: String = "",
    val depositing: Boolean = false,
    val orderType: OrderType = OrderType.LIMIT,
    val stopText: String = "",
    val bidText: String = "",
    val askText: String = "",
    val childPriceText: String = "",
    val childQtyText: String = "",
    val tif: String = "GTC",
    val postOnly: Boolean = false,
    val hidden: Boolean = false,
    val aon: Boolean = false,
    val displayText: String = "",
    val minQtyText: String = "",
    val expiryMinText: String = "",
    val advancedOpen: Boolean = false,
    val fundingRateText: String = "",
    val fundingQtyText: String = "",
    val fundingDurationText: String = "",
    val fundingBorrow: Boolean = true,
    val spotBalance: SpotBalance? = null,
    val spotAssetText: String = "",
    val spotAmountText: String = "",
    val section: TicketSection = TicketSection.TRADE,
    val armed: String? = null,        // "market" | "close" -> a confirm is pending (skipped when oneTap)
    val oneTap: Boolean = false,      // when true, market/close fire without a confirm step
    // ---- PAPER MODE (client-side simulation; shares the Paper screen's account/store) ----
    val paperMode: Boolean = false,   // when true, submits route to PaperEngine, NOT /me/orders
    val paperCash: Long? = null,      // simulated free cash (null until the paper account loads)
    // Position-size / risk calculator (collapsible). riskAmount + stop -> qty via OrderMath.
    val riskCalcOpen: Boolean = false,
    val riskAmountText: String = "",
    val riskStopText: String = "",
    // Risk-% sizer (equity * pct / stop distance -> qty via OrderCalc.positionSizeQty).
    val riskPctText: String = "",
    // Bracket helper: optional attached take-profit + stop-loss placed after the entry fills.
    val bracketEnabled: Boolean = false,
    val bracketTpText: String = "",
    val bracketSlText: String = "",
    // Client-side algo orders (TWAP / Iceberg). algoMode swaps the entry panel for the algo builder.
    val algoMode: Boolean = false,
    val algoKind: AlgoKind = AlgoKind.TWAP,
    val algoTotalQtyText: String = "",
    val algoSlicesText: String = "",
    val algoDurationSecText: String = "",
    val algoVisibleText: String = "",
    val algoIntervalSecText: String = "",
    val algoUseLimit: Boolean = false,
    val algoLimitText: String = "",
    val pm: com.testlogon.android.data.exchange.PmState? = null,   // set when this symbol is a binary prediction market
    val isAdmin: Boolean = false,   // resolved from CurrentUserRepository; gates the margin-config panel
    val marginConfig: MarginConfigForm = MarginConfigForm(),
    // Admin engine-config forms (exchange-admin-config); shown only when isAdmin.
    val matchingAlgo: MatchingAlgoForm = MatchingAlgoForm(),
    val spreadConfig: SpreadConfigForm = SpreadConfigForm(),
    val tradingParams: TradingParamsForm = TradingParamsForm(),
    val riskConfig: RiskConfigForm = RiskConfigForm(),
    val spotIndex: SpotIndexForm = SpotIndexForm(),
    val spotConfig: SpotConfigForm = SpotConfigForm(),
    // Admin prediction-markets forms (exchange-admin-config); shown only when isAdmin.
    val pmCreateBinary: PmCreateBinaryForm = PmCreateBinaryForm(),
    val pmCreateCategorical: PmCreateCategoricalForm = PmCreateCategoricalForm(),
    val pmResolveBinary: PmResolveBinaryForm = PmResolveBinaryForm(),
    val pmResolveCategorical: PmResolveCategoricalForm = PmResolveCategoricalForm(),
    val pmResolutions: List<com.testlogon.android.data.exchange.PmResolution> = emptyList(),
    val feeSchedule: FeeSchedule? = null,
    val fillsFees: FillsFees? = null,
    val liveOrders: LiveOrders? = null,
    val liquidations: Liquidations? = null,
    val fundingPayments: FundingPayments? = null,
    /** symbolId -> ticker, for labelling the account-wide liquidation/funding/fills feeds. */
    val symbolNames: Map<Int, String> = emptyMap(),
    // Trader staking + auctions forms (peer mechanisms); trader-facing (NOT admin-gated).
    val stakeRequest: StakeRequestForm = StakeRequestForm(),
    val stakeOffer: StakeOfferForm = StakeOfferForm(),
    val auctionRequest: AuctionRequestForm = AuctionRequestForm(),
    val auctionBid: AuctionBidForm = AuctionBidForm(),
    // Discovery browse (STUB): open stake requests + auctions (read subsections).
    val stakeRequestsBrowse: com.testlogon.android.data.exchange.StakeRequestsBrowse? = null,
    val auctionsBrowse: com.testlogon.android.data.exchange.AuctionsBrowse? = null,
) {
    /** Ticker for [symbolId] from the resolved catalogue, else "#<id>". */
    fun symbolLabel(symbolId: Int): String = symbolNames[symbolId] ?: ("#" + symbolId)

    /**
     * The working orders to display + manage. Prefers the LIVE server feed (survives restarts, includes
     * quote/OTO legs) when it has loaded; otherwise falls back to this session's locally-tracked list.
     * Both expose a clordid so per-row Amend/Cancel + Cancel-all work identically either way.
     */
    val displayOrders: List<WorkingOrder> get() {
        val live = liveOrders?.orders
        return if (live != null && live.isNotEmpty()) {
            live.map { lo -> WorkingOrder(lo.clordid, lo.side ?: OrderSide.BUY, lo.price, lo.qty, lo.orderId) }
        } else {
            workingOrders
        }
    }
    /** Count for the Orders tab badge: the live feed's count when loaded, else the session list size. */
    val ordersBadgeCount: Int get() = liveOrders?.orders?.size?.takeIf { it > 0 } ?: workingOrders.size
    val isAmending: Boolean get() = amendingClordid != null
    val depositLong: Long? get() = depositText.toLongOrNull()
    val canDeposit: Boolean get() = !depositing && (depositLong ?: 0L) > 0L
    val priceLong: Long? get() = priceText.toLongOrNull()
    val qtyLong: Long? get() = qtyText.toLongOrNull()
    val orderValue: Long? get() {
        val p = priceLong ?: return null
        val q = qtyLong ?: return null
        return p * q
    }
    val canPlace: Boolean get() = !placing && (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
    val stopLong: Long? get() = stopText.toLongOrNull()
    val bidLong: Long? get() = bidText.toLongOrNull()
    val askLong: Long? get() = askText.toLongOrNull()
    val childPriceLong: Long? get() = childPriceText.toLongOrNull()
    val childQtyLong: Long? get() = childQtyText.toLongOrNull()
    val displayQtyLong: Long? get() = displayText.toLongOrNull()
    val minQtyLong: Long? get() = minQtyText.toLongOrNull()
    val expiryMinLong: Long? get() = expiryMinText.toLongOrNull()
    val fundingRateLong: Long? get() = fundingRateText.toLongOrNull()
    val fundingQtyLong: Long? get() = fundingQtyText.toLongOrNull()
    val fundingDurationLong: Long? get() = fundingDurationText.toLongOrNull()
    val spotAssetInt: Int? get() = spotAssetText.toIntOrNull()
    val spotAmountLong: Long? get() = spotAmountText.toLongOrNull()

    /** A short prompt for what's missing, shown when submit is disabled (crisper than a dead button). */
    val entryHint: String? get() = if (placing || canSubmit) null else when (orderType) {
        OrderType.LIMIT -> "Enter price and quantity"
        OrderType.MARKET -> "Enter a quantity"
        OrderType.STOP, OrderType.TAKE_PROFIT -> "Enter trigger price and quantity"
        OrderType.STOP_LIMIT -> "Enter stop, limit and quantity"
        OrderType.QUOTE -> "Enter bid, ask and quantity"
        OrderType.OTO, OrderType.OCO -> "Enter both legs' price and quantity"
        OrderType.FUNDING -> "Enter rate and quantity"
    }

    /** Whether the current order-type has all the fields it needs to submit. */
    val canSubmit: Boolean get() = !placing && when (orderType) {
        OrderType.LIMIT -> (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.MARKET -> (qtyLong ?: 0L) > 0L
        OrderType.STOP -> (stopLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.STOP_LIMIT -> (stopLong ?: 0L) > 0L && (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.TAKE_PROFIT -> (stopLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.QUOTE -> (bidLong ?: 0L) > 0L && (askLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.OTO -> (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L && (childPriceLong ?: 0L) > 0L && (childQtyLong ?: 0L) > 0L
        OrderType.OCO -> (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L && (childPriceLong ?: 0L) > 0L && (childQtyLong ?: 0L) > 0L
        OrderType.FUNDING -> (fundingRateLong ?: 0L) > 0L && (fundingQtyLong ?: 0L) > 0L
    }

    // ---- Order-entry math (client-computed preview + sizing) ----

    /** Available margin balance, or null when the account hasn't loaded. */
    val availableBalance: Long? get() = account?.availableBalance

    /** Buying power the ticket sizes against: paper cash in paper mode, else real available. */
    val effectiveBuyingPower: Long? get() = if (paperMode) paperCash else availableBalance

    /** The price used for preview/sizing: the entered limit price, else the stop/trigger. */
    val entryRefPrice: Long? get() = priceLong ?: stopLong

    /** Exact notional (price x qty) for the ticket preview. */
    val previewNotional: Long? get() = OrderMath.notional(entryRefPrice, qtyLong)

    /** Max whole qty affordable at the reference price from available balance (no leverage). */
    fun maxAffordableQty(refPrice: Long?): Long =
        OrderMath.maxQtyForBalance(effectiveBuyingPower, refPrice ?: entryRefPrice)

    /** Risk-calculator inputs. */
    val riskAmountLong: Long? get() = riskAmountText.toLongOrNull()
    val riskStopLong: Long? get() = riskStopText.toLongOrNull()

    /** qty implied by the risk budget + stop distance (0 when inputs are incomplete). */
    fun riskSizedQty(refPrice: Long?): Long =
        OrderMath.riskSizedQty(riskAmountLong, refPrice ?: entryRefPrice, riskStopLong)

    /** Initial margin the current order would lock, using [initialMarginBps]. */
    fun previewMarginRequired(initialMarginBps: Long): Long =
        OrderMath.marginRequired(previewNotional, initialMarginBps)

    /** Estimated liquidation price of the current order, using [maintenanceMarginBps]. */
    fun previewLiquidationPrice(maintenanceMarginBps: Long): Long? =
        OrderMath.estLiquidationPrice(entryRefPrice, side, maintenanceMarginBps)

    // ---- Risk-% sizer + bracket + algo (order-entry depth) ----

    val riskPctInt: Int? get() = riskPctText.toIntOrNull()

    /** Qty from equity * riskPct / |entry - stop| (0 when inputs are incomplete). */
    fun riskPctSizedQty(refPrice: Long?): Long =
        OrderCalc.positionSizeQty(effectiveBuyingPower, riskPctInt ?: 0, refPrice ?: entryRefPrice, riskStopLong)

    val bracketTpLong: Long? get() = bracketTpText.toLongOrNull()
    val bracketSlLong: Long? get() = bracketSlText.toLongOrNull()

    /** Risk:reward for the bracket (entry + SL + TP). Null until all three are set with non-zero risk. */
    fun bracketRiskReward(refPrice: Long?): OrderCalc.RiskReward? =
        OrderCalc.riskReward(refPrice ?: entryRefPrice, bracketSlLong, bracketTpLong)

    /** Break-even price after round-trip taker fees (est.), using the fee schedule when present. */
    fun breakevenPrice(refPrice: Long?): Long? =
        OrderCalc.breakevenPrice(refPrice ?: entryRefPrice, side, feeSchedule?.takerFeeBps?.toLong() ?: 0L)

    // Algo builder parse accessors.
    val algoTotalQtyLong: Long? get() = algoTotalQtyText.toLongOrNull()
    val algoSlicesInt: Int? get() = algoSlicesText.toIntOrNull()
    val algoDurationSecLong: Long? get() = algoDurationSecText.toLongOrNull()
    val algoVisibleLong: Long? get() = algoVisibleText.toLongOrNull()
    val algoIntervalSecLong: Long? get() = algoIntervalSecText.toLongOrNull()
    val algoLimitLong: Long? get() = algoLimitText.toLongOrNull()

    /** Whether the algo builder has the fields it needs to start. */
    val canStartAlgo: Boolean get() = when (algoKind) {
        AlgoKind.TWAP -> (algoTotalQtyLong ?: 0L) > 0L && (algoSlicesInt ?: 0) > 0 &&
            (algoSlicesInt ?: 0).toLong() <= (algoTotalQtyLong ?: 0L) && (algoDurationSecLong ?: 0L) > 0L &&
            (!algoUseLimit || (algoLimitLong ?: 0L) > 0L)
        AlgoKind.ICEBERG -> (algoTotalQtyLong ?: 0L) > 0L && (algoVisibleLong ?: 0L) > 0L &&
            (algoIntervalSecLong ?: 0L) > 0L && (!algoUseLimit || (algoLimitLong ?: 0L) > 0L)
    }
}


/**
 * Admin-only per-symbol margin-config form. All numeric fields are entered as plain integers (bps or a
 * raw qty). [symbolText] defaults to the ticket's symbol but is editable so an admin can retarget it.
 */
data class MarginConfigForm(
    val symbolText: String = "",
    val initialMarginText: String = "",
    val maintenanceMarginText: String = "",
    val liquidationFeeText: String = "",
    val hourlyBorrowText: String = "",
    val makerFeeText: String = "",
    val takerFeeText: String = "",
    val maxPositionText: String = "",
    val submitting: Boolean = false,
    val result: MarginConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val initialMarginLong: Long? get() = initialMarginText.toLongOrNull()
    val maintenanceMarginLong: Long? get() = maintenanceMarginText.toLongOrNull()
    val liquidationFeeLong: Long? get() = liquidationFeeText.toLongOrNull()
    val hourlyBorrowLong: Long? get() = hourlyBorrowText.toLongOrNull()
    val makerFeeLong: Long? get() = makerFeeText.toLongOrNull()
    val takerFeeLong: Long? get() = takerFeeText.toLongOrNull()
    val maxPositionLong: Long? get() = maxPositionText.toLongOrNull()

    /** All eight fields must parse (bps may be 0; symbol + max position must be present). */
    val canSubmit: Boolean get() = !submitting &&
        symbolInt != null &&
        initialMarginLong != null && maintenanceMarginLong != null &&
        liquidationFeeLong != null && hourlyBorrowLong != null &&
        makerFeeLong != null && takerFeeLong != null &&
        maxPositionLong != null
}

/**
 * Admin engine-config forms (exchange-admin-config). Each mirrors [MarginConfigForm]: plain-integer
 * text fields with parse accessors + a [canSubmit] gate + submitting/result/error. Optional engine
 * params are left blank (null on the wire); required ones must parse.
 */
data class MatchingAlgoForm(
    val symbolText: String = "",
    val algo: Int = 0,                     // 0 = price-time, 1 = pro-rata, 2 = specialist
    val specialistMpidText: String = "",
    val specialistPctText: String = "",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val specialistPctInt: Int? get() = specialistPctText.toIntOrNull()
    val specialistMpid: String? get() = specialistMpidText.trim().ifEmpty { null }
    val canSubmit: Boolean get() = !submitting && symbolInt != null
}

data class SpreadConfigForm(
    val spreadSymbolText: String = "",
    val leg1Text: String = "",
    val leg2Text: String = "",
    val leg1RatioText: String = "1",
    val leg2RatioText: String = "-1",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val spreadSymbolInt: Int? get() = spreadSymbolText.toIntOrNull()
    val leg1Int: Int? get() = leg1Text.toIntOrNull()
    val leg2Int: Int? get() = leg2Text.toIntOrNull()
    val leg1RatioInt: Int? get() = leg1RatioText.toIntOrNull()
    val leg2RatioInt: Int? get() = leg2RatioText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting && spreadSymbolInt != null && leg1Int != null && leg2Int != null
}

data class TradingParamsForm(
    val symbolText: String = "",
    val maxQtyText: String = "",
    val maxNotionalText: String = "",
    val priceBandPctText: String = "",
    val circuitBreakerPctText: String = "",
    val minBlockSizeText: String = "",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val maxQtyInt: Int? get() = maxQtyText.toIntOrNull()
    val maxNotionalLong: Long? get() = maxNotionalText.toLongOrNull()
    val priceBandPctLong: Long? get() = priceBandPctText.toLongOrNull()
    val circuitBreakerPctLong: Long? get() = circuitBreakerPctText.toLongOrNull()
    val minBlockSizeInt: Int? get() = minBlockSizeText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting && symbolInt != null
}

data class RiskConfigForm(
    val maxNotionalText: String = "",
    val windowSecondsText: String = "",
    val mpidText: String = "",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val maxNotionalLong: Long? get() = maxNotionalText.toLongOrNull()
    val windowSecondsInt: Int? get() = windowSecondsText.toIntOrNull()
    val mpid: String? get() = mpidText.trim().ifEmpty { null }
    val canSubmit: Boolean get() = !submitting && maxNotionalLong != null && windowSecondsInt != null && windowSecondsInt!! > 0
}

data class SpotIndexForm(
    val symbolText: String = "",
    val spotIndexPriceText: String = "",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val spotIndexPriceLong: Long? get() = spotIndexPriceText.toLongOrNull()
    val canSubmit: Boolean get() = !submitting && symbolInt != null && spotIndexPriceLong != null
}

data class SpotConfigForm(
    val symbolText: String = "",
    val baseAssetText: String = "",
    val quoteAssetText: String = "",
    val submitting: Boolean = false,
    val result: EngineConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val baseAssetInt: Int? get() = baseAssetText.toIntOrNull()
    val quoteAssetInt: Int? get() = quoteAssetText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting && symbolInt != null && baseAssetInt != null && quoteAssetInt != null
}

private const val NET_ERR = "Network error. Check your connection and try again."

fun MatchingAlgoForm.finish(r: ApiResult<EngineConfigAck>): MatchingAlgoForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

fun SpreadConfigForm.finish(r: ApiResult<EngineConfigAck>): SpreadConfigForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

fun TradingParamsForm.finish(r: ApiResult<EngineConfigAck>): TradingParamsForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

fun RiskConfigForm.finish(r: ApiResult<EngineConfigAck>): RiskConfigForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

fun SpotIndexForm.finish(r: ApiResult<EngineConfigAck>): SpotIndexForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

fun SpotConfigForm.finish(r: ApiResult<EngineConfigAck>): SpotConfigForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = NET_ERR)
}

// ==== Admin prediction-markets (exchange-admin-config) — form state ====

/** Import alias: the PM admin ack + resolution domain types live in data.exchange. */

/**
 * Admin form: configure a BINARY PM on a symbol. [faceText] is the payout on YES (must parse and be
 * > 1); [resolverText] is an optional designated resolver id (blank -> null on the wire).
 */
data class PmCreateBinaryForm(
    val symbolText: String = "",
    val faceText: String = "",
    val resolverText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.PmConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val faceLong: Long? get() = faceText.toLongOrNull()
    val resolver: String? get() = resolverText.trim().ifEmpty { null }
    val canSubmit: Boolean get() = !submitting && symbolInt != null && (faceLong ?: 0L) > 1L
}

/**
 * Admin form: configure a CATEGORICAL (grouped) PM. [outcomesText] is a comma/space-separated list of
 * outcome symbol ids (>= 2 distinct); [faceText] the shared payout (> 1).
 */
data class PmCreateCategoricalForm(
    val groupText: String = "",
    val outcomesText: String = "",
    val faceText: String = "",
    val resolverText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.PmConfigAck? = null,
    val error: String? = null,
) {
    val groupInt: Int? get() = groupText.toIntOrNull()
    val faceLong: Long? get() = faceText.toLongOrNull()
    val resolver: String? get() = resolverText.trim().ifEmpty { null }
    /** Parse the outcome ids from a comma/space/newline-separated list, de-duplicated, order-preserving. */
    val outcomes: List<Int> get() = outcomesText
        .split(',', ' ', '\n', '\t')
        .mapNotNull { it.trim().toIntOrNull() }
        .distinct()
    val canSubmit: Boolean get() = !submitting && (groupInt ?: 0) > 0 && (faceLong ?: 0L) > 1L && outcomes.size >= 2
}

/** Admin form: resolve a BINARY PM to yes/no. [yes] holds the selected outcome. */
data class PmResolveBinaryForm(
    val symbolText: String = "",
    val yes: Boolean = true,
    val sourceText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.PmConfigAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val source: String? get() = sourceText.trim().ifEmpty { null }
    val outcome: String get() = if (yes) "yes" else "no"
    val canSubmit: Boolean get() = !submitting && symbolInt != null
}

/** Admin form: resolve a CATEGORICAL PM by its winning outcome symbol id. */
data class PmResolveCategoricalForm(
    val groupText: String = "",
    val winningText: String = "",
    val sourceText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.PmConfigAck? = null,
    val error: String? = null,
) {
    val groupInt: Int? get() = groupText.toIntOrNull()
    val winningInt: Int? get() = winningText.toIntOrNull()
    val source: String? get() = sourceText.trim().ifEmpty { null }
    val canSubmit: Boolean get() = !submitting && (groupInt ?: 0) > 0 && winningInt != null
}

private const val PM_NET_ERR = "Network error. Check your connection and try again."

fun PmCreateBinaryForm.finish(r: ApiResult<com.testlogon.android.data.exchange.PmConfigAck>): PmCreateBinaryForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = PM_NET_ERR)
}

fun PmCreateCategoricalForm.finish(r: ApiResult<com.testlogon.android.data.exchange.PmConfigAck>): PmCreateCategoricalForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = PM_NET_ERR)
}

fun PmResolveBinaryForm.finish(r: ApiResult<com.testlogon.android.data.exchange.PmConfigAck>): PmResolveBinaryForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = PM_NET_ERR)
}

fun PmResolveCategoricalForm.finish(r: ApiResult<com.testlogon.android.data.exchange.PmConfigAck>): PmResolveCategoricalForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = PM_NET_ERR)
}

// ==== Trader staking + auctions (peer mechanisms) — form state ====

/** Import alias: the staking/auction ack domain type lives in data.exchange. */

/**
 * Trader form: create a stake request. [symbolText] defaults to the ticket symbol but is editable.
 * [minCollateralText]/[maxStakePctText] are raw integers; [lockupSecondsText]/[durationSecondsText]
 * are seconds. [result] holds the last ack (which surfaces the returned request_id).
 */
data class StakeRequestForm(
    val symbolText: String = "",
    val minCollateralText: String = "",
    val maxStakePctText: String = "",
    val lockupSecondsText: String = "",
    val durationSecondsText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.StakeAuctionAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val minCollateralLong: Long? get() = minCollateralText.toLongOrNull()
    val maxStakePctLong: Long? get() = maxStakePctText.toLongOrNull()
    val lockupSecondsInt: Int? get() = lockupSecondsText.toIntOrNull()
    val durationSecondsInt: Int? get() = durationSecondsText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting &&
        (minCollateralLong ?: 0L) > 0L && (maxStakePctLong ?: 0L) > 0L &&
        (lockupSecondsInt ?: 0) > 0 && (durationSecondsInt ?: 0) > 0
}

/** Trader form: offer collateral to stake against an open stake request (by id). */
data class StakeOfferForm(
    val requestIdText: String = "",
    val collateralText: String = "",
    val stakePctText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.StakeAuctionAck? = null,
    val error: String? = null,
) {
    val requestIdLong: Long? get() = requestIdText.toLongOrNull()
    val collateralLong: Long? get() = collateralText.toLongOrNull()
    val stakePctLong: Long? get() = stakePctText.toLongOrNull()
    val canSubmit: Boolean get() = !submitting &&
        (requestIdLong ?: 0L) > 0L && (collateralLong ?: 0L) > 0L && (stakePctLong ?: 0L) > 0L
}

/**
 * Trader form: auction off a position quantity. [symbolText] defaults to the ticket symbol.
 * [reservePriceText]/[durationSecondsText] are optional (blank -> null on the wire).
 */
data class AuctionRequestForm(
    val symbolText: String = "",
    val qtyText: String = "",
    val reservePriceText: String = "",
    val durationSecondsText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.StakeAuctionAck? = null,
    val error: String? = null,
) {
    val symbolInt: Int? get() = symbolText.toIntOrNull()
    val qtyInt: Int? get() = qtyText.toIntOrNull()
    val reservePriceLong: Long? get() = reservePriceText.toLongOrNull()
    val durationSecondsInt: Int? get() = durationSecondsText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting && (qtyInt ?: 0) > 0
}

/** Trader form: bid on an open auction (by id). */
data class AuctionBidForm(
    val auctionIdText: String = "",
    val priceText: String = "",
    val qtyText: String = "",
    val submitting: Boolean = false,
    val result: com.testlogon.android.data.exchange.StakeAuctionAck? = null,
    val error: String? = null,
) {
    val auctionIdLong: Long? get() = auctionIdText.toLongOrNull()
    val priceLong: Long? get() = priceText.toLongOrNull()
    val qtyInt: Int? get() = qtyText.toIntOrNull()
    val canSubmit: Boolean get() = !submitting &&
        (auctionIdLong ?: 0L) > 0L && (priceLong ?: 0L) > 0L && (qtyInt ?: 0) > 0
}

private const val STAKE_NET_ERR = "Network error. Check your connection and try again."

fun StakeRequestForm.finish(r: ApiResult<com.testlogon.android.data.exchange.StakeAuctionAck>): StakeRequestForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data, error = null)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = STAKE_NET_ERR)
}

fun StakeOfferForm.finish(r: ApiResult<com.testlogon.android.data.exchange.StakeAuctionAck>): StakeOfferForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data, error = null)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = STAKE_NET_ERR)
}

fun AuctionRequestForm.finish(r: ApiResult<com.testlogon.android.data.exchange.StakeAuctionAck>): AuctionRequestForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data, error = null)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = STAKE_NET_ERR)
}

fun AuctionBidForm.finish(r: ApiResult<com.testlogon.android.data.exchange.StakeAuctionAck>): AuctionBidForm = when (r) {
    is ApiResult.Success -> copy(submitting = false, result = r.data, error = null)
    is ApiResult.Failure -> copy(submitting = false, error = r.error.message)
    is ApiResult.NetworkError -> copy(submitting = false, error = STAKE_NET_ERR)
}
