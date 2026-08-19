package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.Fill
import com.testlogon.android.data.exchange.FeeSchedule
import com.testlogon.android.data.exchange.FillsFees
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
    val liquidations: Liquidations? = null,
    val fundingPayments: FundingPayments? = null,
    /** symbolId -> ticker, for labelling the account-wide liquidation/funding/fills feeds. */
    val symbolNames: Map<Int, String> = emptyMap(),
) {
    /** Ticker for [symbolId] from the resolved catalogue, else "#<id>". */
    fun symbolLabel(symbolId: Int): String = symbolNames[symbolId] ?: ("#" + symbolId)
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
