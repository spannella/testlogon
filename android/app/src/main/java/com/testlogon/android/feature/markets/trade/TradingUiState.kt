package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.Fill
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.data.exchange.SpotBalance

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
) {
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
