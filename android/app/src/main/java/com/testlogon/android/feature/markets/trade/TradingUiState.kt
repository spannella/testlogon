package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.Fill
import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide

/** Order entry type. LIMIT is the plain resting limit; the rest map to advanced engine endpoints. */
enum class OrderType(val label: String) {
    LIMIT("Limit"),
    STOP("Stop"),
    STOP_LIMIT("Stop-Limit"),
    TAKE_PROFIT("Take-Profit"),
    QUOTE("Quote"),
    OTO("OTO"),
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

    /** Whether the current order-type has all the fields it needs to submit. */
    val canSubmit: Boolean get() = !placing && when (orderType) {
        OrderType.LIMIT -> (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.STOP -> (stopLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.STOP_LIMIT -> (stopLong ?: 0L) > 0L && (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.TAKE_PROFIT -> (stopLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.QUOTE -> (bidLong ?: 0L) > 0L && (askLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
        OrderType.OTO -> (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L && (childPriceLong ?: 0L) > 0L && (childQtyLong ?: 0L) > 0L
    }
}
