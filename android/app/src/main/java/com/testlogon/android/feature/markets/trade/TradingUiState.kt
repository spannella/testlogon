package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.MarginAccount
import com.testlogon.android.data.exchange.OrderSide

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
) {
    val priceLong: Long? get() = priceText.toLongOrNull()
    val qtyLong: Long? get() = qtyText.toLongOrNull()
    val orderValue: Long? get() {
        val p = priceLong ?: return null
        val q = qtyLong ?: return null
        return p * q
    }
    val canPlace: Boolean get() = !placing && (priceLong ?: 0L) > 0L && (qtyLong ?: 0L) > 0L
}
