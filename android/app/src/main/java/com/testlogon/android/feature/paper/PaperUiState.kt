package com.testlogon.android.feature.paper

import com.testlogon.android.data.exchange.Instrument
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.paper.PaperEngine.PaperOrderType

/**
 * Render-ready UI state for the self-contained Paper Trading screen. The ViewModel keeps the pure
 * [PaperEngine.PaperAccount] internally and projects it (plus the selected symbol, live mark, and the
 * user's staged order-ticket inputs) into this immutable shape. Nothing here moves real money.
 */
data class PaperUiState(
    val loading: Boolean = true,
    // ---- market data ----
    val symbols: List<Instrument> = emptyList(),
    val selectedSymbolId: Int? = null,
    /** Latest simulated mark price for the selected symbol (raw ticks), null until first quote. */
    val markPrice: Long? = null,
    // ---- account panel ----
    val startingCash: Long = 0L,
    val cash: Long = 0L,
    val equity: Long = 0L,
    val realizedPnl: Long = 0L,
    val unrealizedPnl: Long = 0L,
    // ---- tables ----
    val positions: List<PaperPositionRow> = emptyList(),
    val workingOrders: List<PaperOrderRow> = emptyList(),
    val fills: List<PaperFillRow> = emptyList(),
    // ---- order ticket ----
    val ticket: PaperTicket = PaperTicket(),
    // ---- transient one-shot user feedback (consumed by the screen) ----
    val toast: String? = null,
) {
    val selectedSymbol: Instrument?
        get() = symbols.firstOrNull { it.symbolId == selectedSymbolId }

    val totalPnl: Long get() = realizedPnl + unrealizedPnl
    val isEquityUp: Boolean get() = equity >= startingCash
}

/** The user's staged order-ticket inputs (raw strings so the field can hold partial/invalid text). */
data class PaperTicket(
    val side: OrderSide = OrderSide.BUY,
    val type: PaperOrderType = PaperOrderType.MARKET,
    val qtyInput: String = "",
    val limitPriceInput: String = "",
) {
    val qty: Long? get() = qtyInput.trim().toLongOrNull()?.takeIf { it > 0 }
    val limitPrice: Long? get() = limitPriceInput.trim().toLongOrNull()?.takeIf { it > 0 }

    /** True when the ticket has enough valid input to submit (limit requires a price). */
    fun isValid(): Boolean =
        qty != null && (type == PaperOrderType.MARKET || limitPrice != null)
}

/** One open-position row (signed qty long/short, avg entry, live mark, unrealized). */
data class PaperPositionRow(
    val symbolId: Int,
    val symbol: String,
    val qty: Long,
    val avgEntry: Long,
    val mark: Long?,
    val unrealized: Long,
) {
    val isLong: Boolean get() = qty >= 0
    val isProfit: Boolean get() = unrealized >= 0
}

/** One working (resting) order row (cancellable). */
data class PaperOrderRow(
    val id: String,
    val symbol: String,
    val side: OrderSide,
    val qty: Long,
    val limitPrice: Long?,
)

/** One historical fill row (newest first in the list). */
data class PaperFillRow(
    val symbol: String,
    val side: OrderSide,
    val price: Long,
    val qty: Long,
    val tsMs: Long,
)
