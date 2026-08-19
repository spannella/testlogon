package com.testlogon.android.feature.markets.trade

import com.testlogon.android.data.exchange.LiveOrder
import com.testlogon.android.data.exchange.LiveOrders
import com.testlogon.android.data.exchange.OrderSide
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * Aggregation logic for the Orders section source selection: [TradingUiState.displayOrders] prefers the
 * LIVE server feed when it has rows, otherwise falls back to the session-tracked list; and
 * [TradingUiState.ordersBadgeCount] mirrors that with the same precedence.
 */
class TradingOrdersStateTest {

    private fun wo(id: String) = WorkingOrder(id, OrderSide.BUY, 100L, 1L, null)
    private fun lo(id: String, side: OrderSide = OrderSide.SELL, price: Long = 50L, qty: Long = 3L) =
        LiveOrder(clordid = id, orderId = null, symbolId = 1, side = side, price = price, qty = qty, tif = null, tsNs = 0L)

    @Test
    fun displayOrders_prefersLiveFeed_whenNonEmpty() {
        val state = TradingUiState(
            workingOrders = listOf(wo("session")),
            liveOrders = LiveOrders(listOf(lo("live1"), lo("live2")), 2),
        )
        assertEquals(listOf("live1", "live2"), state.displayOrders.map { it.clordid })
        assertEquals(2, state.ordersBadgeCount)
    }

    @Test
    fun displayOrders_fallsBackToSession_whenLiveNullOrEmpty() {
        val nullLive = TradingUiState(workingOrders = listOf(wo("s1"), wo("s2")), liveOrders = null)
        assertEquals(listOf("s1", "s2"), nullLive.displayOrders.map { it.clordid })
        assertEquals(2, nullLive.ordersBadgeCount)

        val emptyLive = nullLive.copy(liveOrders = LiveOrders(emptyList(), 0))
        assertEquals(listOf("s1", "s2"), emptyLive.displayOrders.map { it.clordid })
        assertEquals(2, emptyLive.ordersBadgeCount)
    }

    @Test
    fun liveOrder_mapsToWorkingOrder_preservingSidePriceQty() {
        val state = TradingUiState(liveOrders = LiveOrders(listOf(lo("a", OrderSide.SELL, 77L, 9L)), 1))
        val row = state.displayOrders.single()
        assertEquals(OrderSide.SELL, row.side)
        assertEquals(77L, row.price)
        assertEquals(9L, row.qty)
    }

    @Test
    fun liveOrder_nullSide_defaultsToBuyForDisplay() {
        val state = TradingUiState(
            liveOrders = LiveOrders(listOf(lo("a").copy(side = null)), 1),
        )
        assertEquals(OrderSide.BUY, state.displayOrders.single().side)
    }
}
