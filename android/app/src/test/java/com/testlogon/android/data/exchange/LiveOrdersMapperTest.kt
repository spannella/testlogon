package com.testlogon.android.data.exchange

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Unit coverage for the LIVE working-orders read (GET me/orders/live) DTO -> domain mappers. Exercises
 * the defensive parsing the endpoint needs: side resolution, the qty fallback chain
 * (remaining -> leaves -> qty), the alternate `working_orders` key, rows dropped for a missing clordid,
 * count fallback, and null/blank field defaulting.
 */
class LiveOrdersMapperTest {

    @Test
    fun row_mapsAllFields() {
        val o = LiveOrderDto(
            clordid = "abc",
            orderId = 42L,
            symbolId = 7,
            side = "sell",
            price = 100L,
            qty = 5L,
            tif = "GTC",
            tsNs = 123L,
        ).toDomain()
        assertEquals("abc", o.clordid)
        assertEquals(42L, o.orderId)
        assertEquals(7, o.symbolId)
        assertEquals(OrderSide.SELL, o.side)
        assertEquals(100L, o.price)
        assertEquals(5L, o.qty)
        assertEquals("GTC", o.tif)
        assertEquals(123L, o.tsNs)
        assertTrue(o.isActionable)
    }

    @Test
    fun side_isCaseInsensitive_andUnknownStaysNull() {
        assertEquals(OrderSide.BUY, LiveOrderDto(clordid = "x", side = "BUY").toDomain().side)
        assertNull(LiveOrderDto(clordid = "x", side = "cross").toDomain().side)
        assertNull(LiveOrderDto(clordid = "x", side = null).toDomain().side)
    }

    @Test
    fun qty_prefersRemaining_thenLeaves_thenQty() {
        assertEquals(3L, LiveOrderDto(clordid = "x", remainingQty = 3L, leavesQty = 9L, qty = 12L).toDomain().qty)
        assertEquals(9L, LiveOrderDto(clordid = "x", remainingQty = null, leavesQty = 9L, qty = 12L).toDomain().qty)
        assertEquals(12L, LiveOrderDto(clordid = "x", remainingQty = null, leavesQty = null, qty = 12L).toDomain().qty)
        assertEquals(0L, LiveOrderDto(clordid = "x").toDomain().qty)
    }

    @Test
    fun blankTif_becomesNull() {
        assertNull(LiveOrderDto(clordid = "x", tif = "  ").toDomain().tif)
    }

    @Test
    fun envelope_usesOrdersKey_andFiltersRowsWithoutClordid() {
        val dto = LiveOrdersDto(
            count = null,
            orders = listOf(
                LiveOrderDto(clordid = "a", qty = 1L),
                LiveOrderDto(clordid = "", qty = 2L),   // dropped: no client-order-id
                LiveOrderDto(clordid = null, qty = 3L),  // dropped
                LiveOrderDto(clordid = "b", qty = 4L),
            ),
        ).toDomain()
        assertEquals(2, dto.orders.size)
        assertEquals(listOf("a", "b"), dto.orders.map { it.clordid })
        // count falls back to the (filtered) list size when the server omits it.
        assertEquals(2, dto.count)
        assertFalse(dto.isEmpty)
    }

    @Test
    fun envelope_acceptsAlternateWorkingOrdersKey() {
        val dto = LiveOrdersDto(
            orders = null,
            workingOrders = listOf(LiveOrderDto(clordid = "z", qty = 1L)),
        ).toDomain()
        assertEquals(1, dto.orders.size)
        assertEquals("z", dto.orders.first().clordid)
    }

    @Test
    fun envelope_empty_isEmpty() {
        val dto = LiveOrdersDto(orders = emptyList()).toDomain()
        assertTrue(dto.isEmpty)
        assertEquals(0, dto.count)
    }

    @Test
    fun envelope_serverCount_isPreserved() {
        val dto = LiveOrdersDto(count = 5, orders = listOf(LiveOrderDto(clordid = "a"))).toDomain()
        // The server-reported count is trusted even when it differs from the rendered row count.
        assertEquals(5, dto.count)
    }
}
