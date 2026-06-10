package com.testlogon.android.data.purchases

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigDecimal

/**
 * AND-221 / AND-222 — pure DTO -> domain mapper tests: money carried losslessly (BigDecimal major units,
 * no /100), epoch-seconds passthrough, case-insensitive status mapping with Unknown fallback (no throw),
 * title fallback, and full detail mapping incl. shipping + metadata.cart_id.
 */
class PurchasesMapperTest {

    private fun summary(
        status: String = "completed",
        amount: BigDecimal = BigDecimal("42.99"),
        description: String? = "Acme order",
    ) = PurchaseTransactionSummaryDto(
        txnId = "txn_123",
        createdAt = 1748715724,
        updatedAt = 1748715800,
        status = status,
        amount = amount,
        currency = "USD",
        merchantId = "mrc_abc",
        externalRef = "ext-123",
        description = description,
    )

    @Test
    fun summary_mapsFields_moneyMajorUnits_noDivide() {
        val item = summary().toDomain()
        assertEquals("txn_123", item.id)
        assertEquals(0, BigDecimal("42.99").compareTo(item.money.amount)) // NOT 0.4299
        assertEquals("USD", item.money.currency)
        assertEquals(1748715724L, item.createdAtEpochSec)
        assertEquals(OrderStatus.Completed, item.status)
        assertEquals("mrc_abc", item.merchantId)
    }

    @Test
    fun status_caseInsensitive_knownValues() {
        assertEquals(OrderStatus.Pending, "pending".toOrderStatus())
        assertEquals(OrderStatus.Completed, "COMPLETED".toOrderStatus())
        assertEquals(OrderStatus.Cancelled, "cancelled".toOrderStatus())
        assertEquals(OrderStatus.Cancelled, "CANCELED".toOrderStatus())
        assertEquals(OrderStatus.Reverted, "reverted".toOrderStatus())
        assertEquals(OrderStatus.CancelRequested, "CANCEL_REQUESTED".toOrderStatus())
        assertEquals(OrderStatus.CancelDenied, "CANCEL_DENIED".toOrderStatus())
    }

    @Test
    fun status_unknown_fallsBackToUnknown_noThrow() {
        val status = "DISPUTED".toOrderStatus()
        assertTrue(status is OrderStatus.Unknown)
        assertEquals("DISPUTED", (status as OrderStatus.Unknown).raw)
    }

    @Test
    fun title_fallsBackToOrderPrefix_whenNoDescription() {
        val item = summary(description = null).toDomain()
        assertEquals("Order txn_123", item.title)
    }

    @Test
    fun detail_mapsShipping_andCartId() {
        val dto = PurchaseTransactionInfoDto(
            txnId = "txn_1",
            createdAt = 1,
            updatedAt = 2,
            status = "PENDING",
            amount = BigDecimal("49.57"),
            currency = "USD",
            buyerId = "usr_1",
            version = 3,
            shipping = PurchaseShippingDto(
                carrier = "ups",
                trackingNumber = "1Z999",
                trackingUrl = "https://t/1Z999",
                status = "in_transit",
                shippedAt = 1748460000,
            ),
            completedAt = null,
            metadata = mapOf("cart_id" to "cart_77"),
        )
        val detail = dto.toDomain()
        assertEquals("usr_1", detail.buyerId)
        assertEquals("ups", detail.shipping?.carrier)
        assertTrue(detail.shipping?.hasShipment == true)
        assertEquals("cart_77", detail.cartId)
        assertEquals(OrderStatus.Pending, detail.status)
    }

    @Test
    fun detail_noShipping_yieldsNullShipping_andNullCartId() {
        val dto = PurchaseTransactionInfoDto(
            txnId = "t",
            createdAt = 1,
            updatedAt = 2,
            status = "COMPLETED",
            amount = BigDecimal.ONE,
            currency = "USD",
            buyerId = "u",
            version = 1,
        )
        val detail = dto.toDomain()
        assertNull(detail.shipping)
        assertNull(detail.cartId)
    }

    @Test
    fun detail_emptyShipping_collapsesToNull() {
        // A shipping object with neither carrier nor tracking number has nothing to track.
        val dto = PurchaseTransactionInfoDto(
            txnId = "t",
            createdAt = 1,
            updatedAt = 2,
            status = "PENDING",
            amount = BigDecimal.ONE,
            currency = "USD",
            buyerId = "u",
            version = 1,
            shipping = PurchaseShippingDto(estimatedDelivery = "2026-06-02"),
        )
        assertNull(dto.toDomain().shipping)
    }
}
