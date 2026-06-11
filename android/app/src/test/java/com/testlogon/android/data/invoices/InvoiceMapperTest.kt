package com.testlogon.android.data.invoices

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-243 — unit tests for the invoices DTO -> domain mappers: minor-unit money preservation, epoch
 * handling (created_at==0 -> null), unknown `status` -> UNKNOWN, line-item currency threading, and the
 * list-envelope -> page mapping (next_cursor normalization).
 */
class InvoiceMapperTest {

    private fun dto(
        status: String = "generated",
        createdAt: Long = 1_746_100_800L,
        currency: String = "usd",
    ) = InvoiceDto(
        invoiceId = "in_1",
        invoiceNumber = "INV-2026-001052",
        invoiceType = "subscription",
        userSub = "user_abc",
        amountCents = 4500,
        taxCents = 400,
        totalCents = 4900,
        currency = currency,
        status = status,
        sellerName = "TestLogon Inc.",
        buyerName = "Sean P.",
        buyerEmail = "spannella@gmail.com",
        lineItems = listOf(InvoiceLineItemDto(description = "Pro plan", amountCents = 4500, quantity = 1)),
        paymentMethodSummary = "Visa •••• 4242",
        createdAt = createdAt,
    )

    @Test
    fun toSummary_preservesMinorUnits_andMapsStatus() {
        val summary = dto().toSummary()
        assertEquals("INV-2026-001052", summary.invoiceNumber)
        assertEquals(4900L, summary.total.cents)
        assertEquals("usd", summary.total.currency)
        assertEquals(InvoiceStatus.GENERATED, summary.status)
        assertEquals(1_746_100_800L, summary.createdAtEpochSeconds)
    }

    @Test
    fun toSummary_unknownStatus_mapsToUnknown() {
        assertEquals(InvoiceStatus.UNKNOWN, dto(status = "void").toSummary().status)
        assertEquals(InvoiceStatus.EMAILED, dto(status = "emailed").toSummary().status)
    }

    @Test
    fun toSummary_zeroCreatedAt_mapsToNull() {
        assertNull(dto(createdAt = 0).toSummary().createdAtEpochSeconds)
    }

    @Test
    fun toDetail_mapsLineItems_totals_andThreadsCurrency() {
        val detail = dto(currency = "eur").toDetail()
        assertEquals(1, detail.lineItems.size)
        assertEquals(4500L, detail.lineItems[0].amount.cents)
        assertEquals("eur", detail.lineItems[0].amount.currency)
        assertEquals(4500L, detail.amount.cents)
        assertEquals(400L, detail.tax.cents)
        assertEquals(4900L, detail.total.cents)
        assertEquals("Visa •••• 4242", detail.paymentMethodSummary)
    }

    @Test
    fun toPage_mapsRows_andNormalizesBlankCursorToNull() {
        val page = InvoiceListDto(invoices = listOf(dto()), nextCursor = "").toPage()
        assertEquals(1, page.invoices.size)
        assertNull(page.nextCursor)

        val paged = InvoiceListDto(invoices = listOf(dto()), nextCursor = "c2").toPage()
        assertEquals("c2", paged.nextCursor)
    }

    @Test
    fun emailDto_toDomain_carriesRecipientAndMessage() {
        val result = InvoiceEmailDto(ok = true, emailedTo = "x@y.com", message = "done").toDomain()
        assertEquals("x@y.com", result.emailedTo)
        assertEquals("done", result.message)
    }

    @Test
    fun toTax_derivesFlatBreakdownFromScalars() {
        // AND-249: subtotal = amount, tax = tax, total = total; no per-rate lines exist on the wire.
        val tax = dto().toDetail().toTax()
        assertEquals("INV-2026-001052", tax.invoiceNumber)
        assertEquals(4500L, tax.subtotal.cents)
        assertEquals(400L, tax.tax.cents)
        assertEquals(4900L, tax.total.cents)
        assertEquals(tax.total.cents, tax.subtotal.cents + tax.tax.cents)
    }
}
