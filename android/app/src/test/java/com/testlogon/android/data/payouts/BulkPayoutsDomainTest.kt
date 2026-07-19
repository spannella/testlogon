package com.testlogon.android.data.payouts

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-261/263 — pure DTO -> domain mapping for the bulk/batch payout read surface: full-fixture
 * mapping, the status-string table (UNKNOWN fallback), null/missing defaulting, and embedded-item
 * mapping. No network/Android — these are framework-free mappers (cents Long, epoch Long).
 */
class BulkPayoutsDomainTest {

    private fun sampleBatchDto(
        status: String = "completed",
        items: List<PayoutBatchItemDto> = listOf(
            PayoutBatchItemDto(refId = "po_5501", amountCents = 4500, status = "paid", recipient = "creator_88", reason = ""),
        ),
    ) = PayoutBatchDto(
        batchId = "bat_77",
        kind = "payout",
        status = status,
        itemCount = 128,
        totalCents = 5_764_500,
        successCount = 124,
        failureCount = 4,
        createdAtEpochSeconds = 1_748_729_400,
        createdBy = "admin_42",
        items = items,
    )

    @Test
    fun toDomain_mapsAllFields_andEmbeddedItems() {
        val batch = sampleBatchDto().toDomain()
        assertEquals("bat_77", batch.id)
        assertEquals("payout", batch.kind)
        assertEquals(PayoutBatchStatus.COMPLETED, batch.status)
        assertEquals(128, batch.itemCount)
        assertEquals(5_764_500L, batch.total.cents)
        assertEquals("USD", batch.total.currency)
        assertEquals(124, batch.successCount)
        assertEquals(4, batch.failureCount)
        assertEquals(1_748_729_400L, batch.createdAtEpochSeconds)
        assertEquals("admin_42", batch.createdBy)
        assertEquals(1, batch.items.size)
        val item = batch.items[0]
        assertEquals("po_5501", item.refId)
        assertEquals(4500L, item.amount.cents)
        assertEquals("USD", item.amount.currency)
        assertEquals(PayoutStatus.PAID, item.status) // "paid" -> PAID (payout program split PAID/COMPLETED)
        assertEquals("creator_88", item.recipient)
    }

    @Test
    fun batchStatus_table_allVariants_andUnknownFallback() {
        assertEquals(PayoutBatchStatus.DRAFT, PayoutBatchStatus.from("draft"))
        assertEquals(PayoutBatchStatus.PENDING, PayoutBatchStatus.from("pending"))
        assertEquals(PayoutBatchStatus.PROCESSING, PayoutBatchStatus.from("processing"))
        assertEquals(PayoutBatchStatus.PROCESSING, PayoutBatchStatus.from("in_progress"))
        assertEquals(PayoutBatchStatus.COMPLETED, PayoutBatchStatus.from("completed"))
        assertEquals(PayoutBatchStatus.COMPLETED, PayoutBatchStatus.from("succeeded"))
        assertEquals(PayoutBatchStatus.PARTIALLY_FAILED, PayoutBatchStatus.from("partially_failed"))
        assertEquals(PayoutBatchStatus.PARTIALLY_FAILED, PayoutBatchStatus.from("partial"))
        assertEquals(PayoutBatchStatus.FAILED, PayoutBatchStatus.from("failed"))
        assertEquals(PayoutBatchStatus.CANCELED, PayoutBatchStatus.from("canceled"))
        assertEquals(PayoutBatchStatus.CANCELED, PayoutBatchStatus.from("cancelled"))
        assertEquals(PayoutBatchStatus.UNKNOWN, PayoutBatchStatus.from("something_new"))
        assertEquals(PayoutBatchStatus.UNKNOWN, PayoutBatchStatus.from(null))
        assertEquals(PayoutBatchStatus.UNKNOWN, PayoutBatchStatus.from(""))
    }

    @Test
    fun toDomain_nullAndMissingFields_defaultSafely() {
        // Only the required fields supplied; everything else relies on DTO defaults.
        val dto = PayoutBatchDto(batchId = "bat_x", kind = "refund", status = "pending")
        val batch = dto.toDomain()
        assertEquals(0, batch.itemCount)
        assertEquals(0L, batch.total.cents)
        assertEquals(0, batch.successCount)
        assertEquals(0, batch.failureCount)
        assertNull(batch.createdAtEpochSeconds)
        assertNull(batch.createdBy)
        assertTrue(batch.items.isEmpty())
    }

    @Test
    fun item_toDomain_defaultsRecipientAndReason_andUnknownStatus() {
        val item = PayoutBatchItemDto(refId = "r1", amountCents = 100, status = "weird_state").toDomain()
        assertEquals("r1", item.refId)
        assertEquals(100L, item.amount.cents)
        assertEquals(PayoutStatus.UNKNOWN, item.status)
        assertEquals("", item.recipient)
        assertEquals("", item.reason)
    }

    @Test
    fun listMapping_preservesOrder() {
        val dtos = listOf(
            sampleBatchDto().copy(batchId = "bat_a"),
            sampleBatchDto().copy(batchId = "bat_b"),
        )
        val mapped = dtos.map { it.toDomain() }
        assertEquals(listOf("bat_a", "bat_b"), mapped.map { it.id })
    }
}
