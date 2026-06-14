package com.testlogon.android.data.refunds

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-244 — Moshi round-trip + DTO -> domain mapping for the refund surface. Covers snake_case mapping,
 * epoch-seconds -> nullable-on-zero, unknown status -> UNKNOWN, omitted amount_cents on the IN dto, and
 * nullable optionals.
 */
class RefundsMapperTest {

    private val moshi: Moshi = Moshi.Builder().build()

    @Test
    fun out_decodes_snakeCase_andMaps() {
        val json = """
            {
              "refund_request_id": "rfnd_1",
              "status": "approved",
              "amount_cents": 1299,
              "currency": "USD",
              "reason": "Charged twice for the same item",
              "transaction_type": "charge",
              "transaction_entry_id": "entry_1",
              "created_at": 1749124800,
              "admin_notes": "Refund approved",
              "completed_at": null,
              "requester_user_id": "usr_1"
            }
        """.trimIndent()
        val dto = moshi.adapter(RefundRequestOutDto::class.java).fromJson(json)!!
        val domain = dto.toDomain()

        assertEquals("rfnd_1", domain.id)
        assertEquals(RefundStatus.APPROVED, domain.status)
        assertEquals(1299L, domain.amount.cents)
        assertEquals("USD", domain.amount.currency)
        assertEquals("entry_1", domain.transactionEntryId)
        assertEquals("Refund approved", domain.adminNotes)
        assertEquals(1749124800L, domain.createdAtEpochSeconds)
        assertNull(domain.completedAtEpochSeconds)
    }

    @Test
    fun out_unknownStatus_mapsToUnknown_andZeroEpochIsNull() {
        val json = """
            { "refund_request_id": "rfnd_2", "status": "escalated", "amount_cents": 500,
              "currency": "usd", "reason": "x", "created_at": 0 }
        """.trimIndent()
        val dto = moshi.adapter(RefundRequestOutDto::class.java).fromJson(json)!!
        val domain = dto.toDomain()

        assertEquals(RefundStatus.UNKNOWN, domain.status)
        assertNull(domain.createdAtEpochSeconds)
        assertNull(domain.transactionEntryId)
        assertNull(domain.adminNotes)
    }

    @Test
    fun in_omitsAmount_whenNull_fullRefund() {
        val dto = SubmitRefundInput(
            transactionEntryId = "entry_1",
            reason = "needs a refund please",
            amountCents = null,
        ).toDto()
        val json = moshi.adapter(RefundRequestInDto::class.java).toJson(dto)
        assertEquals(false, json.contains("amount_cents"))
        assertEquals(true, json.contains("\"transaction_entry_id\":\"entry_1\""))
    }

    @Test
    fun in_includesAmount_whenPresent() {
        val dto = SubmitRefundInput("entry_1", "needs a refund please", 1299L).toDto()
        val json = moshi.adapter(RefundRequestInDto::class.java).toJson(dto)
        assertEquals(true, json.contains("\"amount_cents\":1299"))
    }

    @Test
    fun list_decodesItemsEnvelope() {
        val json = """{"items":[{"refund_request_id":"r1","status":"pending","amount_cents":100,
            "currency":"usd","reason":"x","created_at":10}]}""".trimIndent()
        val dto = moshi.adapter(RefundListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.items.size)
        assertEquals("r1", dto.items[0].refundRequestId)
    }
}
