package com.testlogon.android.data.disputes

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-245 — Moshi round-trip + DTO -> domain mapping for the dispute surface. Covers snake_case mapping,
 * epoch-seconds -> nullable-on-zero, unknown status -> UNKNOWN, free-text reason passthrough, and
 * nullable optionals; the file-in dto serializes amount_cents/reason.
 */
class DisputesMapperTest {

    private val moshi: Moshi = Moshi.Builder().build()

    @Test
    fun out_decodes_andMaps() {
        val json = """
            {
              "dispute_id": "dp_7c1",
              "provider": "stripe",
              "provider_dispute_id": "du_1Nx",
              "user_id": "usr_42",
              "amount_cents": 4900,
              "currency": "USD",
              "reason": "Cardholder reports an unauthorized charge.",
              "status": "under_review",
              "evidence_submitted": true,
              "evidence_text": "see attachment",
              "resolution": null,
              "admin_notes": "internal",
              "transaction_entry_id": "le_88a",
              "created_at": 1747749780,
              "updated_at": null,
              "deadline_at": 1749599999
            }
        """.trimIndent()
        val dto = moshi.adapter(DisputeDto::class.java).fromJson(json)!!
        val d = dto.toDomain()

        assertEquals("dp_7c1", d.id)
        assertEquals(DisputeStatus.UNDER_REVIEW, d.status)
        assertEquals(4900L, d.amount.cents)
        assertEquals("USD", d.amount.currency)
        assertTrue(d.evidenceSubmitted)
        assertEquals("le_88a", d.transactionEntryId)
        assertEquals(1747749780L, d.createdAtEpochSeconds)
        assertNull(d.updatedAtEpochSeconds)
        assertEquals(1749599999L, d.deadlineAtEpochSeconds)
        // admin_notes/user_id are intentionally not exposed on the domain model.
    }

    @Test
    fun out_unknownStatus_mapsToUnknown_andDefaultsApply() {
        val json = """{"dispute_id":"dp_2","status":"charge_refunded","reason":"x"}"""
        val dto = moshi.adapter(DisputeDto::class.java).fromJson(json)!!
        val d = dto.toDomain()
        assertEquals(DisputeStatus.UNKNOWN, d.status)
        assertEquals(0L, d.amount.cents)
        assertEquals("usd", d.amount.currency)
        assertNull(d.createdAtEpochSeconds)
    }

    @Test
    fun list_decodesItemsEnvelope() {
        val json = """{"items":[{"dispute_id":"d1","provider":"stripe","amount_cents":10,
            "currency":"usd","reason":"r","status":"open","evidence_submitted":false,"created_at":5}]}"""
        val dto = moshi.adapter(DisputeListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.items.size)
        assertEquals("d1", dto.items[0].disputeId)
    }

    @Test
    fun fileIn_serializesRequiredFields() {
        val dto = FileDisputeInput(
            transactionEntryId = "le_1",
            amountCents = 4900,
            currency = null,
            reason = "unauthorized charge here",
        ).toDto()
        val json = moshi.adapter(DisputeFileInDto::class.java).toJson(dto)
        assertTrue(json.contains("\"amount_cents\":4900"))
        assertTrue(json.contains("\"reason\":\"unauthorized charge here\""))
    }
}
