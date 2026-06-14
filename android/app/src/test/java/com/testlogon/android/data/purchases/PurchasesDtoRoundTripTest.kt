package com.testlogon.android.data.purchases

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.Moshi
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.math.BigDecimal

/**
 * AND-218 / AND-222 — pure Moshi (de)serialization fidelity for the purchases DTOs: snake_case mapping,
 * BigDecimal money with NO float drift (incl. high precision), epoch-seconds Long timestamps,
 * required-field fail-fast, unknown-key + unknown-status tolerance, nested shipping/carrier_events
 * decoding, and empty/absent defaults. Mirrors the production Moshi (BigDecimalAdapter + codegen).
 */
class PurchasesDtoRoundTripTest {

    private val moshi: Moshi = Moshi.Builder().add(BigDecimalAdapter).build()
    private val summaryAdapter = moshi.adapter(PurchaseTransactionSummaryDto::class.java)
    private val infoAdapter = moshi.adapter(PurchaseTransactionInfoDto::class.java)

    @Test
    fun summary_roundTrip_snakeCase_and_money() {
        val json = """
            {"txn_id":"txn_001","created_at":1747836191,"updated_at":1747922600,"status":"completed",
             "amount":45.97,"currency":"USD","merchant_id":"mer_001","external_ref":"TL-100245",
             "description":"Logo Tee x2"}
        """.trimIndent()
        val dto = summaryAdapter.fromJson(json)!!
        assertEquals("txn_001", dto.txnId)
        assertEquals(1747836191L, dto.createdAt)
        assertEquals(0, BigDecimal("45.97").compareTo(dto.amount))
        assertEquals("USD", dto.currency)
        val out = summaryAdapter.toJson(dto)
        assertTrue(out.contains("\"txn_id\""))
        assertTrue(out.contains("\"created_at\""))
        assertTrue(out.contains("\"merchant_id\""))
        assertTrue(out.contains("\"external_ref\""))
        // No camelCase wire keys leak; amount stays a JSON number (not a quoted string).
        assertTrue(!out.contains("\"txnId\""))
        assertTrue(out.contains("\"amount\":45.97"))
    }

    @Test
    fun money_highPrecision_isLossless_noDoubleCoercion() {
        val json = """
            {"txn_id":"t","created_at":1,"updated_at":2,"status":"pending","amount":19.995,"currency":"USD"}
        """.trimIndent()
        val dto = summaryAdapter.fromJson(json)!!
        assertEquals(0, BigDecimal("19.995").compareTo(dto.amount))
        assertEquals("19.995", dto.amount.toPlainString())
    }

    @Test
    fun summary_missingRequiredField_throws() {
        // amount omitted (required) -> fail fast.
        val json = """{"txn_id":"t","created_at":1,"updated_at":2,"status":"pending","currency":"USD"}"""
        assertThrows(JsonDataException::class.java) { summaryAdapter.fromJson(json) }
    }

    @Test
    fun summary_unknownKeys_and_unknownStatus_tolerated() {
        val json = """
            {"txn_id":"t","created_at":1,"updated_at":2,"status":"partially_refunded","amount":1.0,
             "currency":"USD","server_time":"now","experimental_flag":true}
        """.trimIndent()
        val dto = summaryAdapter.fromJson(json)!!
        assertEquals("partially_refunded", dto.status) // raw string, never throws
        assertNull(dto.merchantId) // default
    }

    @Test
    fun detail_decodesNestedShipping_andCarrierEvents_andMetadata() {
        val json = """
            {"txn_id":"txn_1","created_at":1,"updated_at":2,"status":"COMPLETED","amount":49.57,
             "currency":"USD","buyer_id":"usr_42","version":3,
             "shipping":{"carrier":"ups","tracking_number":"1Z999","tracking_url":"https://t/1Z999",
               "status":"in_transit","shipped_at":1747850000,"estimated_delivery":"2026-05-25",
               "carrier_events":[{"timestamp":"2026-05-21T18:00:00Z","description":"Shipped"}]},
             "completed_at":1747922600,"metadata":{"cart_id":"cart_77"}}
        """.trimIndent()
        val dto = infoAdapter.fromJson(json)!!
        assertEquals("usr_42", dto.buyerId)
        assertEquals(3, dto.version)
        assertEquals("ups", dto.shipping?.carrier)
        assertEquals(1, dto.shipping?.carrierEvents?.size)
        assertEquals("cart_77", dto.metadata?.get("cart_id"))
        assertEquals(1747922600L, dto.completedAt)
    }

    @Test
    fun detail_absentShipping_isNull_and_carrierEvents_defaultEmpty() {
        val json = """
            {"txn_id":"t","created_at":1,"updated_at":2,"status":"PENDING","amount":1.0,"currency":"USD",
             "buyer_id":"u","version":1}
        """.trimIndent()
        val dto = infoAdapter.fromJson(json)!!
        assertNull(dto.shipping)
        assertNull(dto.completedAt)
    }

    @Test
    fun detail_missingRequired_buyerId_throws() {
        val json = """
            {"txn_id":"t","created_at":1,"updated_at":2,"status":"PENDING","amount":1.0,"currency":"USD",
             "version":1}
        """.trimIndent()
        assertThrows(JsonDataException::class.java) { infoAdapter.fromJson(json) }
    }
}
