package com.testlogon.android.data.taxdocs

import com.squareup.moshi.Moshi
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-246 — Moshi round-trip + DTO -> domain mapping for the tax-documents surface. Covers the
 * `documents` envelope, server defaults when fields are omitted, null year (not downloadable),
 * epoch-seconds -> nullable-on-zero, and unknown keys ignored.
 */
class TaxDocsMapperTest {

    private val moshi: Moshi = Moshi.Builder().build()

    @Test
    fun decodes_documentsEnvelope_andMaps() {
        val json = """
            {"documents":[
              {"doc_id":"txd_1","doc_type":"annual_summary","year":2024,"date_from":1704067200,
               "date_to":1735689599,"grand_total_cents":254013,"transaction_count":87,
               "currency":"usd","created_at":1738281600}
            ]}
        """.trimIndent()
        val dto = moshi.adapter(TaxDocumentListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.documents.size)
        val d = dto.documents[0].toDomain()
        assertEquals("txd_1", d.docId)
        assertEquals(2024, d.year)
        assertEquals(254013L, d.grandTotal.cents)
        assertEquals(87, d.transactionCount)
        assertEquals(1738281600L, d.createdAtEpochSeconds)
        assertTrue(d.isDownloadable)
    }

    @Test
    fun defaults_applyWhenOmitted_andNullYearNotDownloadable() {
        val json = """{"doc_id":"txd_2","unknown_key":"ignored"}"""
        val dto = moshi.adapter(TaxDocumentDto::class.java).fromJson(json)!!
        val d = dto.toDomain()
        assertEquals("annual_summary", d.docType)
        assertEquals("usd", d.grandTotal.currency)
        assertEquals(0L, d.grandTotal.cents)
        assertEquals(0, d.transactionCount)
        assertNull(d.year)
        assertNull(d.createdAtEpochSeconds)
        assertFalse(d.isDownloadable)
    }

    @Test
    fun decodes_summary_dropsAllZeroCategories() {
        val json = """
            {"date_from":1704067200,"date_to":1735689599,"currency":"usd",
             "grand_total_cents":254013,"transaction_count":87,
             "categories":[
               {"category":"subscriptions","total_cents":200000,"transaction_count":40},
               {"category":"tips","total_cents":54013,"transaction_count":47},
               {"category":"unlocks","total_cents":0,"transaction_count":0}
             ]}
        """.trimIndent()
        val dto = moshi.adapter(TaxSpendingSummaryDto::class.java).fromJson(json)!!
        val s = dto.toDomain()
        assertEquals(254013L, s.grandTotal.cents)
        assertEquals("usd", s.grandTotal.currency)
        assertEquals(87, s.transactionCount)
        // all-zero "unlocks" row dropped
        assertEquals(2, s.categories.size)
        assertEquals("subscriptions", s.categories[0].category)
        assertEquals(200000L, s.categories[0].total.cents)
        assertFalse(s.isEmpty)
    }

    @Test
    fun summary_allZero_isEmpty() {
        val dto = moshi.adapter(TaxSpendingSummaryDto::class.java)
            .fromJson("""{"grand_total_cents":0,"transaction_count":0,"categories":[]}""")!!
        assertTrue(dto.toDomain().isEmpty)
    }
}
