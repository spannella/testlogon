package com.testlogon.android.core.network.signing

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * SUX-008 — DTO-level Moshi decode tests for the signing INBOX list envelope. Uses the reflective
 * KotlinJsonAdapterFactory (as production does). The inbox DTOs are plain String fields, so no enum
 * adapter is needed here.
 */
class SigningInboxDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()

    @Test
    fun inboxList_decodesItemsAndCount() {
        val json = """
            {
              "items": [
                {
                  "packet_id": "p1",
                  "owner_user_id": "u1",
                  "source_name": "Lease.pdf",
                  "status": "sent",
                  "status_chip": "Awaiting",
                  "status_text": "Awaiting your signature",
                  "role": "signer",
                  "created_at": "2026-01-01T00:00:00Z"
                }
              ],
              "count": 1
            }
        """.trimIndent()
        val dto = moshi.adapter(SigningInboxListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.count)
        assertEquals(1, dto.items.size)
        val row = dto.items.first()
        assertEquals("p1", row.packetId)
        assertEquals("Lease.pdf", row.sourceName)
        assertEquals("Awaiting your signature", row.statusText)
    }

    @Test
    fun inboxList_sparseRow_decodesWithDefaults() {
        val json = """{"items":[{"packet_id":"p2","status":"draft"}],"count":1}"""
        val dto = moshi.adapter(SigningInboxListDto::class.java).fromJson(json)!!
        val row = dto.items.first()
        assertEquals("p2", row.packetId)
        assertEquals("draft", row.status)
        assertNull(row.sourceName)
        assertNull(row.role)
    }

    @Test
    fun inboxList_emptyBody_decodesToEmptyEnvelope() {
        val dto = moshi.adapter(SigningInboxListDto::class.java).fromJson("{}")!!
        assertEquals(0, dto.count)
        assertEquals(0, dto.items.size)
    }
}
