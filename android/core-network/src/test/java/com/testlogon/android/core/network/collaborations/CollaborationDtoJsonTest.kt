package com.testlogon.android.core.network.collaborations

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import com.testlogon.android.core.network.json.BigDecimalAdapter
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-358 - DTO-level Moshi tests for the AND-358 collaborations transport (mirrors AND-356
 * SyndicateDtoJsonTest).
 *
 * Focus: the split Map String -> Int PERCENT, the FREE-string status passing through raw, *_cents ints, the
 * INTEGER epoch created_at / updated_at, optional-field defaults (nulls) + EXTRA-key tolerance, and the
 * collab_id / id + items / collaborations key variants. The Moshi is built like NetworkModule.provideMoshi.
 * core-network has no test dependency on core-testing, so the JSON is inline. KDoc avoids the
 * comment-terminator character pair.
 */
class CollaborationDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder()
        .add(BigDecimalAdapter)
        .add(KotlinJsonAdapterFactory())
        .build()

    private fun collabAdapter() = moshi.adapter(CollaborationOut::class.java)
    private fun listAdapter() = moshi.adapter(CollaborationListOut::class.java)
    private fun historyAdapter() = moshi.adapter(CollabSplitHistoryOut::class.java)

    @Test
    fun collaboration_decodes_splitPercentMap_andFreeStatus_andEpochLongs() {
        val json = """{"collab_id":"c1","title":"Track","status":"some_custom_status",
                       "initiator_id":"usr_a","recipient_id":"usr_b",
                       "split":{"usr_a":60,"usr_b":40},
                       "created_at":1780000000,"updated_at":1780000500,"unknown_top":1}"""
        val c = requireNotNull(collabAdapter().fromJson(json))
        assertEquals("c1", c.collabId)
        // status is a FREE string preserved raw (the typed CollabStatus is in core-model)
        assertEquals("some_custom_status", c.status)
        // split is integer PERCENT (0-100), NOT basis points
        assertEquals(60, c.split?.get("usr_a"))
        assertEquals(40, c.split?.get("usr_b"))
        assertEquals(1780000000L, c.createdAt)
        assertEquals(1780000500L, c.updatedAt)
    }

    @Test
    fun collaboration_optionalFields_defaultNull() {
        val json = """{"collab_id":"c1"}"""
        val c = requireNotNull(collabAdapter().fromJson(json))
        assertEquals("c1", c.collabId)
        assertNull(c.title)
        assertNull(c.description)
        assertNull(c.status)
        assertNull(c.split)
        assertNull(c.createdAt)
        assertNull(c.updatedAt)
    }

    @Test
    fun collaboration_acceptsIdFallback_whenNoCollabId() {
        val json = """{"id":"c_alt","title":"X"}"""
        val c = requireNotNull(collabAdapter().fromJson(json))
        assertNull(c.collabId)
        assertEquals("c_alt", c.id)
    }

    @Test
    fun list_decodes_itemsVariant_andCursor() {
        val json = """{"items":[{"collab_id":"c1"}],"next_cursor":"cur2"}"""
        val out = requireNotNull(listAdapter().fromJson(json))
        assertEquals(1, out.items?.size)
        assertNull(out.collaborations)
        assertEquals("cur2", out.nextCursor)
    }

    @Test
    fun history_decodes_distributions_withCentsInts() {
        val json = """{"records":[{"record_id":"r1","distributions":[
                         {"user_id":"usr_a","percentage":60,"amount_cents":6000}
                       ]}]}"""
        val out = requireNotNull(historyAdapter().fromJson(json))
        val dist = out.records?.single()?.distributions?.single()
        assertEquals("usr_a", dist?.userId)
        assertEquals(60, dist?.percentage)
        assertEquals(6000, dist?.amountCents)
    }
}
