package com.testlogon.android.core.network.maintenance

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/** WOV — DTO-level Moshi decode tests for the Maintenance Work Orders list envelope. */
class MaintenanceOrderDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()

    @Test
    fun list_decodesOrdersCountCursor() {
        val json = """
            {
              "items": [
                {
                  "work_order_id": "w1",
                  "property_id": "prop1",
                  "unit_id": null,
                  "vendor_id": null,
                  "assignee_sub": null,
                  "title": "Fix sink",
                  "description": "Kitchen sink leak",
                  "priority": "urgent",
                  "wo_status": "open",
                  "scheduled_for": null,
                  "cost_cents": null,
                  "created_at": 1700000000,
                  "updated_at": 1700000100,
                  "completed_at": null,
                  "correlation_id": "c1",
                  "actor_sub": "a1",
                  "escrow_amount_cents": null,
                  "escrow_status": null
                }
              ],
              "count": 1,
              "cursor": "next"
            }
        """.trimIndent()
        val dto = moshi.adapter(MaintenanceOrderListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.count)
        assertEquals("next", dto.cursor)
        val row = dto.items.first()
        assertEquals("w1", row.workOrderId)
        assertEquals("urgent", row.priority)
        assertEquals(1700000100L, row.updatedAt)
    }

    @Test
    fun sparseRow_usesDefaults() {
        val json = """{"items":[{"work_order_id":"w2","property_id":"p2","title":"t"}],"count":1}"""
        val dto = moshi.adapter(MaintenanceOrderListDto::class.java).fromJson(json)!!
        val row = dto.items.first()
        assertEquals("normal", row.priority)
        assertEquals("open", row.woStatus)
        assertNull(dto.cursor)
        assertNull(row.completedAt)
    }
}
