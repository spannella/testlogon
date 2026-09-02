package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.model.ApiError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.time.Instant

/**
 * WOV-004/005 — pure tests for the vendor status logic + board-column bucketing/ordering + the vendor
 * list fold. All logic here is Android-free.
 */
class MaintenanceMathTest {

    private fun vendor(
        id: String,
        name: String = "v-$id",
        status: VendorStatus = VendorStatus.ACTIVE,
        category: String = "general",
        created: Long = 0,
        updated: Long = 0,
        userSub: String? = null,
    ) = Vendor(
        vendorId = id,
        name = name,
        status = status,
        tradeCategory = category,
        userSub = userSub,
        createdAt = created.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) },
        updatedAt = updated.takeIf { it > 0 }?.let { Instant.ofEpochSecond(it) },
    )

    private fun order(id: String, status: WoStatus, priority: WoPriority = WoPriority.NORMAL) =
        MaintenanceOrder(workOrderId = id, propertyId = "p", title = id, status = status, priority = priority)

    // ---- vendor status ----

    @Test
    fun toggleTarget_flipsActiveInactive() {
        assertEquals(VendorStatus.INACTIVE, VendorStatus.ACTIVE.toggleTarget)
        assertEquals(VendorStatus.ACTIVE, VendorStatus.INACTIVE.toggleTarget)
        assertEquals(VendorStatus.ACTIVE, VendorStatus.UNKNOWN.toggleTarget)
    }

    @Test
    fun fromToken_lenientUnknown() {
        assertEquals(VendorStatus.ACTIVE, VendorStatus.fromToken("active"))
        assertEquals(VendorStatus.INACTIVE, VendorStatus.fromToken("inactive"))
        assertEquals(VendorStatus.UNKNOWN, VendorStatus.fromToken("bogus"))
        assertEquals(VendorStatus.UNKNOWN, VendorStatus.fromToken(null))
    }

    @Test
    fun canSetVendorStatus_rejectsNoopAndUnknown() {
        assertTrue(canSetVendorStatus(VendorStatus.ACTIVE, VendorStatus.INACTIVE))
        assertTrue(canSetVendorStatus(VendorStatus.INACTIVE, VendorStatus.ACTIVE))
        assertFalse(canSetVendorStatus(VendorStatus.ACTIVE, VendorStatus.ACTIVE))
        assertFalse(canSetVendorStatus(VendorStatus.ACTIVE, VendorStatus.UNKNOWN))
    }

    @Test
    fun vendorLabels() {
        assertEquals("Active", vendorStatusLabel(VendorStatus.ACTIVE))
        assertEquals("Inactive", vendorStatusLabel(VendorStatus.INACTIVE))
        assertEquals("Deactivate", vendorToggleActionLabel(VendorStatus.ACTIVE))
        assertEquals("Activate", vendorToggleActionLabel(VendorStatus.INACTIVE))
    }

    // ---- vendor filter / sort ----

    @Test
    fun filterVendors_byStatus() {
        val list = listOf(
            vendor("a", status = VendorStatus.ACTIVE),
            vendor("b", status = VendorStatus.INACTIVE),
        )
        assertEquals(listOf("a"), filterVendors(list, status = VendorStatus.ACTIVE).map { it.vendorId })
    }

    @Test
    fun filterVendors_byCategory_blankKeepsAll() {
        val list = listOf(vendor("a", category = "plumbing"), vendor("b", category = "hvac"))
        assertEquals(listOf("a"), filterVendors(list, tradeCategory = "plumbing").map { it.vendorId })
        assertEquals(2, filterVendors(list, tradeCategory = "").size)
        assertEquals(2, filterVendors(list, tradeCategory = null).size)
    }

    @Test
    fun sortVendors_activeFirstThenName() {
        val list = listOf(
            vendor("1", name = "Zeta", status = VendorStatus.ACTIVE),
            vendor("2", name = "Alpha", status = VendorStatus.INACTIVE),
            vendor("3", name = "Beta", status = VendorStatus.ACTIVE),
        )
        assertEquals(listOf("3", "1", "2"), sortVendors(list).map { it.vendorId })
    }

    @Test
    fun sortVendors_isStableAndTotal() {
        val list = listOf(vendor("b", name = "same"), vendor("a", name = "same"))
        // Same status + name -> ordered by vendorId.
        assertEquals(listOf("a", "b"), sortVendors(list).map { it.vendorId })
    }

    // ---- board columns ----

    @Test
    fun defaultBoardColumns_orderedAndComplete() {
        val cols = defaultBoardColumns()
        assertEquals(5, cols.size)
        assertEquals(
            listOf(WoStatus.OPEN, WoStatus.ASSIGNED, WoStatus.IN_PROGRESS, WoStatus.COMPLETED, WoStatus.CANCELLED),
            cols.map { it.statusKey },
        )
    }

    @Test
    fun sortBoardColumns_byOrderThenId() {
        val cols = listOf(
            WoBoardColumn("z", "Z", WoStatus.OPEN, 2),
            WoBoardColumn("a", "A", WoStatus.ASSIGNED, 1),
            WoBoardColumn("b", "B", WoStatus.IN_PROGRESS, 1),
        )
        assertEquals(listOf("a", "b", "z"), sortBoardColumns(cols).map { it.columnId })
    }

    @Test
    fun bucketOrdersByColumn_groupsByStatus_inColumnOrder() {
        val cols = defaultBoardColumns()
        val orders = listOf(
            order("o1", WoStatus.OPEN),
            order("o2", WoStatus.IN_PROGRESS),
            order("o3", WoStatus.OPEN),
            order("o4", WoStatus.UNKNOWN),
        )
        val buckets = bucketOrdersByColumn(orders, cols)
        assertEquals(cols.map { it.columnId }, buckets.map { it.first.columnId })
        val open = buckets.first { it.first.statusKey == WoStatus.OPEN }.second
        assertEquals(setOf("o1", "o3"), open.map { it.workOrderId }.toSet())
        // UNKNOWN status drops out of every column.
        assertTrue(buckets.none { pair -> pair.second.any { it.workOrderId == "o4" } })
    }

    @Test
    fun columnOrderCount_countsMatchingStatus() {
        val orders = listOf(order("a", WoStatus.OPEN), order("b", WoStatus.OPEN), order("c", WoStatus.COMPLETED))
        val openCol = WoBoardColumn("wo_open", "Open", WoStatus.OPEN, 0)
        assertEquals(2, columnOrderCount(orders, openCol))
    }

    // ---- small derivations ----

    @Test
    fun vendorWasEdited_trueOnlyWhenUpdatedAfterCreated() {
        assertTrue(vendorWasEdited(vendor("a", created = 100, updated = 200)))
        assertFalse(vendorWasEdited(vendor("b", created = 200, updated = 200)))
        assertFalse(vendorWasEdited(vendor("c", created = 100, updated = 0)))
    }

    @Test
    fun vendorIsLinked_reflectsUserSub() {
        assertTrue(vendorIsLinked(vendor("a", userSub = "user_1")))
        assertFalse(vendorIsLinked(vendor("b", userSub = null)))
        assertFalse(vendorIsLinked(vendor("c", userSub = "")))
    }

    // ---- vendor list fold ----

    @Test
    fun foldVendorsResult_states() {
        assertTrue(foldVendorsResult(null, ApiError(404, "off")) is VendorsUiState.Unavailable)
        assertTrue(foldVendorsResult(null, ApiError(500, "boom")) is VendorsUiState.Error)
        assertTrue(foldVendorsResult(emptyList(), null) is VendorsUiState.Empty)
        val content = foldVendorsResult(listOf(vendor("a")), null)
        assertTrue(content is VendorsUiState.Content)
    }
}
