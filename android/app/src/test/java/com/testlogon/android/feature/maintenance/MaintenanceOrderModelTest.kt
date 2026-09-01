package com.testlogon.android.feature.maintenance

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.network.maintenance.MaintenanceOrderDto
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/** WOV — pure tests for the work-order state machine, board sort, DTO mapping + list fold. */
class MaintenanceOrderModelTest {

    private fun order(
        id: String,
        status: WoStatus = WoStatus.OPEN,
        priority: WoPriority = WoPriority.NORMAL,
        updated: Long = 0,
    ) = MaintenanceOrder(
        workOrderId = id,
        propertyId = "prop",
        title = "t-$id",
        status = status,
        priority = priority,
        updatedAt = updated.takeIf { it > 0 }?.let { java.time.Instant.ofEpochSecond(it) },
    )

    @Test
    fun allowedTransitions_open() {
        assertEquals(
            setOf(WoStatus.ASSIGNED, WoStatus.IN_PROGRESS, WoStatus.CANCELLED),
            allowedTransitions(WoStatus.OPEN),
        )
    }

    @Test
    fun allowedTransitions_inProgress() {
        assertEquals(setOf(WoStatus.COMPLETED, WoStatus.CANCELLED), allowedTransitions(WoStatus.IN_PROGRESS))
    }

    @Test
    fun terminalStates_allowNothing() {
        assertTrue(allowedTransitions(WoStatus.COMPLETED).isEmpty())
        assertTrue(allowedTransitions(WoStatus.CANCELLED).isEmpty())
        assertTrue(WoStatus.COMPLETED.isTerminal)
        assertFalse(WoStatus.OPEN.isTerminal)
    }

    @Test
    fun canTransition_rejectsIllegal_openToCompleted() {
        assertFalse(canTransition(WoStatus.OPEN, WoStatus.COMPLETED))
        assertTrue(canTransition(WoStatus.IN_PROGRESS, WoStatus.COMPLETED))
    }

    @Test
    fun sortForBoard_activeBeforeTerminal_thenPriority() {
        val sorted = sortForBoard(
            listOf(
                order("done", status = WoStatus.COMPLETED),
                order("low", status = WoStatus.OPEN, priority = WoPriority.LOW),
                order("urgent", status = WoStatus.OPEN, priority = WoPriority.URGENT),
                order("active", status = WoStatus.IN_PROGRESS),
            ),
        )
        assertEquals(listOf("active", "urgent", "low", "done"), sorted.map { it.workOrderId })
    }

    @Test
    fun dtoMapper_lenientEnums_andEpochZeroToNull() {
        val dto = MaintenanceOrderDto(
            workOrderId = "w1",
            propertyId = "p1",
            title = "Fix sink",
            priority = "weird",
            woStatus = "in_progress",
            createdAt = 0,
            updatedAt = 100,
        )
        val d = dto.toDomain()
        assertEquals(WoPriority.UNKNOWN, d.priority)
        assertEquals(WoStatus.IN_PROGRESS, d.status)
        assertNull(d.createdAt)
        assertEquals(java.time.Instant.ofEpochSecond(100), d.updatedAt)
    }

    @Test
    fun foldOrdersResult_404_isUnavailable() {
        val state = foldOrdersResult(null, ApiError(status = 404, message = "no"))
        assertEquals(MaintenanceOrdersUiState.Unavailable, state)
    }

    @Test
    fun foldOrdersResult_otherError_isError() {
        val state = foldOrdersResult(null, ApiError(status = 500, message = "boom"))
        assertTrue(state is MaintenanceOrdersUiState.Error)
    }

    @Test
    fun foldOrdersResult_emptyList_isEmpty_andNonEmptyIsSortedContent() {
        assertEquals(MaintenanceOrdersUiState.Empty, foldOrdersResult(emptyList(), null))
        val state = foldOrdersResult(
            listOf(order("done", status = WoStatus.COMPLETED), order("active", status = WoStatus.IN_PROGRESS)),
            null,
        )
        assertTrue(state is MaintenanceOrdersUiState.Content)
        assertEquals("active", (state as MaintenanceOrdersUiState.Content).orders.first().workOrderId)
    }
}
