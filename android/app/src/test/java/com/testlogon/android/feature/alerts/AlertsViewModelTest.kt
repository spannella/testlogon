package com.testlogon.android.feature.alerts

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.alerts.Alert
import com.testlogon.android.data.alerts.AlertPriority
import com.testlogon.android.data.alerts.AlertsPage
import com.testlogon.android.data.alerts.AlertsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class AlertsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    // ---- domain builders ----

    private fun alert(
        id: String = "al_1",
        readAt: Long? = null,
        priority: AlertPriority = AlertPriority.NORMAL,
    ) = Alert(
        id = id,
        event = "evt",
        title = "Title $id",
        timestampSeconds = 1_700_000_000L,
        readAt = readAt,
        priority = priority,
        actionUrl = null,
        category = "system",
    )

    private fun page(alerts: List<Alert>, nextCursor: String? = null) =
        AlertsPage(alerts = alerts, nextCursor = nextCursor)

    // ---- fake repo ----

    private class FakeAlertsRepository : AlertsRepository {
        var loadResult: ApiResult<AlertsPage> = ApiResult.Failure(ApiError(500, "x"))
        var cacheValue: AlertsPage? = null
        var markReadResult: ApiResult<Unit> = ApiResult.Success(Unit)
        var markAllReadResult: ApiResult<Unit> = ApiResult.Success(Unit)

        var loadCalls = 0
        var lastUnreadOnly: Boolean? = null
        var markReadIds: List<String>? = null
        var markAllReadCalls = 0

        override suspend fun loadAlerts(unreadOnly: Boolean): ApiResult<AlertsPage> {
            loadCalls++
            lastUnreadOnly = unreadOnly
            return loadResult
        }

        override suspend fun markRead(alertIds: List<String>): ApiResult<Unit> {
            markReadIds = alertIds
            return markReadResult
        }

        override suspend fun markAllRead(): ApiResult<Unit> {
            markAllReadCalls++
            return markAllReadResult
        }

        override fun cached(): AlertsPage? = cacheValue

        override fun clear() {}
    }

    @Test
    fun load_success_nonEmpty_movesToContent() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert())))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.Content, vm.uiState.value.phase)
        assertFalse(vm.uiState.value.isStale)
    }

    @Test
    fun load_success_empty_movesToEmpty() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(emptyList()))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun load_failure500_noCache_movesToError() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Failure(ApiError(500, "boom"))
            cacheValue = null
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.Error, vm.uiState.value.phase)
    }

    @Test
    fun load_networkError_withCache_showsStaleContent() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = page(listOf(alert()))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.Content, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
    }

    @Test
    fun load_networkError_withEmptyCache_showsStaleEmpty() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.NetworkError(java.io.IOException(), isTimeout = false)
            cacheValue = page(emptyList())
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.Empty, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.isStale)
    }

    @Test
    fun load_failure401_movesToSessionExpired() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Failure(ApiError(401, "unauthorized"))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertEquals(AlertsUiState.Phase.SessionExpired, vm.uiState.value.phase)
    }

    @Test
    fun onMarkAllRead_callsRepo_flipsUnreadLocally_andEmitsSuccessMessage() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert(id = "a"), alert(id = "b"))))
            markAllReadResult = ApiResult.Success(Unit)
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertTrue(vm.uiState.value.hasUnread)

        val effects = mutableListOf<AlertsEffect>()
        val job = CoroutineScope(UnconfinedTestDispatcher(testScheduler)).launch {
            vm.effects.collect { effects += it }
        }
        vm.onMarkAllRead()
        advanceUntilIdle()
        job.cancel()

        assertEquals(1, repo.markAllReadCalls)
        assertEquals(0, vm.uiState.value.unreadCount)
        assertFalse(vm.uiState.value.hasUnread)
        assertFalse(vm.uiState.value.isMutating)
        assertEquals(1, effects.filterIsInstance<AlertsEffect.ShowMessage>().size)
    }

    @Test
    fun onMarkAllRead_noUnread_isNoOp() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert(id = "a", readAt = 123L))))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.hasUnread)

        vm.onMarkAllRead()
        advanceUntilIdle()

        assertEquals(0, repo.markAllReadCalls)
    }

    @Test
    fun onAlertClick_unread_marksReadViaRepo_andFlipsLocally() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert(id = "a"), alert(id = "b"))))
            markReadResult = ApiResult.Success(Unit)
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()

        vm.onAlertClick("a")
        advanceUntilIdle()

        assertEquals(listOf("a"), repo.markReadIds)
        val a = vm.uiState.value.page!!.alerts.first { it.id == "a" }
        val b = vm.uiState.value.page!!.alerts.first { it.id == "b" }
        assertFalse(a.isUnread)
        assertTrue(b.isUnread)
        assertEquals(1, vm.uiState.value.unreadCount)
    }

    @Test
    fun onAlertClick_alreadyRead_doesNotCallRepo() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert(id = "a", readAt = 999L))))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()

        vm.onAlertClick("a")
        advanceUntilIdle()

        assertEquals(null, repo.markReadIds)
    }

    @Test
    fun onToggleUnreadOnly_togglesFlag_andReloads() = runTest {
        val repo = FakeAlertsRepository().apply {
            loadResult = ApiResult.Success(page(listOf(alert())))
        }
        val vm = AlertsViewModel(repo)
        advanceUntilIdle()
        assertFalse(vm.uiState.value.unreadOnly)
        val loadsAfterInit = repo.loadCalls

        vm.onToggleUnreadOnly()
        advanceUntilIdle()

        assertTrue(vm.uiState.value.unreadOnly)
        assertEquals(loadsAfterInit + 1, repo.loadCalls)
        assertEquals(true, repo.lastUnreadOnly)
    }
}
