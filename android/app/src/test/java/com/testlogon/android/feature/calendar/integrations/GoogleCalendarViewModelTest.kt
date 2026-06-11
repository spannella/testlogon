package com.testlogon.android.feature.calendar.integrations

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.gcal.GoogleCalendarReturn
import com.testlogon.android.data.gcal.GoogleCalendarReturnDispatcher
import com.testlogon.android.data.gcal.ProviderCalendar
import com.testlogon.android.feature.calendar.FakeCalendarRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class GoogleCalendarViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeGoogleCalendarRepository()
    private val calendars = FakeCalendarRepository()
    private val dispatcher = GoogleCalendarReturnDispatcher()

    private fun vm() = GoogleCalendarViewModel(
        repo = repo,
        calendarRepository = calendars,
        returnDispatcher = dispatcher,
    )

    @Test
    fun initialRefresh_disconnected() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.disconnectedStatus())
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is GoogleCalendarUiState.Disconnected)
    }

    @Test
    fun connectClicked_emitsOpenCustomTab_movesToConnecting() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.disconnectedStatus())
        val vm = vm()
        advanceUntilIdle()

        val effects = mutableListOf<GoogleCalendarEffect>()
        val job = launch(UnconfinedTestDispatcher(testScheduler)) { vm.effects.collect { effects += it } }

        vm.onConnectClicked()
        advanceUntilIdle()

        assertTrue(vm.state.value is GoogleCalendarUiState.Connecting)
        assertTrue(effects.any { it is GoogleCalendarEffect.OpenCustomTab })
        assertEquals(1, repo.startCalls)
        job.cancel()
    }

    @Test
    fun returnFromCustomTab_active_transitionsToConnected_andListsCalendars() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.disconnectedStatus())
        val vm = vm()
        advanceUntilIdle()
        vm.onConnectClicked()
        advanceUntilIdle()

        // Now the backend reports active; the return re-reads status.
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.connectedStatus())
        repo.calendarsResult = ApiResult.Success(
            listOf(ProviderCalendar("gcal_1", "Primary", "owner", true, null)),
        )
        vm.onReturnedFromCustomTab()
        advanceUntilIdle()

        val state = vm.state.value
        assertTrue(state is GoogleCalendarUiState.Connected)
        assertEquals("user@example.com", (state as GoogleCalendarUiState.Connected).accountEmail)
        assertEquals(ListState.LOADED, state.listState)
        assertEquals(1, state.calendars.size)
    }

    @Test
    fun deepLinkReturn_stateMismatch_doesNotConnect() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.disconnectedStatus())
        repo.pendingState = "good"
        val vm = vm()
        advanceUntilIdle()

        dispatcher.emit(GoogleCalendarReturn(code = "c", state = "bad", error = null, cancelled = false))
        advanceUntilIdle()

        assertTrue(vm.state.value is GoogleCalendarUiState.Disconnected)
        assertTrue(repo.clearPendingCalls >= 1)
    }

    @Test
    fun disconnect_movesToDisconnected() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.connectedStatus())
        repo.calendarsResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is GoogleCalendarUiState.Connected)

        vm.onDisconnect()
        advanceUntilIdle()
        assertTrue(vm.state.value is GoogleCalendarUiState.Disconnected)
    }

    @Test
    fun connected_zeroCalendars_isEmptyListState() = runTest {
        repo.statusResult = ApiResult.Success(FakeGoogleCalendarRepository.connectedStatus())
        repo.calendarsResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is GoogleCalendarUiState.Connected)
        assertEquals(ListState.EMPTY, (state as GoogleCalendarUiState.Connected).listState)
    }
}
