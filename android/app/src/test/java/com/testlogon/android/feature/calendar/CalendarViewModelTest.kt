package com.testlogon.android.feature.calendar

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.calendar.CalendarEvent
import com.testlogon.android.data.calendar.EventsPage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException
import java.time.Instant

@OptIn(ExperimentalCoroutinesApi::class)
class CalendarViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeCalendarRepository()

    // Fixed "today" = 2026-06-10 UTC.
    private val clock = object : CalendarClock() {
        override fun nowMillis(): Long =
            CalendarMath.toEpochDay(2026, 6, 10) * CalendarMath.MILLIS_PER_DAY + 12 * 3_600_000L
    }
    private val zone = object : CalendarZoneProvider() {
        override fun deviceZoneId(): String = "UTC"
        override fun overrideZoneId(): String? = null
    }

    private fun vm() = CalendarViewModel(
        repository = repo,
        zoneProvider = zone,
        clock = clock,
        savedState = SavedStateHandle(),
    )

    @Test
    fun loadsContent_month_default() = runTest {
        repo.eventsResult = ApiResult.Success(
            EventsPage(events = listOf(timedEvent("e1", 2026, 6, 10, 17))),
        )
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is CalendarUiState.Content)
        assertEquals(CalendarViewMode.MONTH, (state as CalendarUiState.Content).mode)
        assertEquals(42, state.monthDays.size)
        assertTrue(state.monthDays.any { it.events.isNotEmpty() })
    }

    @Test
    fun emptyWindow_setsIsEmpty_notError() = runTest {
        repo.eventsResult = ApiResult.Success(EventsPage(events = emptyList()))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value as CalendarUiState.Content
        assertTrue(state.isEmpty)
    }

    @Test
    fun calendarsNetworkError_mapsToOfflineError() = runTest {
        repo.calendarsResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is CalendarUiState.Error)
        assertTrue((state as CalendarUiState.Error).offline)
    }

    @Test
    fun eventsFailure_mapsToError() = runTest {
        repo.eventsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is CalendarUiState.Error)
    }

    @Test
    fun setMode_week_buildsWeekGrid() = runTest {
        repo.eventsResult = ApiResult.Success(
            EventsPage(events = listOf(timedEvent("e1", 2026, 6, 10, 17))),
        )
        val vm = vm()
        advanceUntilIdle()
        vm.onModeSelected(CalendarViewMode.WEEK)
        advanceUntilIdle()
        val state = vm.state.value as CalendarUiState.Content
        assertEquals(CalendarViewMode.WEEK, state.mode)
        assertTrue(state.weekGrid != null)
    }

    @Test
    fun stepForward_movesFocus_andRequeries() = runTest {
        val vm = vm()
        advanceUntilIdle()
        val before = repo.lastEventsStartUtc
        vm.stepForward()
        advanceUntilIdle()
        // A new window was requested (start changed because the month advanced).
        assertTrue(repo.lastEventsStartUtc != before)
    }

    @Test
    fun retry_reissues() = runTest {
        repo.eventsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is CalendarUiState.Error)
        repo.eventsResult = ApiResult.Success(EventsPage(events = emptyList()))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.state.value is CalendarUiState.Content)
    }

    @Test
    fun zoneMismatch_flaggedWhenOverrideDiffersFromDevice() = runTest {
        val mismatchZone = object : CalendarZoneProvider() {
            override fun deviceZoneId(): String = "UTC"
            override fun overrideZoneId(): String = "Asia/Tokyo"
        }
        val vm = CalendarViewModel(repo, mismatchZone, clock, SavedStateHandle())
        advanceUntilIdle()
        val state = vm.state.value as CalendarUiState.Content
        assertTrue(state.zoneMismatch)
        assertEquals("Asia/Tokyo", state.displayZoneId)
    }

    private fun timedEvent(id: String, y: Int, mo: Int, d: Int, hourUtc: Int): CalendarEvent =
        FakeCalendarRepository.sampleEvent(id).copy(
            startAt = Instant.ofEpochMilli(
                CalendarMath.toEpochDay(y, mo, d) * CalendarMath.MILLIS_PER_DAY +
                    hourUtc * 3_600_000L,
            ),
            endAt = Instant.ofEpochMilli(
                CalendarMath.toEpochDay(y, mo, d) * CalendarMath.MILLIS_PER_DAY +
                    (hourUtc + 1) * 3_600_000L,
            ),
        )
}
