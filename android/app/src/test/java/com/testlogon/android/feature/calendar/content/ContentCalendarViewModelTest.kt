package com.testlogon.android.feature.calendar.content

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.calendar.CalendarClock
import com.testlogon.android.feature.calendar.CalendarMath
import com.testlogon.android.feature.calendar.CalendarZoneProvider
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class ContentCalendarViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeContentCalendarRepository()

    // Fixed "today" = 2026-06-10 UTC 12:00.
    private val clock = object : CalendarClock() {
        override fun nowMillis(): Long =
            CalendarMath.toEpochDay(2026, 6, 10) * CalendarMath.MILLIS_PER_DAY + 12 * 3_600_000L
    }
    private val zone = object : CalendarZoneProvider() {
        override fun deviceZoneId(): String = "UTC"
        override fun overrideZoneId(): String? = null
    }

    private fun vm() = ContentCalendarViewModel(
        repository = repo,
        zoneProvider = zone,
        clock = clock,
        savedState = SavedStateHandle(),
    )

    /** 2026-06-12 12:00 UTC and 2026-06-12 18:00 UTC -> same day; 2026-06-20 -> a second day. */
    private fun secondsAt(year: Int, month: Int, day: Int, hour: Int): Long =
        CalendarMath.toEpochDay(year, month, day) * 86_400L + hour * 3_600L

    @Test
    fun loadsAndBucketsByDay_ascending() = runTest {
        repo.result = ApiResult.Success(
            listOf(
                FakeContentCalendarRepository.sample("b", secondsAt(2026, 6, 20, 9)),
                FakeContentCalendarRepository.sample("a2", secondsAt(2026, 6, 12, 18)),
                FakeContentCalendarRepository.sample("a1", secondsAt(2026, 6, 12, 9)),
            ),
        )
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ContentCalendarUiState.Content)
        val days = (state as ContentCalendarUiState.Content).days
        assertEquals(2, days.size)
        // First day ascending, items by time within the day.
        assertEquals(listOf("a1", "a2"), days.first().items.map { it.id })
        assertEquals(listOf("b"), days.last().items.map { it.id })
    }

    @Test
    fun emptyList_setsEmpty() = runTest {
        repo.result = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is ContentCalendarUiState.Empty)
    }

    @Test
    fun failure_mapsToError() = runTest {
        repo.result = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ContentCalendarUiState.Error)
        assertTrue((state as ContentCalendarUiState.Error).isOffline)
    }

    @Test
    fun staleFallback_afterPriorSuccess() = runTest {
        repo.result = ApiResult.Success(
            listOf(FakeContentCalendarRepository.sample("a1", secondsAt(2026, 6, 12, 9))),
        )
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is ContentCalendarUiState.Content)
        // Now a transient failure for the same period -> stale content retained.
        repo.result = ApiResult.NetworkError(IOException("offline"))
        vm.retry()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is ContentCalendarUiState.Content)
        assertTrue((state as ContentCalendarUiState.Content).isStale)
    }

    @Test
    fun periodChange_requeriesNewRange() = runTest {
        repo.result = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        val firstFrom = repo.lastRange?.from
        vm.nextMonth()
        advanceUntilIdle()
        val secondFrom = repo.lastRange?.from
        assertTrue(firstFrom != secondFrom)
        assertTrue((secondFrom?.epochSecond ?: 0) > (firstFrom?.epochSecond ?: 0))
    }
}
