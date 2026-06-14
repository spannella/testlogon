package com.testlogon.android.feature.calendar.scheduler

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.calendar.CalendarClock
import kotlinx.coroutines.CompletableDeferred
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
class SchedulerViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeSchedulerRepository()

    // Fixed "now" = epoch 1_800_000_000 (well before the sample scheduled time).
    private val clock = object : CalendarClock() {
        override fun nowMillis(): Long = 1_800_000_000L * 1000L
    }

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) =
        SchedulerViewModel(repo = repo, clock = clock, savedState = saved)

    private fun futureInstant(): Instant = Instant.ofEpochSecond(1_900_000_000L)

    @Test
    fun create_happyPath_sendsCreateDto_andSaves() = runTest {
        val vm = vm()
        advanceUntilIdle()
        vm.onActionTypeSelected("post")
        vm.onScheduledAtChanged(futureInstant())
        vm.onTitleChanged("t")
        vm.onSubmit()
        advanceUntilIdle()

        assertTrue(vm.state.value is SchedulerUiState.Saved)
        val sent = repo.lastCreate
        assertEquals("post", sent?.actionType)
        assertEquals(1_900_000_000L, sent?.scheduledAt)
        assertEquals("t", sent?.title)
    }

    @Test
    fun localValidation_blocksSubmit_noRepoCall() = runTest {
        val vm = vm()
        advanceUntilIdle()
        // No type, no time -> invalid.
        vm.onSubmit()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SchedulerUiState.Editing)
        assertTrue((state as SchedulerUiState.Editing).fieldErrors.isNotEmpty())
        assertEquals(0, repo.createCalls)
    }

    @Test
    fun editMode_hydratesForm_thenReschedulePartial() = runTest {
        repo.loadResult = ApiResult.Success(
            FakeSchedulerRepository.sampleScheduled(actionId = "act_1", actionType = "broadcast"),
        )
        val saved = SavedStateHandle(mapOf(SchedulerViewModel.ARG_ACTION_ID to "act_1"))
        val vm = vm(saved)
        advanceUntilIdle()
        val editing = vm.state.value
        assertTrue(editing is SchedulerUiState.Editing)
        assertEquals("broadcast", (editing as SchedulerUiState.Editing).form.actionType)

        vm.onScheduledAtChanged(Instant.ofEpochSecond(1_950_000_000L))
        vm.onSubmit()
        advanceUntilIdle()
        assertTrue(vm.state.value is SchedulerUiState.Saved)
        assertEquals(1_950_000_000L, repo.lastUpdate?.scheduledAt)
    }

    @Test
    fun serverError_422_retainsForm_setsFieldError() = runTest {
        repo.createResult = ApiResult.Failure(
            ApiError(
                status = 422,
                message = "Validation failed",
                raw = """{"detail":[{"loc":["body","scheduled_at"],"msg":"in the past"}]}""",
            ),
        )
        val vm = vm()
        advanceUntilIdle()
        vm.onActionTypeSelected("post")
        vm.onScheduledAtChanged(futureInstant())
        vm.onSubmit()
        advanceUntilIdle()

        val state = vm.state.value
        assertTrue(state is SchedulerUiState.Editing)
        val editing = state as SchedulerUiState.Editing
        assertEquals("post", editing.form.actionType) // form retained
        assertTrue(editing.fieldErrors.containsKey(SchedulerField.ScheduledAt))
        assertEquals("Validation failed", editing.transientError)
    }

    @Test
    fun offline_setsOffline_noRetry() = runTest {
        repo.createResult = ApiResult.NetworkError(IOException("offline"))
        val vm = vm()
        advanceUntilIdle()
        vm.onActionTypeSelected("post")
        vm.onScheduledAtChanged(futureInstant())
        vm.onSubmit()
        advanceUntilIdle()
        val state = vm.state.value
        assertTrue(state is SchedulerUiState.Editing)
        assertTrue((state as SchedulerUiState.Editing).isOffline)
        assertEquals(1, repo.createCalls)
    }

    @Test
    fun doubleSubmit_firesRepoOnce() = runTest {
        val gate = CompletableDeferred<Unit>()
        repo.createGate = gate
        val vm = vm()
        advanceUntilIdle()
        vm.onActionTypeSelected("post")
        vm.onScheduledAtChanged(futureInstant())
        vm.onSubmit()
        advanceUntilIdle()
        // Second submit while the first is in flight.
        vm.onSubmit()
        advanceUntilIdle()
        gate.complete(Unit)
        advanceUntilIdle()
        assertEquals(1, repo.createCalls)
    }
}
