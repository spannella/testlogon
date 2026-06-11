package com.testlogon.android.feature.calendar.scheduler

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class SchedulerListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeSchedulerRepository()

    private fun vm() = SchedulerListViewModel(repo)

    @Test
    fun loadsContent() = runTest {
        repo.listResult = ApiResult.Success(
            listOf(FakeSchedulerRepository.sampleScheduled("a1")),
        )
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is SchedulerListUiState.Content)
    }

    @Test
    fun emptyList_setsEmpty() = runTest {
        repo.listResult = ApiResult.Success(emptyList())
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is SchedulerListUiState.Empty)
    }

    @Test
    fun failure_setsError() = runTest {
        repo.listResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        advanceUntilIdle()
        assertTrue(vm.state.value is SchedulerListUiState.Error)
    }

    @Test
    fun cancel_refreshesList() = runTest {
        repo.listResult = ApiResult.Success(listOf(FakeSchedulerRepository.sampleScheduled("a1")))
        val vm = vm()
        advanceUntilIdle()
        vm.onCancel("a1")
        advanceUntilIdle()
        assertEquals(1, repo.cancelCalls)
    }

    @Test
    fun canCancel_onlyPending() = runTest {
        val vm = vm()
        val pending = FakeSchedulerRepository.sampleScheduled("a1")
        val completed = pending.copy(status = "completed")
        assertTrue(vm.canCancel(pending))
        assertFalse(vm.canCancel(completed))
    }
}
