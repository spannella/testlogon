package com.testlogon.android.feature.tickets

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo.Companion.space
import com.testlogon.android.feature.tickets.ui.SpacesListUiState
import com.testlogon.android.feature.tickets.ui.SpacesListViewModel
import com.testlogon.android.feature.tickets.ui.TicketsEffect
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-372 - tests for [SpacesListViewModel]: a load resolves to Content, an empty list -> Empty, a failure ->
 * Error, a refresh failure keeps the last-good list with isStale=true, and a TERMINAL 401 emits the one-shot
 * NavigateToLogin effect (NOT a generic error).
 *
 * runCurrent (NOT advanceUntilIdle) drains the init load(); the effect channel is collected on
 * backgroundScope.launch so the test never blocks on it.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class SpacesListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeTicketsRepo()

    private fun vm() = SpacesListViewModel(repo)

    @Test
    fun load_success_isContent() = runTest {
        repo.spacesResult = ApiResult.Success(listOf(space("s1"), space("s2")))
        val vm = vm()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is SpacesListUiState.Content)
        assertEquals(listOf("s1", "s2"), (state as SpacesListUiState.Content).spaces.map { it.spaceId })
        assertFalse(state.isStale)
    }

    @Test
    fun load_emptyList_isEmpty() = runTest {
        repo.spacesResult = ApiResult.Success(emptyList())
        val vm = vm()
        runCurrent()
        assertEquals(SpacesListUiState.Empty, vm.uiState.value)
    }

    @Test
    fun load_failure_isError() = runTest {
        repo.spacesResult = FakeTicketsRepo.ticketsFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is SpacesListUiState.Error)
        assertEquals(500, (state as SpacesListUiState.Error).error.status)
    }

    @Test
    fun refreshFailure_keepsLastGood_andFlagsStale() = runTest {
        repo.spacesResult = ApiResult.Success(listOf(space("s1")))
        val vm = vm()
        runCurrent()
        assertTrue(vm.uiState.value is SpacesListUiState.Content)

        repo.spacesResult = FakeTicketsRepo.ticketsFailure(503)
        vm.refresh()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is SpacesListUiState.Content)
        state as SpacesListUiState.Content
        assertEquals(listOf("s1"), state.spaces.map { it.spaceId })
        assertTrue(state.isStale)
        assertFalse(state.isRefreshing)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        repo.spacesResult = FakeTicketsRepo.ticketsFailure(401)
        val received = mutableListOf<TicketsEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        assertEquals(listOf(TicketsEffect.NavigateToLogin), received)
    }
}
