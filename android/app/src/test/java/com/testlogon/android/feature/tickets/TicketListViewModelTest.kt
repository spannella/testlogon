package com.testlogon.android.feature.tickets

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo
import com.testlogon.android.feature.tickets.ui.TicketListViewModel
import com.testlogon.android.feature.tickets.ui.TicketsEffect
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * AND-372 - tests for [TicketListViewModel]: the spaceId is read from SavedStateHandle, the best-effort
 * getSpace read populates the top-bar title, and a TERMINAL 401 on that read emits the one-shot
 * NavigateToLogin effect. The paged ticket list itself is exercised in the repository / Compose paging tests.
 *
 * runCurrent (NOT advanceUntilIdle) drains the init title read; the effect channel is collected on
 * backgroundScope.launch.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TicketListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeTicketsRepo()

    private fun vm() = TicketListViewModel(
        repository = repo,
        savedState = SavedStateHandle(mapOf(TicketListViewModel.ARG_SPACE_ID to "s1")),
    )

    @Test
    fun load_success_populatesSpaceTitle() = runTest {
        repo.spaceResult = ApiResult.Success(TicketSpace(spaceId = "s1", name = "Billing support"))
        val vm = vm()
        runCurrent()
        assertEquals("Billing support", vm.spaceTitle.value)
    }

    @Test
    fun load_failure_leavesTitleNull_noEffect() = runTest {
        repo.spaceResult = FakeTicketsRepo.ticketsFailure(500)
        val received = mutableListOf<TicketsEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        assertEquals(null, vm.spaceTitle.value)
        assertEquals(emptyList<TicketsEffect>(), received)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        repo.spaceResult = FakeTicketsRepo.ticketsFailure(401)
        val received = mutableListOf<TicketsEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        assertEquals(listOf(TicketsEffect.NavigateToLogin), received)
    }
}
