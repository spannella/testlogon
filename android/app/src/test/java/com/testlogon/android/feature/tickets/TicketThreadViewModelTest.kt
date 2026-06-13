package com.testlogon.android.feature.tickets

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.feature.tickets.testing.FakeTicketsAuthStore
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo.Companion.message
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo.Companion.ticketWith
import com.testlogon.android.feature.tickets.ui.TicketThreadUiState
import com.testlogon.android.feature.tickets.ui.TicketThreadViewModel
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
 * AND-372 - tests for [TicketThreadViewModel]: a load with embedded messages -> Content (currentSub carried for
 * mine-vs-other), a ticket with no messages -> Empty, a failure -> Error, a refresh failure keeps the last-good
 * content with isStale=true, a TERMINAL 401 emits the one-shot NavigateToLogin effect, and the mine-vs-other
 * distinction follows sender_sub == currentSub.
 *
 * runCurrent (NOT advanceUntilIdle) drains the init load(); the effect channel is collected on
 * backgroundScope.launch.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class TicketThreadViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeTicketsRepo()

    private fun vm(currentSub: String? = "me") = TicketThreadViewModel(
        repository = repo,
        savedState = SavedStateHandle(
            mapOf(
                TicketThreadViewModel.ARG_SPACE_ID to "s1",
                TicketThreadViewModel.ARG_TICKET_ID to "t1",
            ),
        ),
        authStateStore = FakeTicketsAuthStore(currentSub),
    )

    @Test
    fun load_withMessages_isContent_carriesCurrentSub() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        val vm = vm(currentSub = "me")
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is TicketThreadUiState.Content)
        state as TicketThreadUiState.Content
        assertEquals("me", state.currentSub)
        assertEquals(1, state.ticket.messages.size)
        assertFalse(state.isStale)
    }

    @Test
    fun load_noMessages_isEmpty() = runTest {
        repo.ticketResult = ApiResult.Success(ticketWith(messages = emptyList()))
        val vm = vm()
        runCurrent()
        assertEquals(TicketThreadUiState.Empty, vm.uiState.value)
    }

    @Test
    fun load_failure_isError() = runTest {
        repo.ticketResult = FakeTicketsRepo.ticketsFailure(500)
        val vm = vm()
        runCurrent()
        val state = vm.uiState.value
        assertTrue(state is TicketThreadUiState.Error)
        assertEquals(500, (state as TicketThreadUiState.Error).error.status)
    }

    @Test
    fun refreshFailure_keepsLastGood_andFlagsStale() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        val vm = vm()
        runCurrent()
        assertTrue(vm.uiState.value is TicketThreadUiState.Content)

        repo.ticketResult = FakeTicketsRepo.ticketsFailure(503)
        vm.refresh()
        runCurrent()

        val state = vm.uiState.value
        assertTrue(state is TicketThreadUiState.Content)
        assertTrue((state as TicketThreadUiState.Content).isStale)
    }

    @Test
    fun load_401_emitsNavigateToLogin() = runTest {
        repo.ticketResult = FakeTicketsRepo.ticketsFailure(401)
        val received = mutableListOf<TicketsEffect>()
        val vm = vm()
        backgroundScope.launch { vm.effects.collect { received += it } }
        runCurrent()

        assertEquals(listOf(TicketsEffect.NavigateToLogin), received)
    }

    @Test
    fun mineVsOther_distinguishedBySenderSubMatchingCurrentSub() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(
                messages = listOf(
                    message("m1", senderSub = "me"),
                    message("m2", senderSub = "other"),
                ),
            ),
        )
        val vm = vm(currentSub = "me")
        runCurrent()

        val state = vm.uiState.value as TicketThreadUiState.Content
        val mine = state.ticket.messages.filter { it.senderSub == state.currentSub }
        assertEquals(listOf("m1"), mine.map { it.messageId })
    }
}
