package com.testlogon.android.feature.tickets

import androidx.lifecycle.SavedStateHandle
import com.squareup.moshi.Moshi
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.tickets.TicketSendState
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.tickets.testing.FakeTicketsAuthStore
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo.Companion.message
import com.testlogon.android.feature.tickets.testing.FakeTicketsRepo.Companion.spaceWithMember
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
import org.junit.Assert.assertNull
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
    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    private fun vm(currentSub: String? = "me") = TicketThreadViewModel(
        repository = repo,
        savedState = SavedStateHandle(
            mapOf(
                TicketThreadViewModel.ARG_SPACE_ID to "s1",
                TicketThreadViewModel.ARG_TICKET_ID to "t1",
            ),
        ),
        authStateStore = FakeTicketsAuthStore(currentSub),
        errorParser = errorParser,
    ).apply { clock = { 1_000L } }

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

    // ---- AND-373: reply composer ----

    private fun contentOf(vm: TicketThreadViewModel): TicketThreadUiState.Content =
        vm.uiState.value as TicketThreadUiState.Content

    @Test
    fun canPost_editor_canPost_viewerCannot() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "editor"))
        val editorVm = vm(currentSub = "me")
        runCurrent()
        assertTrue(contentOf(editorVm).composer.canPost)

        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "viewer"))
        val viewerVm = vm(currentSub = "me")
        runCurrent()
        assertFalse(contentOf(viewerVm).composer.canPost)
    }

    @Test
    fun onSend_optimisticInsert_sending_andComposerCleared() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        // Make reply hang so we observe the in-flight SENDING state before reconcile.
        repo.replyResult = ApiResult.Success(ticketWith(messages = emptyList()))
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("hello there")
        // Do NOT runCurrent past the launch yet: assert the synchronous optimistic insert + clear.
        vm.onSend()

        val content = contentOf(vm)
        assertEquals("", content.composer.draft)
        assertTrue(content.composer.sending)
        val optimistic = content.ticket.messages.last()
        assertEquals("hello there", optimistic.body)
        assertEquals("me", optimistic.senderSub)
        assertEquals(TicketSendState.SENDING, optimistic.sendState)
        assertEquals(1_000L, optimistic.createdAt)
    }

    @Test
    fun onSend_success_reconcilesToCanonical_dedupedByMessageId() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        repo.replyResult = ApiResult.Success(
            ticketWith(
                messages = listOf(
                    message("m1", senderSub = "other"),
                    message("m2", senderSub = "me", body = "hello there"),
                ),
            ),
        )
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("hello there")
        vm.onSend()
        runCurrent()

        val content = contentOf(vm)
        val last = content.ticket.messages.last()
        assertEquals("m2", last.messageId)
        assertEquals(TicketSendState.SENT, last.sendState)
        assertNull(last.clientId)
        // No optimistic placeholder left over; no duplicate m2.
        assertEquals(1, content.ticket.messages.count { it.messageId == "m2" })
        assertFalse(content.composer.sending)
        assertEquals(Triple("s1", "t1", "hello there"), repo.replyArgs.single())
    }

    @Test
    fun onSend_failure_marksFailed_andRetryable() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        repo.replyResult = ApiResult.Failure(ApiError(status = 403, message = "forbidden"))
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("nope")
        vm.onSend()
        runCurrent()

        val content = contentOf(vm)
        val failed = content.ticket.messages.last()
        assertEquals(TicketSendState.FAILED, failed.sendState)
        assertEquals("forbidden", content.composer.sendError)
        assertFalse(content.composer.sending)

        // User-driven retry re-sends the same body, no auto-retry happened in between.
        repo.replyResult = ApiResult.Success(
            ticketWith(
                messages = listOf(
                    message("m1", senderSub = "other"),
                    message("m9", senderSub = "me", body = "nope"),
                ),
            ),
        )
        vm.onRetry(failed.clientId!!)
        runCurrent()

        val after = contentOf(vm)
        assertEquals("m9", after.ticket.messages.last().messageId)
        assertEquals(2, repo.replyArgs.size)
        assertTrue(repo.replyArgs.all { it.third == "nope" })
    }

    @Test
    fun onSend_422_mapsBodyFieldError() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        repo.replyResult = ApiResult.Failure(
            ApiError(
                status = 422,
                message = "validation",
                raw = """{"detail":[{"loc":["body","body"],"msg":"too long","type":"value_error"}]}""",
            ),
        )
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("x")
        vm.onSend()
        runCurrent()

        val content = contentOf(vm)
        assertEquals("too long", content.composer.fieldError)
        assertNull(content.composer.sendError)
        assertEquals(TicketSendState.FAILED, content.ticket.messages.last().sendState)
    }

    @Test
    fun onSend_doubleSendGuard_onlyOneInFlightPost() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        repo.replyResult = ApiResult.Success(ticketWith(messages = emptyList()))
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("hello")
        vm.onSend()
        // A second onSend while sending=true is ignored (composer already cleared + sending guard).
        vm.onSend()
        runCurrent()

        assertEquals(1, repo.replyArgs.size)
    }

    @Test
    fun onSend_blankOrOverLimit_notSent() = runTest {
        repo.ticketResult = ApiResult.Success(
            ticketWith(messages = listOf(message("m1", senderSub = "other"))),
        )
        repo.spaceResult = ApiResult.Success(spaceWithMember(memberSub = "me", role = "owner"))
        val vm = vm(currentSub = "me")
        runCurrent()

        vm.onDraftChanged("   ")
        vm.onSend()
        runCurrent()
        assertTrue(repo.replyArgs.isEmpty())

        vm.onDraftChanged("a".repeat(4001))
        vm.onSend()
        runCurrent()
        assertTrue(repo.replyArgs.isEmpty())
    }
}
