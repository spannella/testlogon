package com.testlogon.android.feature.messaging.groupcreate

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.data.messaging.group.FakeGroupRepository
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class GroupCreateViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val messaging = FakeMessagingRepository()
    private val groups = FakeGroupRepository()

    private fun vm() = GroupCreateViewModel(messaging, groups, SavedStateHandle())

    private fun conversation(id: String) = Conversation(
        id = id, title = "Group", iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = 0, unreadCount = 0,
    )

    // canCreate gating (AC-2 / FR-3 / FR-4 / FR-7)
    @Test
    fun canCreate_requiresNameAndTwoParticipants() = runTest {
        val viewModel = vm()
        assertFalse(viewModel.state.value.canCreate)

        viewModel.onNameChange("Trip")
        assertFalse(viewModel.state.value.canCreate) // no participants yet

        // Seed candidates then select two.
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("u1", "Ann"), Contact("u2", "Bob")))
        viewModel.onQueryChange("a")
        advanceTimeBy(400)
        advanceUntilIdle()
        viewModel.onToggleParticipant("u1")
        assertFalse(viewModel.state.value.canCreate) // only one
        viewModel.onToggleParticipant("u2")
        assertTrue(viewModel.state.value.canCreate)

        viewModel.onNameChange("   ")
        assertFalse(viewModel.state.value.canCreate) // blank name
    }

    @Test
    fun toggleParticipant_dedupesAndRemoves() = runTest {
        val viewModel = vm()
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("u1", "Ann"), Contact("u2", "Bob")))
        viewModel.onQueryChange("a")
        advanceTimeBy(400)
        advanceUntilIdle()

        viewModel.onToggleParticipant("u1")
        viewModel.onToggleParticipant("u1") // toggle off (dedupe)
        assertTrue(viewModel.state.value.selected.isEmpty())

        viewModel.onToggleParticipant("u1")
        viewModel.onToggleParticipant("u2")
        assertEquals(2, viewModel.state.value.selected.size)
        viewModel.onRemoveParticipant("u1")
        assertEquals(listOf("u2"), viewModel.state.value.selected.map { it.userId })
    }

    @Test
    fun createClick_success_emitsCreatedWithTrimmedTitle() = runTest {
        groups.createResult = ApiResult.Success(conversation("conv_1"))
        val viewModel = vm()
        viewModel.onNameChange("  Trip  ")
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("u1", "Ann"), Contact("u2", "Bob")))
        viewModel.onQueryChange("a"); advanceTimeBy(400); advanceUntilIdle()
        viewModel.onToggleParticipant("u1"); viewModel.onToggleParticipant("u2")

        val events = mutableListOf<GroupCreateEvent>()
        val job = launch { viewModel.events.collect { events += it } }
        viewModel.onCreateClick()
        advanceUntilIdle()
        assertEquals(GroupCreateEvent.Created("conv_1"), events.single())
        job.cancel()

        val (title, ids, _) = groups.createCalls.single()
        assertEquals("Trip", title) // trimmed
        assertEquals(listOf("u1", "u2"), ids)
    }

    @Test
    fun createClick_failure_preservesInput_andSetsError() = runTest {
        groups.createResult = ApiResult.Failure(ApiError(status = 422, message = "bad"))
        val viewModel = vm()
        viewModel.onNameChange("Trip")
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("u1", "Ann"), Contact("u2", "Bob")))
        viewModel.onQueryChange("a"); advanceTimeBy(400); advanceUntilIdle()
        viewModel.onToggleParticipant("u1"); viewModel.onToggleParticipant("u2")

        viewModel.onCreateClick()
        advanceUntilIdle()

        val s = viewModel.state.value
        assertFalse(s.isSubmitting)
        assertEquals("bad", s.errorMessage)
        assertEquals(2, s.selected.size) // preserved
        assertEquals("Trip", s.name)
    }

    @Test
    fun createClick_doubleTap_firesOnlyOnce() = runTest {
        groups.createResult = ApiResult.Success(conversation("conv_1"))
        val viewModel = vm()
        viewModel.onNameChange("Trip")
        messaging.searchContactsResult = ApiResult.Success(listOf(Contact("u1", "Ann"), Contact("u2", "Bob")))
        viewModel.onQueryChange("a"); advanceTimeBy(400); advanceUntilIdle()
        viewModel.onToggleParticipant("u1"); viewModel.onToggleParticipant("u2")

        viewModel.onCreateClick()
        viewModel.onCreateClick() // ignored: isSubmitting -> canCreate false
        advanceUntilIdle()
        assertEquals(1, groups.createCalls.size)
    }
}
