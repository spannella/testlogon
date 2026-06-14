package com.testlogon.android.feature.messaging.contacts

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.Contact
import com.testlogon.android.data.messaging.Conversation
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

@OptIn(ExperimentalCoroutinesApi::class)
class ContactsViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) = ContactsViewModel(repo, saved)

    private fun contact(id: String, name: String = "Ada Lovelace") = Contact(id = id, displayName = name)

    private fun conv(id: String) = Conversation(
        id = id, title = "Ada", iconUrl = null, lastMessagePreview = null,
        lastActivityEpochSeconds = 1, unreadCount = 0,
    )

    // ---- AND-153/155: search state transitions ----

    @Test
    fun idle_onStart() {
        assertEquals(ContactsPhase.Idle, vm().uiState.value.phase)
    }

    @Test
    fun fullNameSearch_returnsResults() = runTest {
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1", "Ada Lovelace")))
        val vm = vm()
        vm.onQueryChange("Ada Lovelace")
        advanceUntilIdle()

        assertEquals(ContactsPhase.Results, vm.uiState.value.phase)
        assertEquals(listOf("u_1"), vm.uiState.value.contacts.map { it.id })
        assertEquals("Ada Lovelace", repo.searchContactsCalls.single())
    }

    @Test
    fun fragmentSearch_returnsResults() = runTest {
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1", "Alice"), contact("u_2", "Khalil")))
        val vm = vm()
        vm.onQueryChange("ali")
        advanceUntilIdle()

        assertEquals(ContactsPhase.Results, vm.uiState.value.phase)
        assertEquals(2, vm.uiState.value.contacts.size)
        assertEquals("ali", repo.searchContactsCalls.single())
    }

    @Test
    fun rapidTyping_coalescesToSingleSearch() = runTest {
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1")))
        val vm = vm()
        vm.onQueryChange("a")
        advanceTimeBy(100)
        vm.onQueryChange("al")
        advanceTimeBy(100)
        vm.onQueryChange("ali")
        advanceUntilIdle()

        assertEquals(1, repo.searchContactsCalls.size)
        assertEquals("ali", repo.searchContactsCalls.single())
    }

    @Test
    fun blankQuery_idle_noCall() = runTest {
        val vm = vm()
        vm.onQueryChange("   ")
        advanceUntilIdle()
        assertEquals(ContactsPhase.Idle, vm.uiState.value.phase)
        assertTrue(repo.searchContactsCalls.isEmpty())
    }

    @Test
    fun clear_returnsToIdle_clearsResults() = runTest {
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1")))
        val vm = vm()
        vm.onQueryChange("ada")
        advanceUntilIdle()
        assertEquals(ContactsPhase.Results, vm.uiState.value.phase)

        vm.onClear()
        advanceUntilIdle()
        assertEquals(ContactsPhase.Idle, vm.uiState.value.phase)
        assertTrue(vm.uiState.value.contacts.isEmpty())
        assertEquals("", vm.uiState.value.query)
    }

    @Test
    fun emptyResults_emitsEmptyPhaseWithQuery() = runTest {
        repo.searchContactsResult = ApiResult.Success(emptyList())
        val vm = vm()
        vm.onQueryChange("zzz")
        advanceUntilIdle()
        val phase = vm.uiState.value.phase
        assertTrue(phase is ContactsPhase.Empty)
        assertEquals("zzz", (phase as ContactsPhase.Empty).query)
    }

    @Test
    fun failure_emitsError_notOffline() = runTest {
        repo.searchContactsResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        vm.onQueryChange("ada")
        advanceUntilIdle()
        val phase = vm.uiState.value.phase
        assertTrue(phase is ContactsPhase.Error)
        assertEquals(false, (phase as ContactsPhase.Error).offline)
    }

    @Test
    fun networkError_emitsOfflineError() = runTest {
        repo.searchContactsResult = ApiResult.NetworkError(IOException("x"), isTimeout = true)
        val vm = vm()
        vm.onQueryChange("ada")
        advanceUntilIdle()
        val phase = vm.uiState.value.phase
        assertTrue(phase is ContactsPhase.Error)
        assertEquals(true, (phase as ContactsPhase.Error).offline)
    }

    @Test
    fun retry_reissuesCurrentQuery() = runTest {
        repo.searchContactsResult = ApiResult.NetworkError(IOException("x"), isTimeout = true)
        val vm = vm()
        vm.onQueryChange("ada")
        advanceUntilIdle()
        assertEquals(1, repo.searchContactsCalls.size)

        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1")))
        vm.retry()
        advanceUntilIdle()
        assertEquals(2, repo.searchContactsCalls.size)
        assertEquals(ContactsPhase.Results, vm.uiState.value.phase)
    }

    @Test
    fun queryCappedAt64Chars() = runTest {
        repo.searchContactsResult = ApiResult.Success(emptyList())
        val vm = vm()
        vm.onQueryChange("a".repeat(100))
        advanceUntilIdle()
        assertEquals(64, vm.uiState.value.query.length)
        assertEquals(64, repo.searchContactsCalls.single().length)
    }

    @Test
    fun savedState_roundTripsQuery() = runTest {
        val saved = SavedStateHandle()
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1")))
        val vm = vm(saved)
        vm.onQueryChange("ada")
        advanceUntilIdle()
        assertEquals("ada", saved.get<String>("contacts_search_query"))
    }

    @Test
    fun savedState_restoresQuery_andReissuesSearch() = runTest {
        val saved = SavedStateHandle().apply { set("contacts_search_query", "ada") }
        repo.searchContactsResult = ApiResult.Success(listOf(contact("u_1")))
        val vm = vm(saved)
        assertEquals("ada", vm.uiState.value.query)
        advanceUntilIdle()
        assertEquals(ContactsPhase.Results, vm.uiState.value.phase)
        assertEquals("ada", repo.searchContactsCalls.single())
    }

    // ---- AND-154: contact -> start conversation ----

    @Test
    fun contactClick_success_emitsOpenThread() = runTest {
        repo.findOrCreateDmResult = ApiResult.Success(conv("conv_1"))
        val vm = vm()
        val effects = mutableListOf<ContactsEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onContactClick(contact("u_peer"))
        advanceUntilIdle()

        assertEquals(listOf("u_peer"), repo.findOrCreateDmCalls)
        assertEquals(ContactsEffect.OpenThread("conv_1"), effects.single())
        assertNull(vm.uiState.value.pendingDmUserId)
        job.cancel()
    }

    @Test
    fun contactClick_failure_emitsShowError_withRetryUserId_noOpenThread() = runTest {
        repo.findOrCreateDmResult = FakeMessagingRepository.failure(404, "not found")
        val vm = vm()
        val effects = mutableListOf<ContactsEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onContactClick(contact("u_peer"))
        advanceUntilIdle()

        val effect = effects.single()
        assertTrue(effect is ContactsEffect.ShowError)
        assertEquals("u_peer", (effect as ContactsEffect.ShowError).retryUserId)
        assertNull(vm.uiState.value.pendingDmUserId)
        job.cancel()
    }

    @Test
    fun contactClick_networkError_emitsOfflineShowError() = runTest {
        repo.findOrCreateDmResult = ApiResult.NetworkError(IOException("x"), isTimeout = true)
        val vm = vm()
        val effects = mutableListOf<ContactsEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onContactClick(contact("u_peer"))
        advanceUntilIdle()

        val effect = effects.single()
        assertTrue(effect is ContactsEffect.ShowError)
        assertEquals(ContactsViewModel.OFFLINE_MESSAGE, (effect as ContactsEffect.ShowError).message)
        job.cancel()
    }

    @Test
    fun rapidDoubleTap_isSingleFlight_oneRequest() = runTest {
        repo.findOrCreateDmResult = ApiResult.Success(conv("conv_1"))
        val vm = vm()
        val effects = mutableListOf<ContactsEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onContactClick(contact("u_peer"))
        vm.onContactClick(contact("u_peer")) // ignored while pending (FR-4)
        advanceUntilIdle()

        assertEquals(1, repo.findOrCreateDmCalls.size)
        assertEquals(1, effects.size)
        job.cancel()
    }

    @Test
    fun retryStartDm_reInvokesFindOrCreate() = runTest {
        repo.findOrCreateDmResult = FakeMessagingRepository.failure(500, "boom")
        val vm = vm()
        val effects = mutableListOf<ContactsEffect>()
        val job = launch { vm.effects.collect { effects += it } }

        vm.onContactClick(contact("u_peer"))
        advanceUntilIdle()
        assertEquals(1, repo.findOrCreateDmCalls.size)

        repo.findOrCreateDmResult = ApiResult.Success(conv("conv_1"))
        vm.retryStartDm("u_peer")
        advanceUntilIdle()

        assertEquals(2, repo.findOrCreateDmCalls.size)
        assertTrue(effects.any { it is ContactsEffect.OpenThread })
        job.cancel()
    }

    @Test
    fun initialsOf_helper() {
        assertEquals("AL", initialsOf("Ada Lovelace"))
        assertEquals("K", initialsOf("Khalil"))
        assertEquals("?", initialsOf("   "))
    }
}
