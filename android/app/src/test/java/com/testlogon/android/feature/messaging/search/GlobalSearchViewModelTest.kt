package com.testlogon.android.feature.messaging.search

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.messaging.MessageSearchResultItem
import com.testlogon.android.feature.messaging.FakeMessagingRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceTimeBy
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class GlobalSearchViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeMessagingRepository()

    private fun vm(saved: SavedStateHandle = SavedStateHandle()) = GlobalSearchViewModel(repo, saved)

    private fun item(id: String, conv: String, text: String? = "deploy", createdAt: Long = 100L) =
        MessageSearchResultItem(
            messageId = id,
            conversationId = conv,
            senderId = "usr_1",
            kind = "text",
            text = text,
            createdAtEpochSeconds = createdAt,
        )

    @Test
    fun idle_onStart() {
        val vm = vm()
        assertEquals(GlobalSearchPhase.Idle, vm.uiState.value.phase)
    }

    @Test
    fun happyPath_groupsByConversation_setsResults() = runTest {
        repo.searchAllResult = ApiResult.Success(
            listOf(item("m1", "conv_a"), item("m2", "conv_b"), item("m3", "conv_a")),
        )
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()

        val s = vm.uiState.value
        assertEquals(GlobalSearchPhase.Results, s.phase)
        assertEquals(2, s.groups.size) // conv_a + conv_b
        assertEquals(3, s.resultCount)
        assertEquals("deploy", repo.searchAllCalls.single().first)
    }

    @Test
    fun rapidTyping_coalescesToSingleSearch() = runTest {
        repo.searchAllResult = ApiResult.Success(listOf(item("m1", "conv_a")))
        val vm = vm()
        vm.onQueryChange("de")
        advanceTimeBy(100)
        vm.onQueryChange("dep")
        advanceTimeBy(100)
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(1, repo.searchAllCalls.size)
        assertEquals("deploy", repo.searchAllCalls.single().first)
    }

    @Test
    fun shortQuery_tooShort_noCall() = runTest {
        val vm = vm()
        vm.onQueryChange("d")
        advanceUntilIdle()
        assertEquals(GlobalSearchPhase.TooShort, vm.uiState.value.phase)
        assertTrue(repo.searchAllCalls.isEmpty())
    }

    @Test
    fun blankQuery_idle_noCall() = runTest {
        val vm = vm()
        vm.onQueryChange("")
        advanceUntilIdle()
        assertEquals(GlobalSearchPhase.Idle, vm.uiState.value.phase)
        assertTrue(repo.searchAllCalls.isEmpty())
    }

    @Test
    fun emptyResults_emitsEmptyPhase() = runTest {
        repo.searchAllResult = ApiResult.Success(emptyList())
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(GlobalSearchPhase.Empty, vm.uiState.value.phase)
    }

    @Test
    fun failure_emitsError_notOffline() = runTest {
        repo.searchAllResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        val phase = vm.uiState.value.phase
        assertTrue(phase is GlobalSearchPhase.Error)
        assertEquals(false, (phase as GlobalSearchPhase.Error).offline)
    }

    @Test
    fun networkError_emitsOfflineError() = runTest {
        repo.searchAllResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = true)
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        val phase = vm.uiState.value.phase
        assertTrue(phase is GlobalSearchPhase.Error)
        assertEquals(true, (phase as GlobalSearchPhase.Error).offline)
    }

    @Test
    fun filters_reissueImmediately_andSendParams() = runTest {
        repo.searchAllResult = ApiResult.Success(listOf(item("m1", "conv_a")))
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(1, repo.searchAllCalls.size)

        vm.onSenderChange("usr_2")
        advanceUntilIdle()
        vm.onAfterChange(1746057600L)
        advanceUntilIdle()

        val last = repo.searchAllCalls.last()
        assertEquals("usr_2", last.second)
        assertEquals(1746057600L, last.third)
        assertTrue(vm.uiState.value.hasActiveFilters)
    }

    @Test
    fun clearFilters_resets_andReissues() = runTest {
        repo.searchAllResult = ApiResult.Success(listOf(item("m1", "conv_a")))
        val vm = vm()
        vm.onQueryChange("deploy")
        vm.onSenderChange("usr_2")
        advanceUntilIdle()
        vm.clearFilters()
        advanceUntilIdle()
        assertNull(vm.uiState.value.senderId)
        assertNull(vm.uiState.value.afterTs)
    }

    @Test
    fun savedState_roundTripsQueryAndFilters() = runTest {
        val saved = SavedStateHandle()
        repo.searchAllResult = ApiResult.Success(listOf(item("m1", "conv_a")))
        val vm = vm(saved)
        vm.onQueryChange("deploy")
        vm.onSenderChange("usr_2")
        vm.onAfterChange(1746057600L)
        advanceUntilIdle()
        assertEquals("deploy", saved.get<String>("search_query"))
        assertEquals("usr_2", saved.get<String>("search_sender_id"))
        assertEquals(1746057600L, saved.get<Long>("search_after_ts"))
    }

    @Test
    fun retry_reissuesCurrentCriteria() = runTest {
        repo.searchAllResult = ApiResult.NetworkError(java.io.IOException("x"), isTimeout = true)
        val vm = vm()
        vm.onQueryChange("deploy")
        advanceUntilIdle()
        assertEquals(1, repo.searchAllCalls.size)

        repo.searchAllResult = ApiResult.Success(listOf(item("m1", "conv_a")))
        vm.retry()
        advanceUntilIdle()
        assertEquals(2, repo.searchAllCalls.size)
        assertEquals(GlobalSearchPhase.Results, vm.uiState.value.phase)
    }

    @Test
    fun groupByConversation_preservesFirstAppearanceOrder() {
        val grouped = GlobalSearchViewModel.groupByConversation(
            listOf(item("m1", "conv_b"), item("m2", "conv_a"), item("m3", "conv_b")),
        )
        assertEquals(listOf("conv_b", "conv_a"), grouped.map { it.conversationId })
        assertEquals(2, grouped[0].items.size)
    }
}
