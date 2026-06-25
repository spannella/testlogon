package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.SyndicateListItem
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateRepo
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * Batch-7 - unit tests for [SyndicateListViewModel], now backed by the real GET ui/syndicates list endpoint
 * plus the create flow. Uses runCurrent (NOT advanceUntilIdle).
 */
class SyndicateListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeSyndicateRepo) = SyndicateListViewModel(repo)

    @Test
    fun load_empty_surfacesEmpty() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo().apply { listResult = ApiResult.Success(emptyList()) }
        val sut = vm(repo)
        runCurrent()

        assertEquals(SyndicateListUiState.Empty, sut.uiState.value)
        assertEquals(1, repo.listCallCount)
    }

    @Test
    fun load_withItems_surfacesContent() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo().apply {
            listResult = ApiResult.Success(listOf(SyndicateListItem(id = "syn_1", name = "Aces", role = "admin")))
        }
        val sut = vm(repo)
        runCurrent()

        val state = sut.uiState.value
        assertTrue(state is SyndicateListUiState.Content)
        assertEquals(1, (state as SyndicateListUiState.Content).items.size)
    }

    @Test
    fun load_failure_surfacesError() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo().apply { listResult = FakeSyndicateRepo.failure(500) }
        val sut = vm(repo)
        runCurrent()

        assertTrue(sut.uiState.value is SyndicateListUiState.Error)
    }

    @Test
    fun submitCreate_success_emitsCreatedAndReloads() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo().apply {
            listResult = ApiResult.Success(emptyList())
            createResult = ApiResult.Success(SyndicateListItem(id = "syn_new", name = "New", role = "admin"))
        }
        val sut = vm(repo)
        runCurrent()

        sut.openCreate()
        sut.onCreateNameChange("Squad")
        sut.submitCreate()
        runCurrent()

        assertEquals(1, repo.createCallCount)
        assertEquals("Squad" to null, repo.createArgs.single())
        // list reloaded after create
        assertTrue(repo.listCallCount >= 2)
        assertEquals(false, sut.createState.value.visible)
    }

    @Test
    fun submitCreate_invalidName_isNoOp() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo()
        val sut = vm(repo)
        runCurrent()

        sut.openCreate()
        sut.onCreateNameChange("x") // too short (<2)
        sut.submitCreate()
        runCurrent()

        assertEquals(0, repo.createCallCount)
    }
}
