package com.testlogon.android.feature.syndicates.ui

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.feature.syndicates.testing.FakeSyndicateRepo
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

/**
 * AND-361 - unit tests for [SyndicateListViewModel] (FR-6).
 *
 * NO LIST ENDPOINT: the SyndicateApi exposes only by-id reads, so this ViewModel surfaces
 * [SyndicateListUiState.NotAvailable] (a known capability gap, NOT an error) and does NOT call the
 * repository. These tests pin that contract: load()/refresh()/retry() all resolve to NotAvailable and the
 * repository's by-id reads are never invoked.
 *
 * REUSE: uses the existing AND-356 [FakeSyndicateRepo] (no new fake). Uses runCurrent (NOT advanceUntilIdle).
 */
class SyndicateListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeSyndicateRepo) = SyndicateListViewModel(repo)

    @Test
    fun load_surfacesNotAvailable_withoutCallingRepo() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo()
        val sut = vm(repo)
        runCurrent()

        assertEquals(SyndicateListUiState.NotAvailable, sut.uiState.value)
        assertEquals(0, repo.overviewCallCount)
        assertEquals(0, repo.licensingContentCallCount)
        assertEquals(0, repo.registerCallCount)
    }

    @Test
    fun refresh_staysNotAvailable() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo()
        val sut = vm(repo)
        runCurrent()

        sut.refresh()
        runCurrent()

        assertEquals(SyndicateListUiState.NotAvailable, sut.uiState.value)
        assertEquals(0, repo.overviewCallCount)
    }

    @Test
    fun retry_staysNotAvailable() = runTest(mainRule.dispatcher) {
        val repo = FakeSyndicateRepo()
        val sut = vm(repo)
        runCurrent()

        sut.retry()
        runCurrent()

        assertEquals(SyndicateListUiState.NotAvailable, sut.uiState.value)
        assertEquals(0, repo.overviewCallCount)
    }
}
