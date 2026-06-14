package com.testlogon.android.feature.invoices

import androidx.paging.CombinedLoadStates
import androidx.paging.LoadState
import androidx.paging.LoadStates
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-249/250 — [InvoiceListViewModel.onLoadStateChanged] derives the coarse [InvoicesUiState] from the
 * paged list's [CombinedLoadStates] + item count: initial-loading gate, empty signal, and the
 * banner-on-error-with-content flag. retry() proxies to refresh (a fresh paged stream). This test does
 * NOT collect/asSnapshot the paging flow (per the gotcha — no asSnapshot on a hand-built source); it
 * feeds CombinedLoadStates directly, which is deterministic and JVM-pure.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class InvoiceListViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun combined(
        refresh: LoadState,
        append: LoadState = LoadState.NotLoading(endOfPaginationReached = false),
    ): CombinedLoadStates {
        val source = LoadStates(
            refresh = refresh,
            prepend = LoadState.NotLoading(endOfPaginationReached = true),
            append = append,
        )
        return CombinedLoadStates(
            refresh = refresh,
            prepend = LoadState.NotLoading(endOfPaginationReached = true),
            append = append,
            source = source,
            mediator = null,
        )
    }

    @Test
    fun onLoadStateChanged_initialLoading_setsInitialLoadingFlag() = runTest {
        val vm = InvoiceListViewModel(FakeInvoicesRepository())
        vm.onLoadStateChanged(combined(refresh = LoadState.Loading), itemCount = 0)
        val state = vm.uiState.value
        assertTrue(state.isInitialLoading)
        assertFalse(state.isEmpty)
        assertFalse(state.hasBanner)
    }

    @Test
    fun onLoadStateChanged_notLoadingEmpty_setsEmpty() = runTest {
        val vm = InvoiceListViewModel(FakeInvoicesRepository())
        vm.onLoadStateChanged(
            combined(refresh = LoadState.NotLoading(endOfPaginationReached = true)),
            itemCount = 0,
        )
        val state = vm.uiState.value
        assertTrue(state.isEmpty)
        assertFalse(state.isInitialLoading)
    }

    @Test
    fun onLoadStateChanged_appendErrorWithContent_raisesBanner() = runTest {
        val vm = InvoiceListViewModel(FakeInvoicesRepository())
        vm.onLoadStateChanged(
            combined(
                refresh = LoadState.NotLoading(endOfPaginationReached = false),
                append = LoadState.Error(RuntimeException("append failed")),
            ),
            itemCount = 5,
        )
        val state = vm.uiState.value
        assertTrue(state.hasBanner)
        assertFalse(state.isEmpty)
    }

    @Test
    fun retry_isExposed_andDoesNotThrow() = runTest {
        val vm = InvoiceListViewModel(FakeInvoicesRepository())
        val job = launch { vm.invoices.collect {} }
        advanceUntilIdle()
        vm.retry() // proxies to refresh (re-anchors the paged stream)
        advanceUntilIdle()
        job.cancel()
    }
}
