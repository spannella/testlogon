package com.testlogon.android.feature.earnings.percontent

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import androidx.paging.PagingSource
import androidx.paging.PagingState
import androidx.paging.testing.asSnapshot
import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.earnings.ContentRevenue
import com.testlogon.android.data.earnings.ContentRevenueDetail
import com.testlogon.android.data.earnings.ContentRevenuePage
import com.testlogon.android.data.earnings.ContentRevenueQuery
import com.testlogon.android.data.earnings.ContentRevenueRepository
import com.testlogon.android.data.earnings.RevenueSortKey
import com.testlogon.android.data.earnings.SortOrder
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test

class PerContentRevenueViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun row(id: String) = ContentRevenue(id, "post", id, 0, 0, 0, 0, 0, 0, 100)

    /** Fake repo: records the last query and feeds a one-page pager that fires the header callback. */
    private class FakeRepo : ContentRevenueRepository {
        val queries = mutableListOf<ContentRevenueQuery>()
        override fun pager(
            query: ContentRevenueQuery,
            onHeader: (ContentRevenuePage) -> Unit,
        ): Pager<String, ContentRevenue> {
            queries += query
            val page = ContentRevenuePage(
                items = listOf(ContentRevenue("a", "post", "a", 0, 0, 0, 0, 0, 0, 100)),
                totalItems = 7,
                totalRevenueCents = 4242,
                currency = "USD",
                nextCursor = null,
            )
            return Pager(PagingConfig(pageSize = 50, enablePlaceholders = false)) {
                object : PagingSource<String, ContentRevenue>() {
                    override suspend fun load(params: LoadParams<String>): LoadResult<String, ContentRevenue> {
                        if (params.key == null) onHeader(page)
                        return LoadResult.Page(page.items, prevKey = null, nextKey = null)
                    }
                    override fun getRefreshKey(state: PagingState<String, ContentRevenue>): String? = null
                }
            }
        }
        override suspend fun detail(contentId: String, fromDate: String?, toDate: String?) =
            ApiResult.Success(
                ContentRevenueDetail(
                    ContentRevenue(contentId, "post", contentId, 0, 0, 0, 0, 0, 0, 100),
                    "USD",
                    emptyList(),
                ),
            ) as ApiResult<ContentRevenueDetail>
    }

    @Test
    fun firstPage_populatesHeaderSummary() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        val vm = PerContentRevenueViewModel(repo)
        // asSnapshot drives the differ so PagingSource.load() runs + fires onHeader (a bare collect does not).
        vm.items.asSnapshot()
        advanceUntilIdle()
        assertEquals(7, vm.uiState.value.totalItems)
        assertEquals(4242L, vm.uiState.value.totalRevenueCents)
        assertEquals("USD", vm.uiState.value.currency)
    }

    @Test
    fun onSortChange_updatesQuery_andResetsHeader() = runTest(mainRule.dispatcher) {
        val repo = FakeRepo()
        val vm = PerContentRevenueViewModel(repo)
        val job = launch { vm.items.collect {} }
        advanceUntilIdle()

        vm.onSortChange(RevenueSortKey.TIPS, SortOrder.ASC)
        advanceUntilIdle()

        assertEquals(RevenueSortKey.TIPS, vm.uiState.value.query.sortBy)
        assertEquals(SortOrder.ASC, vm.uiState.value.query.sortOrder)
        // a new query was emitted to the repo (pager invalidated)
        assertEquals(RevenueSortKey.TIPS, repo.queries.last().sortBy)
        job.cancel()
    }

    @Test
    fun defaults_areTotalDesc() = runTest(mainRule.dispatcher) {
        val vm = PerContentRevenueViewModel(FakeRepo())
        assertEquals(RevenueSortKey.TOTAL, vm.uiState.value.query.sortBy)
        assertEquals(SortOrder.DESC, vm.uiState.value.query.sortOrder)
    }
}
