package com.testlogon.android.feature.purchases

import androidx.lifecycle.SavedStateHandle
import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-219 / AND-221 / AND-222 — [PurchaseHistoryViewModel]: query mirrored + persisted, debounce
 * collapses rapid input to one search for the final term, blank query routes to the list endpoint,
 * clear resets, results mapped, and the query restored from SavedStateHandle drives the search stream.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class PurchaseHistoryViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakePurchasesRepository, saved: SavedStateHandle = SavedStateHandle()) =
        PurchaseHistoryViewModel(repo, saved)

    @Test
    fun onQueryChange_updatesQuery_andPersists() = runTest {
        val saved = SavedStateHandle()
        val model = vm(FakePurchasesRepository(), saved)
        model.onQueryChange("tee")
        assertEquals("tee", model.query.value)
        assertEquals("tee", saved.get<String>(PurchaseHistoryViewModel.KEY_QUERY))
    }

    @Test
    fun blankQuery_routesToListEndpoint_notSearch() = runTest {
        val repo = FakePurchasesRepository(
            listResult = ApiResult.Success(listOf(FakePurchasesRepository.sampleItem("a"))),
        )
        val model = vm(repo)
        val ids = model.items.asSnapshot().map { it.id }
        assertEquals(listOf("a"), ids)
        assertEquals(1, repo.listCalls)
        assertTrue(repo.searchQueries.isEmpty())
    }

    @Test
    fun search_debounced_collapsesToFinalTerm() = runTest {
        val repo = FakePurchasesRepository(
            searchResult = ApiResult.Success(listOf(FakePurchasesRepository.sampleItem("s"))),
        )
        val model = vm(repo)
        // Rapid edits conflate to the latest value in the query StateFlow before collection.
        model.onQueryChange("t")
        model.onQueryChange("te")
        model.onQueryChange("  tee  ")
        val ids = model.items.asSnapshot().map { it.id }
        assertEquals(listOf("s"), ids)
        assertEquals(listOf("tee"), repo.searchQueries) // trimmed + single (final) search
    }

    @Test
    fun onClear_resetsQuery() = runTest {
        val saved = SavedStateHandle(mapOf(PurchaseHistoryViewModel.KEY_QUERY to "shoes"))
        val model = vm(FakePurchasesRepository(), saved)
        assertEquals("shoes", model.query.value)
        model.onClear()
        assertEquals("", model.query.value)
        assertEquals("", saved.get<String>(PurchaseHistoryViewModel.KEY_QUERY))
    }

    @Test
    fun restoredQuery_drivesSearchStream_onFirstCollection() = runTest {
        val repo = FakePurchasesRepository(
            searchResult = ApiResult.Success(listOf(FakePurchasesRepository.sampleItem("s"))),
        )
        val saved = SavedStateHandle(mapOf(PurchaseHistoryViewModel.KEY_QUERY to "tee"))
        val model = vm(repo, saved)
        assertEquals("tee", model.query.value)
        // asSnapshot materializes the page (triggering the PagingSource load) for the restored query.
        val ids = model.items.asSnapshot().map { it.id }
        assertEquals(listOf("s"), ids)
        assertEquals(listOf("tee"), repo.searchQueries)
        assertEquals(0, repo.listCalls)
    }
}
