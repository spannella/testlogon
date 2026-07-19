package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import androidx.paging.testing.asSnapshot
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogItemPage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-207 / AND-208 / AND-209 — [CatalogSearchViewModel] behaviour: query mirrored immediately,
 * min-length gate (no request below 2 chars), trimming, conflation to the final term, results mapped to
 * domain items, clear resets, and the query persisted to SavedStateHandle.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CatalogSearchViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun item(id: String) = CatalogItem(
        itemId = id, categoryId = "c", name = "n-$id", priceCents = 1, currency = "USD",
    )

    private fun vm(repo: FakeCatalogRepository, saved: SavedStateHandle = SavedStateHandle()) =
        CatalogSearchViewModel(
            repo,
            FakeShopAdsRepository(),
            FakeCatalogAdTrackRepository(),
            com.testlogon.android.data.ads.AdClickAttributionStore(),
            saved,
        )

    @Test
    fun onQueryChange_updatesQuery_andPersists() = runTest {
        val saved = SavedStateHandle()
        val model = vm(FakeCatalogRepository(), saved)
        model.onQueryChange("hoodie")
        assertEquals("hoodie", model.query.value)
        assertEquals("hoodie", saved.get<String>("catalog_search_query"))
    }

    @Test
    fun minLengthGate_belowTwoChars_noSearch() = runTest {
        val repo = FakeCatalogRepository()
        val model = vm(repo)
        // Drive the cold results flow with a cancellable collector (asSnapshot hangs on a hand-built
        // empty PagingData — the differ never signals completion); assert no search fired below min len.
        val job = launch { model.results.collect {} }
        model.onQueryChange("a")
        advanceUntilIdle()
        job.cancel()
        assertTrue("no search issued below min length", repo.searchQueries.isEmpty())
    }

    @Test
    fun search_trims_andMapsItems_forFinalTerm() = runTest {
        val repo = FakeCatalogRepository().apply {
            searchPages[null] = ApiResult.Success(
                CatalogItemPage(listOf(item("i1"), item("i2")), nextToken = null),
            )
        }
        val model = vm(repo)
        // Rapid edits conflate to the latest value in the query StateFlow before collection.
        model.onQueryChange("ho")
        model.onQueryChange("hood")
        model.onQueryChange("  hoodie  ")

        val ids = model.results.asSnapshot().map { it.itemId }
        assertEquals(listOf("i1", "i2"), ids)
        assertEquals(listOf("hoodie"), repo.searchQueries) // trimmed + single (final) search
    }

    @Test
    fun emptyResults_yieldNoItems() = runTest {
        val repo = FakeCatalogRepository().apply {
            searchPages[null] = ApiResult.Success(CatalogItemPage(emptyList(), nextToken = null))
        }
        val model = vm(repo)
        model.onQueryChange("zzqq")
        assertTrue(model.results.asSnapshot().isEmpty())
        assertEquals(listOf("zzqq"), repo.searchQueries)
    }

    @Test
    fun onClear_resetsQuery() = runTest {
        val saved = SavedStateHandle(mapOf("catalog_search_query" to "shoes"))
        val model = vm(FakeCatalogRepository(), saved)
        assertEquals("shoes", model.query.value)
        model.onClear()
        assertEquals("", model.query.value)
        assertEquals("", saved.get<String>("catalog_search_query"))
    }
}
