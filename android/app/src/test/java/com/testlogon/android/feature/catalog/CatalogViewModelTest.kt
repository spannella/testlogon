package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.catalog.CatalogCategory
import com.testlogon.android.data.catalog.CatalogCategoryPage
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-205 — [CatalogViewModel] transitions: load -> Ready (default-select first), Empty, Error + retry,
 * selectCategory persists the id to SavedStateHandle, and a persisted selection is restored on reload.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CatalogViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun category(id: String) = CatalogCategory(categoryId = id, name = "n-$id", createdAt = "t")

    private fun vm(repo: FakeCatalogRepository, saved: SavedStateHandle = SavedStateHandle()) =
        CatalogViewModel(repo, saved)

    @Test
    fun load_defaultSelectsFirstCategory() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.Success(
                CatalogCategoryPage(listOf(category("a"), category("b")), nextToken = null),
            )
        }
        val saved = SavedStateHandle()
        val model = vm(repo, saved)
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state is CatalogUiState.Ready)
        assertEquals("a", (state as CatalogUiState.Ready).selectedId)
        assertEquals("a", saved.get<String?>(CatalogViewModel.KEY_SELECTED))
    }

    @Test
    fun load_emptyCategories_isEmpty() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.Success(CatalogCategoryPage(emptyList(), nextToken = null))
        }
        val model = vm(repo)
        advanceUntilIdle()
        assertEquals(CatalogUiState.Empty, model.uiState.value)
    }

    @Test
    fun load_failure_isError_retryRecovers() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        advanceUntilIdle()
        assertTrue(model.uiState.value is CatalogUiState.Error)

        repo.categoriesResult = ApiResult.Success(CatalogCategoryPage(listOf(category("a")), nextToken = null))
        model.retryCategories()
        advanceUntilIdle()
        assertTrue(model.uiState.value is CatalogUiState.Ready)
    }

    @Test
    fun networkError_isRetryableError() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.NetworkError(IOException("offline"))
        }
        val model = vm(repo)
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state is CatalogUiState.Error)
        assertTrue((state as CatalogUiState.Error).retryable)
    }

    @Test
    fun selectCategory_persists_andUpdatesReady() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.Success(
                CatalogCategoryPage(listOf(category("a"), category("b")), nextToken = null),
            )
        }
        val saved = SavedStateHandle()
        val model = vm(repo, saved)
        advanceUntilIdle()
        model.selectCategory("b")
        assertEquals("b", saved.get<String?>(CatalogViewModel.KEY_SELECTED))
        assertEquals("b", (model.uiState.value as CatalogUiState.Ready).selectedId)
    }

    @Test
    fun persistedSelection_isRestoredOnLoad() = runTest {
        val repo = FakeCatalogRepository().apply {
            categoriesResult = ApiResult.Success(
                CatalogCategoryPage(listOf(category("a"), category("b")), nextToken = null),
            )
        }
        val saved = SavedStateHandle(mapOf(CatalogViewModel.KEY_SELECTED to "b"))
        val model = vm(repo, saved)
        advanceUntilIdle()
        assertEquals("b", (model.uiState.value as CatalogUiState.Ready).selectedId)
    }
}
