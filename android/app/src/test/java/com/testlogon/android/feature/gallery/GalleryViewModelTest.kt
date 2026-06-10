package com.testlogon.android.feature.gallery

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.gallery.GalleryCategory
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class GalleryViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun vm(repo: FakeGalleryRepository) = GalleryViewModel(repo)

    @Test
    fun init_loadsCategories() = runTest {
        val repo = FakeGalleryRepository().apply {
            categoriesResult = ApiResult.Success(listOf(GalleryCategory("travel", "Travel")))
        }
        val model = vm(repo)
        advanceUntilIdle()
        assertEquals(listOf(GalleryCategory("travel", "Travel")), model.uiState.value.categories)
    }

    @Test
    fun selectingCategory_setsCategory_clearsSearch() = runTest {
        val model = vm(FakeGalleryRepository())
        advanceUntilIdle()
        model.onSearch("bay")
        assertEquals("bay", model.uiState.value.searchQuery)
        model.onCategorySelected("travel")
        assertEquals("travel", model.uiState.value.selectedCategory)
        assertNull(model.uiState.value.searchQuery)
    }

    @Test
    fun search_setsQuery_clearsCategory() = runTest {
        val model = vm(FakeGalleryRepository())
        advanceUntilIdle()
        model.onCategorySelected("travel")
        model.onSearch("  bay  ")
        assertEquals("bay", model.uiState.value.searchQuery) // trimmed
        assertNull(model.uiState.value.selectedCategory)
    }

    @Test
    fun blankSearch_clearsQuery() = runTest {
        val model = vm(FakeGalleryRepository())
        advanceUntilIdle()
        model.onSearch("   ")
        assertNull(model.uiState.value.searchQuery)
    }

    @Test
    fun setColumns_updates() = runTest {
        val model = vm(FakeGalleryRepository())
        advanceUntilIdle()
        model.setColumns(4)
        assertEquals(4, model.uiState.value.columns)
    }
}
