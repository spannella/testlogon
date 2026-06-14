package com.testlogon.android.feature.vod

import com.testlogon.android.MainDispatcherRule
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.vod.VodCategory
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Rule
import org.junit.Test

@OptIn(ExperimentalCoroutinesApi::class)
class VodCatalogViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private val repo = FakeVodRepository()

    @Test
    fun loadsCategories_onInit() = runTest {
        repo.categoriesResult = ApiResult.Success(listOf(VodCategory("a", "A"), VodCategory("b", "B")))
        val vm = VodCatalogViewModel(repo)
        advanceUntilIdle()
        assertEquals(listOf("a", "b"), vm.categories.value.map { it.slug })
    }

    @Test
    fun selectCategory_updatesActive_andToggleClears() = runTest {
        val vm = VodCatalogViewModel(repo)
        advanceUntilIdle()
        assertNull(vm.activeCategory.value)
        vm.selectCategory("comedy")
        assertEquals("comedy", vm.activeCategory.value)
        // Re-selecting the active category toggles back to "all" (null).
        vm.selectCategory("comedy")
        assertNull(vm.activeCategory.value)
    }
}
