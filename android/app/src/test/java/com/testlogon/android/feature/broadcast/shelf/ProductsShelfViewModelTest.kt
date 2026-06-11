package com.testlogon.android.feature.broadcast.shelf

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.broadcast.shelf.ShelfProduct
import com.testlogon.android.data.broadcast.shelf.ShelfRepository
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

class ProductsShelfViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private class FakeRepo(var result: ApiResult<List<ShelfProduct>>) : ShelfRepository {
        var calls = 0
        override suspend fun getSessionProducts(sessionId: String): ApiResult<List<ShelfProduct>> {
            calls++
            return result
        }
    }

    private fun product(id: String) = ShelfProduct(id, "c1", id, 4500, "USD", null, null)

    @Test
    fun firstExpand_loadsOnce_secondExpandDoesNotReload() = runTest {
        val repo = FakeRepo(ApiResult.Success(listOf(product("i1"))))
        val vm = ProductsShelfViewModel("s1", repo)

        vm.setExpanded(true)
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ProductsShelfUiState.Ready)
        assertEquals(1, repo.calls)

        vm.setExpanded(false)
        vm.setExpanded(true)
        advanceUntilIdle()
        // Already loaded -> no re-fetch from a re-open.
        assertEquals(1, repo.calls)
    }

    @Test
    fun emptyList_mapsToEmpty() = runTest {
        val repo = FakeRepo(ApiResult.Success(emptyList()))
        val vm = ProductsShelfViewModel("s1", repo)
        vm.setExpanded(true)
        advanceUntilIdle()
        assertEquals(ProductsShelfUiState.Empty, vm.uiState.value)
    }

    @Test
    fun failure_mapsToRetryableError() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = ProductsShelfViewModel("s1", repo)
        vm.setExpanded(true)
        advanceUntilIdle()
        val state = vm.uiState.value
        assertTrue(state is ProductsShelfUiState.Error)
        assertTrue((state as ProductsShelfUiState.Error).retryable)
    }

    @Test
    fun authError_mapsToNonRetryable() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 401, message = "auth")))
        val vm = ProductsShelfViewModel("s1", repo)
        vm.setExpanded(true)
        advanceUntilIdle()
        assertEquals(false, (vm.uiState.value as ProductsShelfUiState.Error).retryable)
    }

    @Test
    fun retry_reloads() = runTest {
        val repo = FakeRepo(ApiResult.Failure(ApiError(status = 500, message = "boom")))
        val vm = ProductsShelfViewModel("s1", repo)
        vm.setExpanded(true)
        advanceUntilIdle()
        repo.result = ApiResult.Success(listOf(product("i1")))
        vm.retry()
        advanceUntilIdle()
        assertTrue(vm.uiState.value is ProductsShelfUiState.Ready)
        assertEquals(2, repo.calls)
    }
}
