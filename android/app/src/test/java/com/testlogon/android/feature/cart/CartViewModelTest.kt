package com.testlogon.android.feature.cart

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import com.testlogon.android.data.cart.OkRespDto
import com.testlogon.android.data.catalog.CatalogItem
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-211 / AND-212 — [CartViewModel] transitions: load -> Loaded / Empty / Error; optimistic qty
 * change reconciles on success and rolls back on failure; remove transitions to empty; per-row guard
 * issues one request; search filters + clear restores; query persisted to SavedStateHandle.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CartViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun item(sku: String, qty: Int = 1, unit: Long = 1000, name: String = "Item-$sku") =
        CartItem(sku = sku, name = name, quantity = qty, unitPriceCents = unit, lineTotalCents = unit * qty)

    private fun cart(vararg items: CartItem) =
        FullCart(cartId = "cart_1", items = items.toList(), totalCents = items.sumOf { it.lineTotalCents }, currency = "USD")

    private fun vm(repo: FakeCartRepository, saved: SavedStateHandle = SavedStateHandle()) =
        CartViewModel(repo, saved)

    @Test
    fun load_success_isLoaded() = runTest {
        val repo = FakeCartRepository().apply { loadResult = ApiResult.Success(cart(item("A", qty = 2))) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state.load is CartLoadState.Loaded)
        assertEquals(2000L, state.cart?.totalCents)
        job.cancel()
    }

    @Test
    fun load_emptyCart_isEmpty() = runTest {
        val repo = FakeCartRepository().apply { loadResult = ApiResult.Success(FullCart.empty("cart_1")) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        assertTrue(model.uiState.value.isEmpty)
        job.cancel()
    }

    @Test
    fun load_networkError_isRetryableError() = runTest {
        val repo = FakeCartRepository().apply { loadResult = ApiResult.NetworkError(IOException("x")) }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        val load = model.uiState.value.load
        assertTrue(load is CartLoadState.Error)
        assertTrue((load as CartLoadState.Error).retryable)
        job.cancel()
    }

    @Test
    fun onQuantityChange_optimistic_thenReconciles() = runTest {
        val repo = FakeCartRepository().apply {
            loadResult = ApiResult.Success(cart(item("A", qty = 1, unit = 1000)))
            setQtyResult = ApiResult.Success(cart(item("A", qty = 3, unit = 1000)))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onQuantityChange("A", 3)
        advanceUntilIdle()
        // Reconciled to the server cart.
        assertEquals(3, model.uiState.value.cart?.items?.single()?.quantity)
        assertEquals(3000L, model.uiState.value.cart?.totalCents)
        assertEquals(1, repo.setQtyCalls)
        assertFalse(model.uiState.value.isMutating)
        job.cancel()
    }

    @Test
    fun onQuantityChange_failure_rollsBack_andEmitsEvent() = runTest {
        val repo = FakeCartRepository().apply {
            loadResult = ApiResult.Success(cart(item("A", qty = 2, unit = 1000)))
            setQtyResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        val events = mutableListOf<CartEvent>()
        val ejob = launch { model.events.collect { events += it } }
        advanceUntilIdle()

        model.onQuantityChange("A", 5)
        advanceUntilIdle()

        // Rolled back to qty 2 / total 2000.
        assertEquals(2, model.uiState.value.cart?.items?.single()?.quantity)
        assertEquals(2000L, model.uiState.value.cart?.totalCents)
        assertTrue(events.single() is CartEvent.MutationFailed)
        job.cancel()
        ejob.cancel()
    }

    @Test
    fun onQuantityChange_belowOne_isNoOp() = runTest {
        val repo = FakeCartRepository().apply {
            loadResult = ApiResult.Success(cart(item("A", qty = 1)))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        model.onQuantityChange("A", 0)
        advanceUntilIdle()
        assertEquals(0, repo.setQtyCalls)
        job.cancel()
    }

    @Test
    fun onRemove_lastItem_transitionsToEmpty() = runTest {
        val repo = FakeCartRepository().apply {
            loadResult = ApiResult.Success(cart(item("A", qty = 1)))
            removeResult = ApiResult.Success(FullCart.empty("cart_1"))
        }
        val model = vm(repo)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()
        model.onRemove("A")
        advanceUntilIdle()
        assertTrue(model.uiState.value.isEmpty)
        assertEquals(1, repo.removeCalls)
        job.cancel()
    }

    @Test
    fun search_filtersBySku_andName_thenClearRestores() = runTest {
        val repo = FakeCartRepository().apply {
            loadResult = ApiResult.Success(
                cart(
                    item("TL-SHIRT", name = "Cool Tee"),
                    item("TL-MUG", name = "Coffee Mug"),
                ),
            )
        }
        val saved = SavedStateHandle()
        val model = vm(repo, saved)
        val job = launch { model.uiState.collect {} }
        advanceUntilIdle()

        model.onQueryChange("mug")
        advanceUntilIdle()
        assertEquals(listOf("TL-MUG"), model.uiState.value.filtered.items.map { it.sku })
        assertEquals("mug", saved.get<String>(CartViewModel.KEY_QUERY))

        model.onClearQuery()
        advanceUntilIdle()
        assertEquals(2, model.uiState.value.filtered.items.size)
        job.cancel()
    }
}

/** Test double for the cart repository. */
class FakeCartRepository : CartRepository {
    var loadResult: ApiResult<FullCart> = ApiResult.Success(FullCart.empty("cart_1"))
    var setQtyResult: ApiResult<FullCart> = ApiResult.Success(FullCart.empty("cart_1"))
    var removeResult: ApiResult<FullCart> = ApiResult.Success(FullCart.empty("cart_1"))
    var setQtyCalls = 0
    var removeCalls = 0

    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        ApiResult.Success(CartItem(sku = "s", name = "n", quantity = 1, unitPriceCents = 1, lineTotalCents = 1))

    override suspend fun loadCart(): ApiResult<FullCart> = loadResult

    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart> {
        setQtyCalls++
        return setQtyResult
    }

    override suspend fun removeLine(sku: String): ApiResult<FullCart> {
        removeCalls++
        return removeResult
    }

    override suspend fun clearCart(): ApiResult<OkRespDto> = ApiResult.Success(OkRespDto(ok = true))
}
