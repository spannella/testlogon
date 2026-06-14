package com.testlogon.android.feature.catalog

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.catalog.CatalogRepository
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import java.io.IOException

/**
 * AND-206 / AND-208 / AND-209 — [ProductDetailViewModel] transitions: load -> Ready / NotFound / Error;
 * retry re-loads; add-to-cart emits AddedToCart / AddToCartFailed; the in-flight double-tap guard issues
 * one request; add is ignored when not Ready.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class ProductDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun savedState() = SavedStateHandle(
        mapOf(
            ProductDetailViewModel.ARG_CATEGORY_ID to "cat_books",
            ProductDetailViewModel.ARG_ITEM_ID to "itm_1",
        ),
    )

    private fun sampleItem(stockStatus: String = "in_stock") = CatalogItem(
        itemId = "itm_1",
        categoryId = "cat_books",
        name = "Tee",
        priceCents = 1999,
        currency = "USD",
        stockStatus = stockStatus,
        stockCount = 5,
    )

    private fun vm(
        catalog: FakeCatalogRepository,
        cart: FakeCartRepository = FakeCartRepository(),
    ) = ProductDetailViewModel(catalog, cart, savedState())

    @Test
    fun load_success_isReady() = runTest {
        val catalog = FakeCatalogRepository().apply { getItemResult = ApiResult.Success(sampleItem()) }
        val model = vm(catalog)
        advanceUntilIdle()
        val state = model.uiState.value
        assertTrue(state is ProductDetailUiState.Ready)
        assertEquals("itm_1", (state as ProductDetailUiState.Ready).item.itemId)
    }

    @Test
    fun load_notFound_isNotFound() = runTest {
        val catalog = FakeCatalogRepository().apply {
            getItemResult = ApiResult.Failure(
                ApiError(status = CatalogRepository.STATUS_ITEM_NOT_FOUND, message = "x"),
            )
        }
        val model = vm(catalog)
        advanceUntilIdle()
        assertEquals(ProductDetailUiState.NotFound, model.uiState.value)
    }

    @Test
    fun load_transportError_isRetryableError_retryRecovers() = runTest {
        val catalog = FakeCatalogRepository().apply {
            getItemResult = ApiResult.NetworkError(IOException("offline"))
        }
        val model = vm(catalog)
        advanceUntilIdle()
        val err = model.uiState.value
        assertTrue(err is ProductDetailUiState.Error)
        assertTrue((err as ProductDetailUiState.Error).retryable)

        catalog.getItemResult = ApiResult.Success(sampleItem())
        model.retry()
        advanceUntilIdle()
        assertTrue(model.uiState.value is ProductDetailUiState.Ready)
    }

    @Test
    fun httpError_isError() = runTest {
        val catalog = FakeCatalogRepository().apply {
            getItemResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(catalog)
        advanceUntilIdle()
        assertTrue(model.uiState.value is ProductDetailUiState.Error)
    }

    @Test
    fun addToCart_success_emitsAddedToCart() = runTest {
        val catalog = FakeCatalogRepository().apply { getItemResult = ApiResult.Success(sampleItem()) }
        val cart = FakeCartRepository().apply {
            result = ApiResult.Success(
                CartItem(sku = "itm_1", name = "Tee", quantity = 1, unitPriceCents = 1999, lineTotalCents = 1999),
            )
        }
        val model = vm(catalog, cart)
        advanceUntilIdle()

        val events = mutableListOf<ProductDetailEvent>()
        val job = launch { model.events.collect { events += it } }

        model.addToCart()
        advanceUntilIdle()

        assertEquals(1, cart.callCount)
        assertEquals(1, events.size)
        assertTrue(events.single() is ProductDetailEvent.AddedToCart)
        assertEquals(AddToCartStatus.Idle, model.addState.value) // back to idle after completion
        job.cancel()
    }

    @Test
    fun addToCart_failure_emitsAddToCartFailed() = runTest {
        val catalog = FakeCatalogRepository().apply { getItemResult = ApiResult.Success(sampleItem()) }
        val cart = FakeCartRepository().apply {
            result = ApiResult.Failure(ApiError(status = 500, message = "nope"))
        }
        val model = vm(catalog, cart)
        advanceUntilIdle()

        val events = mutableListOf<ProductDetailEvent>()
        val job = launch { model.events.collect { events += it } }

        model.addToCart()
        advanceUntilIdle()

        assertTrue(events.single() is ProductDetailEvent.AddToCartFailed)
        job.cancel()
    }

    @Test
    fun addToCart_doubleTap_whileInFlight_issuesOneRequest() = runTest {
        val catalog = FakeCatalogRepository().apply { getItemResult = ApiResult.Success(sampleItem()) }
        val cart = FakeCartRepository()
        val model = vm(catalog, cart)
        advanceUntilIdle()
        // Two synchronous taps before the dispatcher runs the launched coroutines: the first sets
        // InFlight synchronously, so the second is a no-op.
        model.addToCart()
        model.addToCart()
        advanceUntilIdle()
        assertEquals(1, cart.callCount)
    }

    @Test
    fun addToCart_ignoredWhenNotReady() = runTest {
        val catalog = FakeCatalogRepository().apply {
            getItemResult = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val cart = FakeCartRepository()
        val model = vm(catalog, cart)
        advanceUntilIdle()
        model.addToCart()
        advanceUntilIdle()
        assertEquals(0, cart.callCount)
    }
}

/** Test double for the cart repository: returns a fixed result and counts invocations. */
class FakeCartRepository : CartRepository {
    var result: ApiResult<CartItem> =
        ApiResult.Success(CartItem(sku = "s", name = "n", quantity = 1, unitPriceCents = 1, lineTotalCents = 1))
    var callCount = 0

    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> {
        callCount++
        return result
    }

    // AND-211 cart-surface methods are unused by the product-detail flow; default to an empty cart.
    override suspend fun loadCart(): ApiResult<com.testlogon.android.data.cart.FullCart> =
        ApiResult.Success(com.testlogon.android.data.cart.FullCart.empty("cart_test"))

    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<com.testlogon.android.data.cart.FullCart> =
        ApiResult.Success(com.testlogon.android.data.cart.FullCart.empty("cart_test"))

    override suspend fun removeLine(sku: String): ApiResult<com.testlogon.android.data.cart.FullCart> =
        ApiResult.Success(com.testlogon.android.data.cart.FullCart.empty("cart_test"))

    override suspend fun clearCart(): ApiResult<com.testlogon.android.data.cart.OkRespDto> =
        ApiResult.Success(com.testlogon.android.data.cart.OkRespDto(ok = true))
}
