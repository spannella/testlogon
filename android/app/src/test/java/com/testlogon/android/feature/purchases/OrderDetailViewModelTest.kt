package com.testlogon.android.feature.purchases

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import com.testlogon.android.data.cart.OkRespDto
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.purchases.PurchaseShipping
import com.testlogon.android.data.tracking.Carrier
import com.testlogon.android.data.tracking.CarrierTracking
import com.testlogon.android.data.tracking.Shipment
import com.testlogon.android.data.tracking.ShipmentStatus
import com.testlogon.android.data.tracking.TrackingRepository
import com.testlogon.android.feature.tracking.TrackingUiState
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-220 / AND-222 — [OrderDetailViewModel]: Loading -> Content (with embedded AND-215 tracking),
 * items resolved from cart_id, no-shipping -> NotShipped tracking, tracking failure isolated (Content
 * still emitted), terminal 404 -> non-retryable Error, and network -> retryable Error.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class OrderDetailViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun shipping() = PurchaseShipping(carrier = "ups", trackingNumber = "1Z999")

    private fun shipment() = Shipment(
        carrier = Carrier("ups", "UPS"),
        trackingNumber = "1Z999",
        trackingUrl = "https://ups.com",
        status = ShipmentStatus.IN_TRANSIT,
        statusDescription = null,
        estimatedDeliveryEpochMs = null,
        deliveredAtEpochMs = null,
        events = emptyList(),
    )

    private fun vm(
        purchases: FakePurchasesRepository,
        cart: CartRepository = FakeCartRepository(),
        tracking: TrackingRepository = FakeTrackingRepository(),
        txnId: String = "txn_1",
    ) = OrderDetailViewModel(
        purchasesRepository = purchases,
        cartRepository = cart,
        trackingRepository = tracking,
        entitlementsRepository = FakeOrderEntitlementsRepository(),
        savedState = SavedStateHandle(mapOf(OrderDetailViewModel.ARG_TXN_ID to txnId)),
    )

    @Test
    fun content_withItems_andTracking() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Success(
                FakePurchasesRepository.sampleDetail(shipping = shipping(), cartId = "cart_1"),
            ),
        )
        val cart = FakeCartRepository(
            items = ApiResult.Success(listOf(cartItem("sku1"))),
        )
        val tracking = FakeTrackingRepository(
            ApiResult.Success(CarrierTracking("txn_1", shipment())),
        )
        val model = vm(purchases, cart, tracking)
        advanceUntilIdle()
        val state = model.state.value
        assertTrue(state is OrderDetailUiState.Content)
        state as OrderDetailUiState.Content
        assertEquals(1, state.items.size)
        assertTrue(state.tracking is TrackingUiState.Ready)
    }

    @Test
    fun noShipping_yieldsNotShippedTracking_noTrackingCall() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Success(FakePurchasesRepository.sampleDetail(shipping = null)),
        )
        val tracking = FakeTrackingRepository(ApiResult.Success(CarrierTracking("txn_1", null)))
        val model = vm(purchases, tracking = tracking)
        advanceUntilIdle()
        val state = model.state.value as OrderDetailUiState.Content
        assertEquals(TrackingUiState.NotShipped, state.tracking)
        assertEquals(0, tracking.calls) // tracking GET skipped when there is no shipping
    }

    @Test
    fun shippedByHeader_noLegacyShipping_stillFetchesTracking() = runTest {
        // ECOMX selldash-E3: real seller-ship orders have `shipping = null` on the txn detail; the
        // E1 order-header `fulfillment_status = "shipped"` is the authoritative signal. The gate must
        // GET .../tracking (which aggregates the buyer's ship-group tracking) and render Ready.
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Success(
                FakePurchasesRepository.sampleDetail(shipping = null, fulfillmentStatus = "shipped"),
            ),
        )
        val tracking = FakeTrackingRepository(ApiResult.Success(CarrierTracking("txn_1", shipment())))
        val model = vm(purchases, tracking = tracking)
        advanceUntilIdle()
        val state = model.state.value as OrderDetailUiState.Content
        assertTrue(state.tracking is TrackingUiState.Ready)
        assertEquals(1, tracking.calls) // tracking GET happens off the header status, not legacy shipping
    }

    @Test
    fun trackingFailure_isIsolated_orderStillContent() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Success(FakePurchasesRepository.sampleDetail(shipping = shipping())),
        )
        val tracking = FakeTrackingRepository(ApiResult.NetworkError(RuntimeException("io")))
        val model = vm(purchases, tracking = tracking)
        advanceUntilIdle()
        val state = model.state.value
        assertTrue(state is OrderDetailUiState.Content) // order renders despite tracking failure
        assertTrue((state as OrderDetailUiState.Content).tracking is TrackingUiState.Error)
    }

    @Test
    fun itemsFailure_isIsolated_emptyItems() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Success(
                FakePurchasesRepository.sampleDetail(cartId = "cart_1"),
            ),
        )
        val cart = FakeCartRepository(items = ApiResult.Failure(ApiError(500, "boom")))
        val model = vm(purchases, cart)
        advanceUntilIdle()
        val state = model.state.value as OrderDetailUiState.Content
        assertTrue(state.items.isEmpty())
    }

    @Test
    fun detail404_isNonRetryableError() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.Failure(ApiError(404, "not found")),
        )
        val model = vm(purchases)
        advanceUntilIdle()
        val state = model.state.value
        assertTrue(state is OrderDetailUiState.Error)
        assertEquals(false, (state as OrderDetailUiState.Error).retryable)
    }

    @Test
    fun networkError_isRetryableError() = runTest {
        val purchases = FakePurchasesRepository(
            detailResult = ApiResult.NetworkError(RuntimeException("offline")),
        )
        val model = vm(purchases)
        advanceUntilIdle()
        val state = model.state.value as OrderDetailUiState.Error
        assertTrue(state.retryable)
    }

    @Test
    fun blankTxnId_isNonRetryableError() = runTest {
        val model = vm(FakePurchasesRepository(), txnId = "")
        advanceUntilIdle()
        assertTrue(model.state.value is OrderDetailUiState.Error)
    }

    private fun cartItem(sku: String) = CartItem(
        sku = sku, name = "Item $sku", quantity = 2, unitPriceCents = 1999, lineTotalCents = 3998,
    )
}

/** Cart fake: only itemsForCart is exercised; other members are unsupported. */
private class FakeCartRepository(
    private val items: ApiResult<List<CartItem>> = ApiResult.Success(emptyList()),
) : CartRepository {
    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        throw UnsupportedOperationException()
    override suspend fun loadCart(): ApiResult<FullCart> = throw UnsupportedOperationException()
    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart> =
        throw UnsupportedOperationException()
    override suspend fun removeLine(sku: String): ApiResult<FullCart> =
        throw UnsupportedOperationException()
    override suspend fun clearCart(): ApiResult<OkRespDto> = throw UnsupportedOperationException()
    override suspend fun itemsForCart(cartId: String): ApiResult<List<CartItem>> = items
}

private class FakeTrackingRepository(
    private val result: ApiResult<CarrierTracking> = ApiResult.Success(CarrierTracking("txn_1", null)),
) : TrackingRepository {
    var calls = 0
    override suspend fun tracking(txnId: String): ApiResult<CarrierTracking> {
        calls++
        return result
    }
}


/** ECOMX-43 (B5) — empty entitlements fake for the order-detail tests. */
private class FakeOrderEntitlementsRepository :
    com.testlogon.android.data.entitlements.OrderEntitlementsRepository {
    override suspend fun library() =
        com.testlogon.android.core.model.ApiResult.Success(
            emptyList<com.testlogon.android.data.entitlements.LibraryEntitlement>(),
        )
    override suspend fun libraryForOrder(orderId: String) =
        com.testlogon.android.core.model.ApiResult.Success(
            emptyList<com.testlogon.android.data.entitlements.LibraryEntitlement>(),
        )
}
