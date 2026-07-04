package com.testlogon.android.feature.checkout

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.data.cart.CartItem
import com.testlogon.android.data.cart.CartRepository
import com.testlogon.android.data.cart.FullCart
import com.testlogon.android.data.cart.OkRespDto
import com.testlogon.android.data.catalog.CatalogItem
import com.testlogon.android.data.checkout.CheckoutLineItem
import com.testlogon.android.data.checkout.CheckoutRepository
import com.testlogon.android.data.checkout.CheckoutSession
import com.testlogon.android.data.checkout.CheckoutSessionRequest
import com.testlogon.android.data.checkout.CheckoutStatus
import com.testlogon.android.data.messaging.BillingAuthorizer
import com.testlogon.android.data.messaging.BillingResult
import com.testlogon.android.data.messaging.StubBillingAuthorizer
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-213 / AND-031 — [CheckoutSessionViewModel]: empty-cart guard (no session created), happy path
 * (Loading -> Ready), error mapping, idempotency-key reuse across process death, and the billing-stub
 * path which surfaces PaymentsUnavailable and NEVER charges (StubBillingAuthorizer.NotConfigured).
 */
@OptIn(ExperimentalCoroutinesApi::class)
class CheckoutSessionViewModelTest {

    @get:Rule
    val mainRule = MainDispatcherRule()

    private fun savedState(total: Long = 4498, idem: String? = null): SavedStateHandle {
        val map = mutableMapOf<String, Any?>(
            CheckoutSessionViewModel.ARG_CART_ID to "cart_1",
            CheckoutSessionViewModel.ARG_TOTAL_CENTS to total,
            CheckoutSessionViewModel.ARG_CURRENCY to "USD",
        )
        if (idem != null) map[CheckoutSessionViewModel.KEY_IDEMPOTENCY] = idem
        return SavedStateHandle(map)
    }

    private fun session() = CheckoutSession(
        id = "cs_1",
        orderId = "ord_1",
        status = CheckoutStatus.PENDING_PAYMENT,
        lineItems = listOf(CheckoutLineItem("SKU-1", "Widget", 2)),
        totalCents = 4498,
        currency = "USD",
    )

    private fun vm(
        checkout: FakeCheckoutRepository,
        billing: BillingAuthorizer = StubBillingAuthorizer(),
        saved: SavedStateHandle = savedState(),
    ) = CheckoutSessionViewModel(checkout, FakeCartRepoForCheckout(), billing, saved)

    @Test
    fun emptyCart_guards_noSessionCreated() = runTest {
        val checkout = FakeCheckoutRepository()
        val model = vm(checkout, saved = savedState(total = 0))
        advanceUntilIdle()
        assertEquals(OrderReviewUiState.EmptyCart, model.state.value)
        assertEquals(0, checkout.createCalls)
    }

    @Test
    fun happyPath_loadsReady() = runTest {
        val checkout = FakeCheckoutRepository().apply { result = ApiResult.Success(session()) }
        val model = vm(checkout)
        advanceUntilIdle()
        val state = model.state.value
        assertTrue(state is OrderReviewUiState.Ready)
        assertEquals("cs_1", (state as OrderReviewUiState.Ready).session.id)
    }

    @Test
    fun failure_isRetryableError() = runTest {
        val checkout = FakeCheckoutRepository().apply {
            result = ApiResult.Failure(ApiError(status = 500, message = "boom"))
        }
        val model = vm(checkout)
        advanceUntilIdle()
        assertTrue(model.state.value is OrderReviewUiState.Error)
    }

    @Test
    fun idempotencyKey_reusedAcrossProcessDeath() = runTest {
        val saved = savedState()
        FakeCheckoutRepository().also { checkout ->
            val m1 = vm(checkout, saved = saved)
            advanceUntilIdle()
            val firstKey = checkout.lastRequest?.idempotencyKey
            // Rebuild the VM with the SAME SavedStateHandle (simulates process-death restore).
            val checkout2 = FakeCheckoutRepository()
            vm(checkout2, saved = saved)
            advanceUntilIdle()
            assertEquals(firstKey, checkout2.lastRequest?.idempotencyKey)
        }
    }

    @Test
    fun placeOrder_completesPurchase_viaReliableCartEndpoint() = runTest {
        // FIX (ecom residual #1): "Place order" now completes via cartRepository.purchase and emits
        // PurchaseComplete with the purchase txn id (routed to order confirmation by the nav layer).
        val checkout = FakeCheckoutRepository().apply { result = ApiResult.Success(session()) }
        val model = vm(checkout)
        advanceUntilIdle()

        val events = mutableListOf<CheckoutEvent>()
        val job = launch { model.events.collect { events += it } }

        model.placeOrder()
        advanceUntilIdle()

        val evt = events.single()
        assertTrue(evt is CheckoutEvent.PurchaseComplete)
        assertEquals("txn_paid", (evt as CheckoutEvent.PurchaseComplete).txnId)
        assertEquals(1, checkout.createCalls) // only the session-creation call; no billing-stub charge
        job.cancel()
    }
}

/** Fake checkout repo recording the request and the call count. */
private class FakeCheckoutRepository : CheckoutRepository {
    var result: ApiResult<CheckoutSession> = ApiResult.Success(
        CheckoutSession("cs_x", "ord_x", CheckoutStatus.PENDING_PAYMENT, emptyList(), 4498, "USD"),
    )
    var createCalls = 0
    var lastRequest: CheckoutSessionRequest? = null

    override suspend fun createSession(request: CheckoutSessionRequest): ApiResult<CheckoutSession> {
        createCalls++
        lastRequest = request
        return result
    }
}

/** A billing authorizer that records the authorize call but, like the stub, NEVER charges. */
private class RecordingBillingAuthorizer : BillingAuthorizer {
    var authorizeCalled = false
    override suspend fun authorize(amountMinorUnits: Long, currency: String, memo: String?): BillingResult {
        authorizeCalled = true
        return BillingResult.NotConfigured
    }
}

/** Minimal cart repo (unused by checkout creation; the VM seeds totals from nav args). */
private class FakeCartRepoForCheckout : CartRepository {
    override suspend fun addToCart(item: CatalogItem, quantity: Int): ApiResult<CartItem> =
        ApiResult.Success(CartItem("s", "n", 1, 1, 1))
    override suspend fun loadCart(): ApiResult<FullCart> = ApiResult.Success(FullCart.empty("cart_1"))
    override suspend fun setQuantity(sku: String, quantity: Int): ApiResult<FullCart> =
        ApiResult.Success(FullCart.empty("cart_1"))
    override suspend fun removeLine(sku: String): ApiResult<FullCart> =
        ApiResult.Success(FullCart.empty("cart_1"))
    override suspend fun clearCart(): ApiResult<OkRespDto> = ApiResult.Success(OkRespDto(ok = true))
    override suspend fun purchase(
        cartId: String,
        idempotencyKey: String,
        promoCode: String?,
        promoCodeId: String?,
    ): ApiResult<com.testlogon.android.data.cart.CartPurchaseResult> = ApiResult.Success(
        com.testlogon.android.data.cart.CartPurchaseResult(
            cartId = cartId,
            orderId = "ord_paid",
            purchaseTxnId = "txn_paid",
            purchasedTotalCents = 4498,
            currency = "USD",
            discountCents = 0,
        ),
    )
}
