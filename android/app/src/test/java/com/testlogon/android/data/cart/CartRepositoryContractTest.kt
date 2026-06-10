package com.testlogon.android.data.cart

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.catalog.CatalogItem
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-206 / AND-209 — contract tests for [CartRepositoryImpl.addToCart] (the two-step verified flow:
 * list-or-create a cart, then POST the line item). Covers: create-when-no-active-cart, reuse an existing
 * active cart, create-cart failure short-circuits before the add, add-failure mapping with NO auto-retry,
 * and 422 validation. The catalog item exposes no sku, so item_id is reused as the sku (web parity).
 */
class CartRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CartRepositoryImpl {
        val api = backend.retrofit(moshi).create(CartApi::class.java)
        return CartRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun sampleItem() = CatalogItem(
        itemId = "itm_1",
        categoryId = "cat_books",
        name = "Tee",
        priceCents = 1999,
        currency = "USD",
        imageUrls = listOf("http://h/a.png"),
    )

    private val itemOut =
        """{"sku":"itm_1","name":"Tee","quantity":1,"unit_price_cents":1999,"line_total_cents":1999,
            "updated_at":"t","item_id":"itm_1"}"""

    @Test
    fun addToCart_noActiveCart_createsThenAdds() = runTest {
        backend.enqueue(Fixtures.okBody("""[]"""))                                   // listCarts -> none
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_9","status":"active","created_at":"t","currency":"USD"}""")) // createCart
        backend.enqueue(Fixtures.okBody(itemOut))                                    // addItem

        val result = repo().addToCart(sampleItem(), quantity = 1)
        assertTrue(result is ApiResult.Success)
        assertEquals("itm_1", (result as ApiResult.Success).data.sku)

        assertEquals("/ui/shoppingcart/carts", backend.takeRequest().requestUrl?.encodedPath) // list (GET)
        assertEquals("/ui/shoppingcart/carts", backend.takeRequest().requestUrl?.encodedPath) // create (POST)
        val add = backend.takeRequest()
        assertEquals("/ui/shoppingcart/carts/cart_9/items", add.requestUrl?.encodedPath)
        val body = add.body.readUtf8()
        assertTrue(body.contains("\"sku\":\"itm_1\""))         // sku = item_id
        assertTrue(body.contains("\"unit_price_cents\":1999"))
    }

    @Test
    fun addToCart_reusesActiveCart_skipsCreate() = runTest {
        backend.enqueue(
            Fixtures.okBody("""[{"cart_id":"cart_existing","status":"active","created_at":"t","currency":"USD"}]"""),
        )
        backend.enqueue(Fixtures.okBody(itemOut))

        val result = repo().addToCart(sampleItem(), quantity = 2)
        assertTrue(result is ApiResult.Success)

        assertEquals("/ui/shoppingcart/carts", backend.takeRequest().requestUrl?.encodedPath) // list only
        val add = backend.takeRequest()
        assertEquals("/ui/shoppingcart/carts/cart_existing/items", add.requestUrl?.encodedPath)
        assertTrue(add.body.readUtf8().contains("\"quantity\":2"))
        assertEquals(2, backend.requestCount) // exactly list + add (no create)
    }

    @Test
    fun addToCart_createFailure_shortCircuits_beforeAdd() = runTest {
        backend.enqueue(Fixtures.okBody("""[]"""))            // no active cart
        backend.enqueue(Fixtures.error("\"boom\"", 500))       // createCart -> 500

        val result = repo().addToCart(sampleItem())
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
        assertEquals(2, backend.requestCount) // list + failed create; the add POST never fired
    }

    @Test
    fun addToCart_addFailure_mapped_andNotAutoRetried() = runTest {
        backend.enqueue(
            Fixtures.okBody("""[{"cart_id":"cart_1","status":"active","created_at":"t","currency":"USD"}]"""),
        )
        backend.enqueue(Fixtures.error("\"nope\"", 500))       // addItem -> 500

        val result = repo().addToCart(sampleItem())
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
        assertEquals(2, backend.requestCount) // list + ONE add (never retried)
    }

    @Test
    fun addToCart_422_validation_mapped() = runTest {
        backend.enqueue(
            Fixtures.okBody("""[{"cart_id":"cart_1","status":"active","created_at":"t","currency":"USD"}]"""),
        )
        backend.enqueue(Fixtures.error("""[{"loc":["body","quantity"],"msg":"too many","type":"value_error"}]""", 422))

        val result = repo().addToCart(sampleItem(), quantity = 5000)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
