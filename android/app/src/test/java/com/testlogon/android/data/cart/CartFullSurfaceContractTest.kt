package com.testlogon.android.data.cart

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-210 / AND-211 — contract tests for the FULL cart surface added on top of the AND-206 add seam:
 * loadCart (resolve -> items + total compose), setQuantity (PATCH then re-fetch), removeLine (DELETE
 * then re-fetch), clearCart (DELETE cart). Verifies verbs/paths/bodies, totals math, and no auto-retry.
 */
class CartFullSurfaceContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CartRepositoryImpl {
        val api = backend.retrofit(moshi).create(CartApi::class.java)
        return CartRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private val openCart = """[{"cart_id":"cart_1","status":"OPEN","created_at":"t","currency":"USD"}]"""

    private val itemsBody = """
        {"cart_id":"cart_1","items":[
          {"sku":"SKU-1","name":"Widget","quantity":2,"unit_price_cents":1999,"line_total_cents":3998,
           "updated_at":"t","image_url":"http://h/a.png","category_id":"cat_1","item_id":"itm_1"},
          {"sku":"SKU-2","name":"Gadget","quantity":1,"unit_price_cents":500,"line_total_cents":500,
           "updated_at":"t"}
        ]}
    """.trimIndent()

    private val totalBody = """{"cart_id":"cart_1","total_cents":4498,"currency":"USD"}"""

    @Test
    fun loadCart_resolvesOpenCart_composesItemsAndTotal() = runTest {
        backend.enqueue(Fixtures.okBody(openCart))   // listCarts -> first OPEN
        backend.enqueue(Fixtures.okBody(itemsBody))  // getCartItems
        backend.enqueue(Fixtures.okBody(totalBody))  // getCartTotal

        val result = repo().loadCart()
        assertTrue(result is ApiResult.Success)
        val cart = (result as ApiResult.Success).data
        assertEquals("cart_1", cart.cartId)
        assertEquals(2, cart.items.size)
        assertEquals(3, cart.itemCount)              // 2 + 1 (derived)
        assertEquals(4498L, cart.totalCents)         // authoritative server total
        assertEquals("Widget", cart.items[0].name)
        assertEquals("http://h/a.png", cart.items[0].imageUrl)

        assertEquals("/ui/shoppingcart/carts", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/shoppingcart/carts/cart_1/items", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/shoppingcart/carts/cart_1/total", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun loadCart_noActiveCart_createsCart() = runTest {
        backend.enqueue(Fixtures.okBody("""[]"""))   // no carts
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_new","status":"OPEN","created_at":"t","currency":"USD"}"""))
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_new","items":[]}"""))
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_new","total_cents":0,"currency":"USD"}"""))

        val result = repo().loadCart()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)

        assertEquals("/ui/shoppingcart/carts", backend.takeRequest().requestUrl?.encodedPath) // list
        val create = backend.takeRequest()
        assertEquals("POST", create.method)
        assertEquals("/ui/shoppingcart/carts", create.requestUrl?.encodedPath)
    }

    @Test
    fun loadCart_totalFails_fallsBackToDerivedSubtotal() = runTest {
        backend.enqueue(Fixtures.okBody(openCart))
        backend.enqueue(Fixtures.okBody(itemsBody))
        backend.enqueue(Fixtures.error("\"boom\"", 500)) // total fails

        val result = repo().loadCart()
        assertTrue(result is ApiResult.Success)
        assertEquals(4498L, (result as ApiResult.Success).data.totalCents) // derived 3998 + 500
    }

    @Test
    fun setQuantity_patchesSku_thenReFetches() = runTest {
        // First resolve (cached after this) then load to seed cart id.
        backend.enqueue(Fixtures.okBody(openCart))
        backend.enqueue(Fixtures.okBody(itemsBody))
        backend.enqueue(Fixtures.okBody(totalBody))
        val r = repo()
        r.loadCart()
        repeat(3) { backend.takeRequest() }

        backend.enqueue(Fixtures.okBody("{}"))         // PATCH untyped 200
        backend.enqueue(Fixtures.okBody(itemsBody))    // re-fetch items
        backend.enqueue(Fixtures.okBody(totalBody))    // re-fetch total

        val result = r.setQuantity("SKU-1", 3)
        assertTrue(result is ApiResult.Success)

        val patch = backend.takeRequest()
        assertEquals("PATCH", patch.method)
        assertEquals("/ui/shoppingcart/carts/cart_1/items/SKU-1", patch.requestUrl?.encodedPath)
        assertTrue(patch.body.readUtf8().contains("\"quantity\":3"))
        assertEquals("/ui/shoppingcart/carts/cart_1/items", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("/ui/shoppingcart/carts/cart_1/total", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun setQuantity_patchFails_notRetried() = runTest {
        backend.enqueue(Fixtures.okBody(openCart))
        backend.enqueue(Fixtures.okBody(itemsBody))
        backend.enqueue(Fixtures.okBody(totalBody))
        val r = repo()
        r.loadCart()
        val baseline = backend.requestCount

        backend.enqueue(Fixtures.error("\"nope\"", 500))
        val result = r.setQuantity("SKU-1", 3)
        assertTrue(result is ApiResult.Failure)
        assertEquals(500, (result as ApiResult.Failure).error.status)
        assertEquals(baseline + 1, backend.requestCount) // exactly ONE PATCH, no re-fetch, no retry
    }

    @Test
    fun removeLine_deletesSku_thenReFetches() = runTest {
        backend.enqueue(Fixtures.okBody(openCart))
        backend.enqueue(Fixtures.okBody(itemsBody))
        backend.enqueue(Fixtures.okBody(totalBody))
        val r = repo()
        r.loadCart()
        repeat(3) { backend.takeRequest() }

        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))                          // DELETE item
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_1","items":[]}"""))      // re-fetch items (now empty)
        backend.enqueue(Fixtures.okBody("""{"cart_id":"cart_1","total_cents":0,"currency":"USD"}"""))

        val result = r.removeLine("SKU-1")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)

        val del = backend.takeRequest()
        assertEquals("DELETE", del.method)
        assertEquals("/ui/shoppingcart/carts/cart_1/items/SKU-1", del.requestUrl?.encodedPath)
    }

    @Test
    fun clearCart_deletesCart() = runTest {
        backend.enqueue(Fixtures.okBody(openCart))
        backend.enqueue(Fixtures.okBody(itemsBody))
        backend.enqueue(Fixtures.okBody(totalBody))
        val r = repo()
        r.loadCart()
        repeat(3) { backend.takeRequest() }

        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = r.clearCart()
        assertTrue(result is ApiResult.Success)
        assertEquals(true, (result as ApiResult.Success).data.ok)

        val del = backend.takeRequest()
        assertEquals("DELETE", del.method)
        assertEquals("/ui/shoppingcart/carts/cart_1", del.requestUrl?.encodedPath)
    }
}
