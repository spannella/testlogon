package com.testlogon.android.data.broadcast.shelf

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-283 — contract tests for [ShelfRepositoryImpl]: GET path, items[] -> domain mapping (item_id->id,
 * effective_price preference, display_order sort), empty list, and 422 -> Failure.
 */
class ShelfRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ShelfRepositoryImpl {
        val api = backend.retrofit(moshi).create(BroadcastShelfApi::class.java)
        return ShelfRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun getProducts_mapsItems_ordersByDisplayOrder_prefersEffectivePrice() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"session_id":"s1","count":2,"items":[
                   {"session_id":"s1","item_id":"i2","category_id":"c1","name":"B","price_cents":4500,
                    "currency":"USD","image_url":"http://h/b.jpg","display_order":1,"added_by":"u",
                    "added_at":1},
                   {"session_id":"s1","item_id":"i1","category_id":"c1","name":"A","price_cents":4500,
                    "currency":"USD","image_url":"http://h/a.jpg","display_order":0,"added_by":"u",
                    "added_at":1,"effective_price_cents":3900,"original_price_cents":4500,
                    "is_broadcast_price":true}
                ]}""",
            ),
        )
        val result = repo().getSessionProducts("s1")
        assertTrue(result is ApiResult.Success)
        val products = (result as ApiResult.Success).data
        assertEquals(listOf("i1", "i2"), products.map { it.itemId })
        // i1 prefers effective_price_cents and carries the strikethrough original.
        assertEquals(3900L, products[0].priceCents)
        assertEquals(4500L, products[0].originalPriceCents)
        // i2 has no broadcast price -> base price, no strikethrough.
        assertEquals(4500L, products[1].priceCents)
        assertNull(products[1].originalPriceCents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/s1/products", req.requestUrl?.encodedPath)
    }

    @Test
    fun getProducts_emptyItems_returnsEmpty() = runTest {
        backend.enqueue(Fixtures.okBody("""{"session_id":"s1","count":0,"items":[]}"""))
        val result = repo().getSessionProducts("s1")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun getProducts_422_mapsFailure() = runTest {
        backend.enqueue(
            Fixtures.error("""[{"loc":["path","session_id"],"msg":"field required","type":"value_error"}]""", 422),
        )
        val result = repo().getSessionProducts("s1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
