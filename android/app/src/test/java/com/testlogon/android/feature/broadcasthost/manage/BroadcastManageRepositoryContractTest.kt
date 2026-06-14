package com.testlogon.android.feature.broadcasthost.manage

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-314 — MockWebServer contract tests for [BroadcastManageRepositoryImpl] over [BroadcastManageApi]. Verifies
 * verb + resolved path + request body for goals (list / create / delete) and products (list / add / remove /
 * reorder / set-price / clear-price). Asserts the create body { label, target_cents, sort_order }, the add body
 * { item_id, category_id, display_order }, the reorder body { item_order: [...] } followed by a re-fetch, the
 * set-price body { broadcast_price_cents, expires_in_seconds } + the PriceOut merge, the empty-200 ACK success
 * via Response of Unit, the products decode (incl. broadcast-price fields + discount_pct), and 422 detail
 * mapping. Each request body is read exactly ONCE.
 */
class BroadcastManageRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): BroadcastManageRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return BroadcastManageRepositoryImpl(
            api = retrofit.create(BroadcastManageApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun listGoals_decodesAndOrdersBySortOrder() = runTest {
        backend.enqueue(Fixtures.okBody(GOALS_JSON))
        val result = repo().goals("bcs_1")
        assertTrue(result is ApiResult.Success)
        val goals = (result as ApiResult.Success).data
        assertEquals(2, goals.size)
        // sort_order asc: g2 (0) before g1 (1).
        assertEquals("g2", goals[0].goalId)
        assertEquals("g1", goals[1].goalId)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/goals", req.requestUrl?.encodedPath)
    }

    @Test
    fun createGoal_postsBody_returnsGoal() = runTest {
        backend.enqueue(Fixtures.okBody(GOAL_OUT_JSON))
        val result = repo().createGoal("bcs_1", label = "New car", targetCents = 500_000L, sortOrder = 2)
        assertTrue(result is ApiResult.Success)
        assertEquals("g9", (result as ApiResult.Success).data.goalId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/goals", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("New car", body["label"])
        assertEquals(500000.0, body["target_cents"])
        assertEquals(2.0, body["sort_order"])
    }

    @Test
    fun deleteGoal_ackBody_succeedsViaResponseUnit() = runTest {
        backend.enqueue(Fixtures.okBody("{\"ok\":true,\"goal_id\":\"g1\"}"))
        val result = repo().deleteGoal("bcs_1", "g1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/broadcast/sessions/bcs_1/goals/g1", req.requestUrl?.encodedPath)
    }

    @Test
    fun deleteGoal_empty200_stillSucceeds() = runTest {
        // An EMPTY 200 body must be success (Response of Unit), not a Moshi EOF.
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().deleteGoal("bcs_1", "g1")
        assertTrue(result is ApiResult.Success)
    }

    @Test
    fun listProducts_decodesBroadcastPriceFields() = runTest {
        backend.enqueue(Fixtures.okBody(PRODUCTS_JSON))
        val result = repo().products("bcs_1")
        assertTrue(result is ApiResult.Success)
        val items = (result as ApiResult.Success).data
        assertEquals(1, items.size)
        val item = items[0]
        assertEquals("i1", item.itemId)
        assertTrue(item.isBroadcastPrice)
        assertEquals(20, item.discountPct)
        // effective_price_cents wins over base price_cents.
        assertEquals(800L, item.priceCents)
        assertEquals(1000L, item.catalogPriceCents)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/broadcast/sessions/bcs_1/products", req.requestUrl?.encodedPath)
    }

    @Test
    fun addProduct_postsBody_returnsItem() = runTest {
        backend.enqueue(Fixtures.okBody(PRODUCT_OUT_JSON))
        val result = repo().addProduct("bcs_1", itemId = "i9", categoryId = "c1", displayOrder = 3)
        assertTrue(result is ApiResult.Success)
        assertEquals("i9", (result as ApiResult.Success).data.itemId)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/broadcast/sessions/bcs_1/products", req.requestUrl?.encodedPath)
        val body = req.bodyJson()
        assertEquals("i9", body["item_id"])
        assertEquals("c1", body["category_id"])
        assertEquals(3.0, body["display_order"])
    }

    @Test
    fun removeProduct_sendsDelete_acks() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().removeProduct("bcs_1", "i1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/broadcast/sessions/bcs_1/products/i1", req.requestUrl?.encodedPath)
    }

    @Test
    fun reorder_patchesItemOrder_thenReFetches() = runTest {
        // First the ACK PATCH, then the re-fetch GET (reorder returns only an ack).
        backend.enqueue(Fixtures.okBody("{\"ok\":true}"))
        backend.enqueue(Fixtures.okBody(PRODUCTS_JSON))
        val result = repo().reorder("bcs_1", listOf("i2", "i1"))
        assertTrue(result is ApiResult.Success)
        assertEquals(1, (result as ApiResult.Success).data.size)

        val patch = backend.takeRequest()
        assertEquals("PATCH", patch.method)
        assertEquals("/broadcast/sessions/bcs_1/products/reorder", patch.requestUrl?.encodedPath)
        @Suppress("UNCHECKED_CAST")
        val order = patch.bodyJson()["item_order"] as List<String>
        assertEquals(listOf("i2", "i1"), order)

        val refetch = backend.takeRequest()
        assertEquals("GET", refetch.method)
        assertEquals("/broadcast/sessions/bcs_1/products", refetch.requestUrl?.encodedPath)
    }

    @Test
    fun setPrice_patchesBody_mergesPriceOut() = runTest {
        // The set-price PATCH (PriceOut), then the re-fetch GET that reconciles the item.
        backend.enqueue(Fixtures.okBody(PRICE_OUT_JSON))
        backend.enqueue(Fixtures.okBody(PRODUCTS_JSON))
        val result = repo().setPrice("bcs_1", "i1", cents = 800L, expiresInSeconds = 3600L)
        assertTrue(result is ApiResult.Success)
        val item = (result as ApiResult.Success).data
        assertTrue(item.isBroadcastPrice)
        assertEquals(20, item.discountPct)

        val patch = backend.takeRequest()
        assertEquals("PATCH", patch.method)
        assertEquals("/broadcast/sessions/bcs_1/products/i1/price", patch.requestUrl?.encodedPath)
        val body = patch.bodyJson()
        assertEquals(800.0, body["broadcast_price_cents"])
        assertEquals(3600.0, body["expires_in_seconds"])
    }

    @Test
    fun clearPrice_sendsDelete_acks() = runTest {
        backend.enqueue(Fixtures.okBody(""))
        val result = repo().clearPrice("bcs_1", "i1")
        assertTrue(result is ApiResult.Success)

        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/broadcast/sessions/bcs_1/products/i1/price", req.requestUrl?.encodedPath)
    }

    @Test
    fun createGoal_422_mapsToFailureWithDetail() = runTest {
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","target_cents"],"msg":"ensure this value is greater than or equal to 100","type":"value_error"}]""",
                422,
            ),
        )
        val result = repo().createGoal("bcs_1", label = "x", targetCents = 1L, sortOrder = 0)
        assertTrue(result is ApiResult.Failure)
        val error = (result as ApiResult.Failure).error
        assertEquals(422, error.status)
        assertTrue(error.message.contains("greater than or equal to 100"))
    }

    private companion object {
        const val GOALS_JSON = """
            {"session_id":"bcs_1","goals":[
              {"goal_id":"g1","session_id":"bcs_1","label":"Car","target_cents":500000,
               "current_cents":100000,"reached":false,"sort_order":1,"created_at":1749322800},
              {"goal_id":"g2","session_id":"bcs_1","label":"Mic","target_cents":20000,
               "current_cents":20000,"reached":true,"reached_at":1749322900,"sort_order":0,"created_at":1749322700}
            ]}
        """

        const val GOAL_OUT_JSON = """
            {"goal_id":"g9","session_id":"bcs_1","label":"New car","target_cents":500000,
             "current_cents":0,"reached":false,"sort_order":2,"created_at":1749323000}
        """

        const val PRODUCTS_JSON = """
            {"session_id":"bcs_1","items":[
              {"session_id":"bcs_1","item_id":"i1","category_id":"c1","name":"Hat","price_cents":1000,
               "currency":"USD","display_order":0,"added_by":"u1","added_at":1749322800,
               "effective_price_cents":800,"original_price_cents":1000,"is_broadcast_price":true,
               "broadcast_price_cents":800,"broadcast_price_expires_at":1749326400,"discount_pct":20}
            ],"count":1}
        """

        const val PRODUCT_OUT_JSON = """
            {"session_id":"bcs_1","item_id":"i9","category_id":"c1","name":"Mug","price_cents":1500,
             "currency":"USD","display_order":3,"added_by":"u1","added_at":1749323000,"is_broadcast_price":false}
        """

        const val PRICE_OUT_JSON = """
            {"session_id":"bcs_1","item_id":"i1","original_price_cents":1000,"broadcast_price_cents":800,
             "broadcast_price_expires_at":1749326400,"discount_pct":20,"set_by":"u1","set_at":1749322800}
        """
    }
}
