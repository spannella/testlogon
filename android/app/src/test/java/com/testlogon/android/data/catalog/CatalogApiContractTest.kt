package com.testlogon.android.data.catalog

import com.squareup.moshi.Moshi
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.squareup.moshi.JsonDataException
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import retrofit2.HttpException

/**
 * AND-204 — contract tests for [CatalogApi] against MockWebServer with the production-style Moshi
 * converter. Verifies verb/path/query for all three endpoints, token-paging params, null-token
 * omission, snake_case decoding, money fidelity (Long), required-field fail-fast, unknown-key
 * tolerance, free-form attributes, and 422 propagation as HttpException.
 */
class CatalogApiContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun api(): CatalogApi = backend.retrofit(moshi).create(CatalogApi::class.java)

    @Test
    fun listCategories_path_query_decode() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"cat_apparel","name":"Apparel","description":"Shirts","creator_id":"usr_1","created_at":"2026-01-02T10:00:00Z"}
                ],"next_token":"tok_2"}""",
            ),
        )
        val page = api().listCategories(pageSize = 50)
        assertEquals("cat_apparel", page.items.single().categoryId)
        assertEquals("Apparel", page.items.single().name)
        assertEquals("tok_2", page.nextToken)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/catalog/categories", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("page_size"))
    }

    @Test
    fun listItems_path_query_money_lastPage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"cat_apparel","item_id":"itm_001","name":"Logo Tee","price_cents":1999,"currency":"USD",
                    "image_urls":["http://h/1.png","http://h/2.png"],"attributes":{"color":"black"},
                    "stock_count":12,"stock_status":"in_stock","low_stock_threshold":5,"position":0,
                    "created_at":"2026-01-02T10:00:00Z","updated_at":"2026-05-01T00:00:00Z"}
                ],"next_token":null}""",
            ),
        )
        val page = api().listItems("cat_apparel", pageSize = 10, nextToken = "abc")
        val item = page.items.single()
        assertEquals(1999L, item.priceCents)
        assertEquals("USD", item.currency)
        assertEquals(2, item.imageUrls.size)
        assertEquals("black", item.attributes["color"])
        assertNull(page.nextToken)
        val req = backend.takeRequest()
        assertEquals("/ui/catalog/categories/cat_apparel/items", req.requestUrl?.encodedPath)
        assertEquals("10", req.requestUrl?.queryParameter("page_size"))
        assertEquals("abc", req.requestUrl?.queryParameter("next_token"))
    }

    @Test
    fun listCategories_nullToken_isOmitted() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[]}"""))
        api().listCategories(pageSize = 50, nextToken = null)
        val req = backend.takeRequest()
        assertNull(req.requestUrl?.queryParameter("next_token"))
        assertEquals("/ui/catalog/categories", req.requestUrl?.encodedPath)
    }

    @Test
    fun searchCatalog_encodesQuery_sameEnvelope() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"c","item_id":"itm_1","name":"Tee","price_cents":500,"currency":"USD",
                    "image_urls":[],"attributes":{},"created_at":"2026-01-02T10:00:00Z","updated_at":"2026-01-02T10:00:00Z"}
                ],"next_token":null}""",
            ),
        )
        val page = api().searchCatalog(query = "tee & hats", pageSize = 50)
        assertEquals("itm_1", page.items.single().itemId)
        val req = backend.takeRequest()
        assertEquals("/ui/catalog/items/search", req.requestUrl?.encodedPath)
        assertEquals("tee & hats", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun missingRequiredField_throwsJsonDataException() {
        // item_id omitted on a required field -> fail fast.
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"c","name":"NoId","price_cents":1,"currency":"USD",
                    "image_urls":[],"attributes":{},"created_at":"t","updated_at":"t"}
                ]}""",
            ),
        )
        assertThrows(JsonDataException::class.java) {
            runBlocking { api().listItems("c") }
        }
    }

    @Test
    fun unknownKeys_and_defaults_tolerated() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"c","item_id":"itm_1","name":"Tee","price_cents":1,"currency":"USD",
                    "created_at":"t","updated_at":"t","server_time":"now","experimental_flag":true}
                ]}""",
            ),
        )
        val page = api().listItems("c")
        val item = page.items.single()
        assertTrue(item.imageUrls.isEmpty()) // default
        assertTrue(item.attributes.isEmpty()) // default
        assertEquals("unlimited", item.stockStatus) // default
        assertEquals(5, item.lowStockThreshold) // default
        assertNull(page.nextToken)
    }

    @Test
    fun mixedTypeAttributes_preserved() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"c","item_id":"itm_1","name":"Tee","price_cents":1,"currency":"USD",
                    "image_urls":[],"attributes":{"color":"black","featured":true,"rank":3},
                    "created_at":"t","updated_at":"t"}
                ]}""",
            ),
        )
        val attrs = api().listItems("c").items.single().attributes
        assertEquals("black", attrs["color"])
        assertEquals(true, attrs["featured"])
        // JSON numbers decode to Double via Moshi's default Any binding.
        assertEquals(3.0, attrs["rank"])
    }

    @Test
    fun error_422_propagatesAsHttpException() {
        backend.enqueue(Fixtures.error("""[{"loc":["query","q"],"msg":"field required","type":"missing"}]""", 422))
        val ex = assertThrows(HttpException::class.java) {
            runBlocking { api().searchCatalog("") }
        }
        assertEquals(422, ex.code())
    }
}
