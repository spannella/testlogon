package com.testlogon.android.data.catalog

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
 * AND-204 / AND-205 — contract tests for [CatalogRepositoryImpl]: DTO->domain mapping (thumbnail =
 * image_urls.first), token pagination, and error folding (422 -> Failure, transport -> NetworkError).
 */
class CatalogRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CatalogRepositoryImpl {
        val api = backend.retrofit(moshi).create(CatalogApi::class.java)
        return CatalogRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun categories_mapsDomain_followsToken() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"category_id":"c1","name":"Books","created_at":"t"}],"next_token":"t2"}""",
            ),
        )
        val page = (repo().categories() as ApiResult.Success).data
        assertEquals("c1", page.categories.single().categoryId)
        assertEquals("t2", page.nextToken)
        assertEquals("/ui/catalog/categories", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun categoryItems_mapsDomain_thumbnailFromFirstImage() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"category_id":"c","item_id":"i1","name":"Tee","price_cents":1999,"currency":"USD",
                    "image_urls":["http://h/a.png","http://h/b.png"],"attributes":{},
                    "created_at":"t","updated_at":"t"}
                ],"next_token":null}""",
            ),
        )
        val page = (repo().categoryItems("c", cursor = "cur") as ApiResult.Success).data
        val item = page.items.single()
        assertEquals("i1", item.itemId)
        assertEquals(1999L, item.priceCents)
        assertEquals("http://h/a.png", item.thumbnailUrl)
        assertNull(page.nextToken)
        val req = backend.takeRequest()
        assertEquals("/ui/catalog/categories/c/items", req.requestUrl?.encodedPath)
        assertEquals("cur", req.requestUrl?.queryParameter("next_token"))
    }

    @Test
    fun search_path_andQuery() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[{"category_id":"c","item_id":"i","name":"Tee","price_cents":1,"currency":"USD","image_urls":[],"attributes":{},"created_at":"t","updated_at":"t"}],"next_token":null}""",
            ),
        )
        val page = (repo().search(query = "tee", cursor = null) as ApiResult.Success).data
        assertEquals("i", page.items.single().itemId)
        val req = backend.takeRequest()
        assertEquals("/ui/catalog/items/search", req.requestUrl?.encodedPath)
        assertEquals("tee", req.requestUrl?.queryParameter("q"))
    }

    @Test
    fun items_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","q"],"msg":"bad","type":"value_error"}]""", 422))
        val result = repo().categoryItems("c", cursor = null)
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun categories_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().categories()
        assertTrue(result is ApiResult.NetworkError)
    }
}
