package com.testlogon.android.data.catalog

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
 * AND-206 / AND-209 — contract tests for [CatalogRepositoryImpl.getItem] (list-then-find; there is no
 * single-item GET). Covers: resolve from the first page, resolve across a paged list, client-side
 * not-found (id absent), and transport failure pass-through.
 */
class CatalogGetItemContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): CatalogRepositoryImpl {
        val api = backend.retrofit(moshi).create(CatalogApi::class.java)
        return CatalogRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private fun itemJson(id: String) =
        """{"category_id":"c","item_id":"$id","name":"N-$id","price_cents":1999,"currency":"USD",
            "image_urls":["http://h/$id.png"],"attributes":{},"created_at":"t","updated_at":"t"}"""

    @Test
    fun getItem_resolvesFromFirstPage_andMapsDomain() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[${itemJson("i1")},${itemJson("i2")}],"next_token":null}"""))
        val result = repo().getItem("c", "i2")
        assertTrue(result is ApiResult.Success)
        val item = (result as ApiResult.Success).data
        assertEquals("i2", item.itemId)
        assertEquals(1999L, item.priceCents)
        assertEquals("http://h/i2.png", item.thumbnailUrl)
        assertEquals("/ui/catalog/categories/c/items", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun getItem_walksPages_untilMatch() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[${itemJson("i1")}],"next_token":"t2"}"""))
        backend.enqueue(Fixtures.okBody("""{"items":[${itemJson("i2")}],"next_token":null}"""))
        val result = repo().getItem("c", "i2")
        assertTrue(result is ApiResult.Success)
        assertEquals("i2", (result as ApiResult.Success).data.itemId)
        // Two list GETs were issued (first page + the next_token follow).
        assertEquals("/ui/catalog/categories/c/items", backend.takeRequest().requestUrl?.encodedPath)
        assertEquals("t2", backend.takeRequest().requestUrl?.queryParameter("next_token"))
    }

    @Test
    fun getItem_absentId_isClientSideNotFound() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[${itemJson("i1")}],"next_token":null}"""))
        val result = repo().getItem("c", "missing")
        assertTrue(result is ApiResult.Failure)
        assertEquals(CatalogRepository.STATUS_ITEM_NOT_FOUND, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun getItem_transportFailure_passesThrough() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().getItem("c", "i1")
        assertTrue(result is ApiResult.NetworkError)
    }
}
