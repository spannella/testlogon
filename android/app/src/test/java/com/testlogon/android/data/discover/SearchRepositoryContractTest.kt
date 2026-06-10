package com.testlogon.android.data.discover

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
 * AND-185 — contract tests for [SearchRepositoryImpl]. Verifies path/params (limit clamped to <=20),
 * the keyed-results envelope decoding via [SearchMapper], the LRU cache, and 422 mapping.
 */
class SearchRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SearchRepositoryImpl {
        val api = backend.retrofit(moshi).create(SearchApi::class.java)
        return SearchRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    private val multiBody =
        """{"query":"jane","partial":false,"results":{
           "users":{"total_estimate":8,"has_more":true,"items":[
              {"type":"user","id":"u_123","title":"Jane Doe","snippet":"@jdoe","thumbnail_url":"http://h/a.jpg","url":"/users/u_123"}]},
           "posts":{"total_estimate":4,"has_more":false,"items":[
              {"type":"post","id":"c_987","title":"Jane's stream","snippet":"...","url":"/posts/c_987"}]}
        }}"""

    @Test
    fun search_decodesKeyedSections_andSendsParams() = runTest {
        backend.enqueue(Fixtures.okBody(multiBody))
        val result = repo().search("jane", limit = 10)
        assertTrue(result is ApiResult.Success)
        val data = (result as ApiResult.Success).data
        assertEquals(2, data.categories.size)
        assertEquals(SearchEntityType.USER, data.categories[0].type)
        assertEquals(8, data.categories[0].totalEstimate)
        assertTrue(data.categories[0].hasMore)
        assertEquals("/users/u_123", data.categories[0].items.single().url)
        assertEquals(2, data.totalCount)

        val req = backend.takeRequest()
        assertEquals("/ui/search", req.requestUrl?.encodedPath)
        assertEquals("jane", req.requestUrl?.queryParameter("q"))
        assertEquals("10", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun search_clampsLimitTo20() = runTest {
        backend.enqueue(Fixtures.okBody("""{"query":"x","results":{}}"""))
        repo().search("x", limit = 99)
        assertEquals("20", backend.takeRequest().requestUrl?.queryParameter("limit"))
    }

    @Test
    fun search_emptyResults_mapsToEmptyDomain() = runTest {
        backend.enqueue(Fixtures.okBody("""{"query":"zzzz","results":{}}"""))
        val result = repo().search("zzzz")
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty)
    }

    @Test
    fun search_cachesPerQuery() = runTest {
        backend.enqueue(Fixtures.okBody(multiBody))
        val repo = repo()
        repo.search("jane")
        assertEquals("jane", repo.cached("jane")?.query)
        assertEquals(null, repo.cached("other"))
    }

    @Test
    fun search_422_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("""[{"loc":["query","q"],"msg":"too long","type":"string_too_long"}]""", 422))
        val result = repo().search("x".repeat(3))
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
