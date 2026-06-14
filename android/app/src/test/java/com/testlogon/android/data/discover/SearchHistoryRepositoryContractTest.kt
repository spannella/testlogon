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
 * AND-186 / TC-AND-186-07 — contract tests for [SearchHistoryRepositoryImpl] over the server-backed
 * search-history API: list (GET), record-on-success (POST body), delete-by-id (DELETE {item_id}),
 * clear-all (DELETE). De-dup + cap are asserted on the listed result.
 */
class SearchHistoryRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): SearchHistoryRepositoryImpl {
        val api = backend.retrofit(moshi).create(SearchApi::class.java)
        return SearchHistoryRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun recent_listsHistory_dedupesCaseInsensitive_andCaps() = runTest {
        val body = """{"items":[
            {"id":"a","query":"Kotlin","ts":3,"result_count":5},
            {"id":"b","query":"kotlin","ts":2,"result_count":4},
            {"id":"c","query":"compose","ts":1,"result_count":3}
        ]}"""
        backend.enqueue(Fixtures.okBody(body))
        val recent = repo().recent()
        // "Kotlin" wins (most-recent, kept first); the lowercase dup is dropped.
        assertEquals(listOf("Kotlin", "compose"), recent.map { it.query })
        assertEquals("a", recent.first().id)

        val req = backend.takeRequest()
        assertEquals("/ui/search/history", req.requestUrl?.encodedPath)
        assertEquals("20", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun record_postsQueryAndResultCount() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"id":"new-1"}"""))
        repo().record("jane doe", resultCount = 7)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/search/history", req.requestUrl?.encodedPath)
        val sentBody = req.body.readUtf8()
        assertTrue(sentBody.contains("\"query\":\"jane doe\""))
        assertTrue(sentBody.contains("\"result_count\":7"))
    }

    @Test
    fun record_skipsTooShortQuery_noRequest() = runTest {
        repo().record("a", resultCount = 0)
        assertEquals(0, backend.requestCount)
    }

    @Test
    fun remove_deletesByItemId() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))
        val result = repo().remove("item-42")
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/search/history/item-42", req.requestUrl?.encodedPath)
    }

    @Test
    fun clear_deletesAll() = runTest {
        backend.enqueue(Fixtures.okBody("""{"ok":true,"deleted_count":3}"""))
        val result = repo().clear()
        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("DELETE", req.method)
        assertEquals("/ui/search/history", req.requestUrl?.encodedPath)
    }

    @Test
    fun recent_onFailure_returnsEmpty() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        assertTrue(repo().recent().isEmpty())
    }
}
