package com.testlogon.android.data.contentcalendar

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
import java.time.Instant

/**
 * AND-274 — MockWebServer contract tests for [ContentCalendarRepositoryImpl]. Verifies verb/path/query,
 * the {items, from_ts, to_ts, count, conflicts} envelope, epoch-seconds mapping + ascending sort, and
 * error propagation. Plain Moshi (the DTO timestamp is a numeric field, no Instant adapter).
 */
class ContentCalendarRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): ContentCalendarRepositoryImpl {
        val retrofit = backend.retrofit(moshi)
        return ContentCalendarRepositoryImpl(
            api = retrofit.create(ContentCalendarApi::class.java),
            errorParser = ApiErrorParser(moshi),
        )
    }

    @Test
    fun list_sendsEpochSecondsAndCsvTypes_decodesEnvelope_sorted() = runTest {
        backend.enqueue(Fixtures.okBody(ENVELOPE_JSON))
        val result = repo().scheduledContent(
            range = ContentDateRange(
                from = Instant.ofEpochSecond(1780723200L),
                to = Instant.ofEpochSecond(1783315200L),
            ),
            filter = ContentFilter(types = setOf(ContentItemType.POST, ContentItemType.BROADCAST)),
        )
        assertTrue(result is ApiResult.Success)
        val items = (result as ApiResult.Success).data
        assertEquals(3, items.size)
        // Sorted ascending by scheduledAt: cnt_4014 (1781367000) < cnt_4012 (1781445600) < cnt_4013.
        assertEquals("cnt_4014", items.first().id)
        assertEquals("cnt_4013", items.last().id)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/content-calendar", req.requestUrl?.encodedPath)
        assertEquals("1780723200", req.requestUrl?.queryParameter("from_ts"))
        assertEquals("1783315200", req.requestUrl?.queryParameter("to_ts"))
        assertEquals("post,broadcast", req.requestUrl?.queryParameter("types"))
    }

    @Test
    fun list_noTypeFilter_omitsTypesParam() = runTest {
        backend.enqueue(Fixtures.okBody("""{"items":[],"from_ts":0,"to_ts":0,"count":0,"conflicts":[]}"""))
        repo().scheduledContent(ContentDateRange(Instant.ofEpochSecond(1L), Instant.ofEpochSecond(2L)))
        val req = backend.takeRequest()
        assertEquals(null, req.requestUrl?.queryParameter("types"))
    }

    @Test
    fun list_401_mapsToFailure_notSwallowed() = runTest {
        backend.enqueue(Fixtures.error("\"unauthorized\"", 401))
        val result = repo().scheduledContent(
            ContentDateRange(Instant.ofEpochSecond(1L), Instant.ofEpochSecond(2L)),
        )
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
    }

    @Test
    fun list_timeout_mapsToNetworkError() = runTest {
        backend.enqueue(Fixtures.timeout())
        val result = repo().scheduledContent(
            ContentDateRange(Instant.ofEpochSecond(1L), Instant.ofEpochSecond(2L)),
        )
        assertTrue(result is ApiResult.NetworkError)
    }

    private companion object {
        const val ENVELOPE_JSON = """
            {"items":[
              {"id":"cnt_4012","type":"post","title":"June newsletter","scheduled_at":1781445600,
               "timezone":"America/New_York","local_time":"10:00 AM","status":"scheduled",
               "color":"#3b82f6","icon":"calendar","has_images":true,"visibility":"subscribers"},
              {"id":"cnt_4013","type":"broadcast","title":"Launch teaser","scheduled_at":1781618400,
               "timezone":null,"local_time":null,"status":"overdue","color":"#ef4444","icon":"video",
               "description":"Go-live teaser","profile_id":"prf_22"},
              {"id":"cnt_4014","type":"vod","title":"Welcome clip","scheduled_at":1781367000,
               "status":"cancelled","color":"#9ca3af","icon":"film","duration_seconds":95,
               "thumbnail_url":"https://cdn.testlogon.dev/c/4014.png"}
            ],"from_ts":1780723200,"to_ts":1783315200,"count":3,"conflicts":[]}
        """
    }
}
