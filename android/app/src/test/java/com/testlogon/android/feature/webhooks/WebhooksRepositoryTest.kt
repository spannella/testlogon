package com.testlogon.android.feature.webhooks

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.webhooks.data.DefaultWebhooksRepository
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksApi
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksApi.Companion.endpointDto
import com.testlogon.android.feature.webhooks.testing.FakeWebhooksApi.Companion.eventTypeDto
import com.testlogon.android.core.network.webhooks.EventTypesDto
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.IOException

/**
 * AND-398 - tests for [DefaultWebhooksRepository]: list maps the BARE ARRAY (no envelope) with the corrected
 * field names + epoch createdAt; create write-throughs the cache + strips the secret from the cached copy but
 * returns it; get prefers the cached entry; offline (NetworkError) falls back to the cached snapshot; a 401
 * surfaces as Failure(status=401); event-types unwraps the named envelope. Recording fakes record the @Path /
 * @Body BEFORE throwing.
 */
class WebhooksRepositoryTest {

    private fun repo(api: FakeWebhooksApi) = DefaultWebhooksRepository(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun list_mapsBareArray_correctedFields_andEpochCreatedAt() = runTest {
        val api = FakeWebhooksApi(
            list = {
                listOf(
                    endpointDto(
                        id = "wh_1",
                        url = "https://a.test/h",
                        eventTypes = listOf("session.finalized", "mfa.verified"),
                        enabled = false,
                        createdAt = 1_747_072_651L,
                    ),
                    endpointDto(id = "wh_2"),
                )
            },
        )
        val result = repo(api).list(forceRefresh = true)

        assertTrue(result is ApiResult.Success)
        val items = (result as ApiResult.Success).data
        assertEquals(listOf("wh_1", "wh_2"), items.map { it.id })
        assertEquals(listOf("session.finalized", "mfa.verified"), items.first().events)
        assertFalse(items.first().enabled)
        assertEquals(1_747_072_651L, items.first().createdAt)
        assertEquals(1, api.listCallCount)
    }

    @Test
    fun list_401_isFailureWithStatus401() = runTest {
        val api = FakeWebhooksApi(list = { throw FakeWebhooksApi.httpWebhookError(401) })
        val result = repo(api).list(forceRefresh = true)
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        assertEquals(1, api.listCallCount) // recorded BEFORE throwing
    }

    @Test
    fun list_offlineWithPopulatedCache_fallsBackToStaleSnapshot() = runTest {
        val api = FakeWebhooksApi(list = { listOf(endpointDto("wh_1")) })
        val r = repo(api)
        // First list populates the in-memory cache.
        assertTrue(r.list(forceRefresh = true) is ApiResult.Success)
        // Now the network drops -> fall back to the cached snapshot.
        api.list = { throw IOException("connection dropped") }
        val result = r.list(forceRefresh = true)
        assertTrue(result is ApiResult.Success)
        assertEquals(listOf("wh_1"), (result as ApiResult.Success).data.map { it.id })
    }

    @Test
    fun list_offlineWithEmptyCache_isNetworkError() = runTest {
        val api = FakeWebhooksApi(list = { throw IOException("offline") })
        val result = repo(api).list(forceRefresh = true)
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun create_writesThroughCache_returnsSecret_butCachesSecretLess() = runTest {
        val api = FakeWebhooksApi(
            create = { endpointDto(id = "wh_new", secret = "whsec_abc") },
        )
        val r = repo(api)
        val result = r.create("https://new.test/h", listOf("session.finalized"))

        assertTrue(result is ApiResult.Success)
        // Caller receives the one-time secret.
        assertEquals("whsec_abc", (result as ApiResult.Success).data.secret)
        // POST body recorded with the corrected wire fields.
        val body = api.createBodies.single()
        assertEquals("https://new.test/h", body.url)
        assertEquals(listOf("session.finalized"), body.eventTypes)

        // get() now serves the write-through entry FROM CACHE (no network get) and the secret is stripped.
        val got = r.get("wh_new")
        assertTrue(got is ApiResult.Success)
        assertEquals("wh_new", (got as ApiResult.Success).data.id)
        assertNull(got.data.secret)
        assertTrue(got.data.secretSet) // secretSet was derived true at map time
        assertTrue(api.getIds.isEmpty()) // served from cache, network get never called
    }

    @Test
    fun get_uncached_fetchesFromNetwork() = runTest {
        val api = FakeWebhooksApi(get = { endpointDto("wh_x") })
        val result = repo(api).get("wh_x")
        assertTrue(result is ApiResult.Success)
        assertEquals("wh_x", (result as ApiResult.Success).data.id)
        assertEquals("wh_x", api.getIds.single())
    }

    @Test
    fun eventTypes_unwrapsNamedEnvelope() = runTest {
        val api = FakeWebhooksApi(
            eventTypes = {
                EventTypesDto(
                    eventTypes = listOf(
                        eventTypeDto("session.finalized"),
                        eventTypeDto("mfa.verified"),
                    ),
                )
            },
        )
        val result = repo(api).eventTypes()
        assertTrue(result is ApiResult.Success)
        assertEquals(
            listOf("session.finalized", "mfa.verified"),
            (result as ApiResult.Success).data.map { it.type },
        )
        assertEquals(1, api.eventTypesCallCount)
    }
}
