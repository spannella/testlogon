package com.testlogon.android.data.disputes

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
 * AND-245 — contract tests for [DisputesRepositoryImpl] against MockWebServer. Covers list ({items} +
 * limit + newest-first sort), detail (path param), file-dispute POST (path + body), and 422 mapping.
 */
class DisputesRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): DisputesRepositoryImpl {
        val api = backend.retrofit(moshi).create(DisputesApi::class.java)
        return DisputesRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun listDisputes_mapsItems_sortsNewestFirst_andSendsLimit() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"items":[
                   {"dispute_id":"old","provider":"stripe","amount_cents":100,"currency":"usd","reason":"a","status":"resolved","evidence_submitted":true,"created_at":1000},
                   {"dispute_id":"new","provider":"stripe","amount_cents":200,"currency":"usd","reason":"b","status":"open","evidence_submitted":false,"created_at":2000}
                ]}""",
            ),
        )
        val result = repo().listDisputes()
        assertTrue(result is ApiResult.Success)
        val list = (result as ApiResult.Success).data
        assertEquals("new", list[0].id)
        assertEquals("old", list[1].id)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/billing/disputes", req.requestUrl?.encodedPath)
        assertEquals("50", req.requestUrl?.queryParameter("limit"))
    }

    @Test
    fun getDispute_usesPathParam() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"dispute_id":"dp_7c1","provider":"stripe","amount_cents":4900,"currency":"usd",
                   "reason":"unauthorized","status":"resolved","evidence_submitted":true,"resolution":"won","created_at":1}""",
            ),
        )
        val result = repo().getDispute("dp_7c1")
        assertTrue(result is ApiResult.Success)
        assertEquals(DisputeStatus.RESOLVED, (result as ApiResult.Success).data.status)
        assertEquals("/ui/billing/disputes/dp_7c1", backend.takeRequest().requestUrl?.encodedPath)
    }

    @Test
    fun fileDispute_postsBody() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"dispute_id":"dp_new","provider":"stripe","amount_cents":4900,"currency":"usd",
                   "reason":"unauthorized charge here","status":"open","evidence_submitted":false,"created_at":1}""",
                code = 201,
            ),
        )
        val result = repo().fileDispute(
            FileDisputeInput("le_1", 4900, null, "unauthorized charge here"),
        )
        assertTrue(result is ApiResult.Success)
        assertEquals("dp_new", (result as ApiResult.Success).data.id)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/billing/disputes", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"amount_cents\":4900"))
    }

    @Test
    fun listDisputes_422_isFailure() = runTest {
        backend.enqueue(Fixtures.error("\"bad\"", 422))
        val result = repo().listDisputes()
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
    }
}
