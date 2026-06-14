package com.testlogon.android.data.messaging.legalhold

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
 * AND-164 — contract tests for [LegalHoldRepositoryImpl] against MockWebServer, asserting the REAL wire
 * contract verified from reference/openapi.pretty.json (LegalHoldOut) + openapi.index.txt (line 329):
 * GET path + default status=active query, bare LegalHoldOut[] parse with epoch created_at, tolerant
 * parse of unknown extra fields, active-only filtering, and the MessageControlsErrorOut error path.
 */
class LegalHoldRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): LegalHoldRepositoryImpl {
        val api = backend.retrofit(moshi).create(LegalHoldApi::class.java)
        return LegalHoldRepositoryImpl(api = api, errorParser = ApiErrorParser(moshi))
    }

    @Test
    fun loadActiveHolds_getsCorrectPath_andQuery_andParsesEpoch() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [{"hold_id":"lh_1","tenant_id":"t","conversation_id":"conv_1","message_id":null,
                  "case_id":"CASE-4471","report_id":null,"reason":"matter 4471","status":"active",
                  "created_at":1740926700,"created_by_user_id":"usr_admin","extra_unknown":"ignored"}]
                """.trimIndent(),
            ),
        )
        val r = repo().loadActiveHolds("conv_1")
        assertTrue(r is ApiResult.Success)
        val holds = (r as ApiResult.Success).data
        assertEquals(1, holds.size)
        assertEquals(1740926700L, holds.single().createdAtEpochSeconds)
        assertEquals(HoldSource.CONVERSATION, holds.single().source)

        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/messaging/conversations/conv_1/legal-holds", req.requestUrl?.encodedPath)
        assertEquals("active", req.requestUrl?.queryParameter("status"))
    }

    @Test
    fun loadActiveHolds_filtersOutReleased() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [{"hold_id":"a","tenant_id":"t","conversation_id":"conv_1","case_id":"C","reason":"r",
                  "status":"released","created_at":1,"created_by_user_id":"u"},
                 {"hold_id":"b","tenant_id":"t","conversation_id":"conv_1","case_id":"C","reason":"r",
                  "status":"active","created_at":2,"created_by_user_id":"u"}]
                """.trimIndent(),
            ),
        )
        val r = repo().loadActiveHolds("conv_1")
        assertEquals(listOf("b"), (r as ApiResult.Success).data.map { it.holdId })
    }

    @Test
    fun conversationHold_resolvesConversationLevelOnly() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """
                [{"hold_id":"msg","tenant_id":"t","conversation_id":"conv_1","message_id":"m9",
                  "case_id":"C","reason":"r","status":"active","created_at":1,"created_by_user_id":"u"}]
                """.trimIndent(),
            ),
        )
        // Only a message-scoped hold exists => the conversation itself is NOT held.
        assertNull((repo().conversationHold("conv_1") as ApiResult.Success).data)
    }

    @Test
    fun emptyList_isNotHeld() = runTest {
        backend.enqueue(Fixtures.okBody("[]"))
        assertTrue((repo().loadActiveHolds("conv_1") as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun notFound404_messageControlsError_isFailure() = runTest {
        // Fixtures.error wraps the detail value in {"detail": ...}; pass a JSON string literal.
        backend.enqueue(Fixtures.error("\"not found\"", 404))
        val r = repo().loadActiveHolds("conv_1")
        assertTrue(r is ApiResult.Failure)
        assertEquals(404, (r as ApiResult.Failure).error.status)
    }

    @Test
    fun disconnect_isNetworkError() = runTest {
        backend.enqueue(Fixtures.disconnect())
        assertTrue(repo().loadActiveHolds("conv_1") is ApiResult.NetworkError)
    }
}
