package com.testlogon.android.data.preferences

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.AccountState
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

/** AND-083 — account status mapping (epoch seconds, unknown-state fallback, error mapping). */
class AccountStatusRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun repo(): AccountStatusRepositoryImpl {
        val api = backend.retrofit(moshi).create(AccountStatusApi::class.java)
        return AccountStatusRepositoryImpl(api, ApiErrorParser(moshi))
    }

    @Test
    fun getStatus_mapsSuspended_withReasonAndUpdatedAt() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"status":"suspended","reason":"policy review","updated_at":1730557269}"""),
        )
        val result = repo().getStatus()
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertEquals(AccountState.SUSPENDED, status.state)
        assertEquals("policy review", status.reason)
        assertEquals(1730557269L, status.updatedAtEpochSeconds)

        val recorded = backend.takeRequest()
        assertEquals("GET", recorded.method)
        assertEquals("/ui/account/status", recorded.requestUrl?.encodedPath)
    }

    @Test
    fun getStatus_closed_populatesClosedAt() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"closed","closed_at":1751328000}"""))
        val result = repo().getStatus()
        assertTrue(result is ApiResult.Success)
        val status = (result as ApiResult.Success).data
        assertEquals(AccountState.CLOSED, status.state)
        assertEquals(1751328000L, status.closedAtEpochSeconds)
    }

    @Test
    fun getStatus_unknownState_fallsBackToUnknown() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"frozen_pending_review","unexpected":1}"""))
        val result = repo().getStatus()
        assertTrue(result is ApiResult.Success)
        assertEquals(AccountState.UNKNOWN, (result as ApiResult.Success).data.state)
        assertEquals("frozen_pending_review", result.data.rawState)
    }

    @Test
    fun getStatus_httpError_mapsToFailure() = runTest {
        backend.enqueue(Fixtures.error("\"boom\"", 500))
        assertTrue(repo().getStatus() is ApiResult.Failure)
    }
}
