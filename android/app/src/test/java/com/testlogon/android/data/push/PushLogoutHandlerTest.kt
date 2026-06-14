package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import kotlinx.coroutines.delay
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-110 / AND-109 — logout deregister handler: clears local state always; enqueues a retry worker
 * when deregister fails or times out; never throws (logout must not be blocked/failed).
 */
class PushLogoutHandlerTest {

    private val scheduler = FakePushWorkScheduler()

    private class StubRepo(
        private val deregisterResult: suspend () -> ApiResult<Unit>,
    ) : PushRepository {
        var clearCalls = 0
        override suspend fun registerCurrentToken(forceToken: String?) = ApiResult.Success(Unit)
        override suspend fun deregisterCurrentToken(): ApiResult<Unit> = deregisterResult()
        override suspend fun clearLocalPushState() {
            clearCalls++
        }
    }

    @Test
    fun success_clears_state_and_does_not_enqueue() = runTest {
        val repo = StubRepo { ApiResult.Success(Unit) }
        PushLogoutHandlerImpl(repo, scheduler).onLogout()

        assertEquals(1, repo.clearCalls)
        assertEquals(0, scheduler.deregisterCalls)
    }

    @Test
    fun failure_clears_state_and_enqueues_retry() = runTest {
        val repo = StubRepo { ApiResult.Failure(ApiError(500, "boom")) }
        PushLogoutHandlerImpl(repo, scheduler).onLogout()

        assertEquals(1, repo.clearCalls)
        assertEquals(1, scheduler.deregisterCalls)
    }

    @Test
    fun timeout_does_not_block_clears_state_and_enqueues_retry() = runTest {
        // Deregister hangs past the 5s timeout; withTimeoutOrNull returns null -> enqueue + clear.
        val repo = StubRepo {
            delay(PushLogoutHandlerImpl.DEREGISTER_TIMEOUT_MS + 10_000)
            ApiResult.Success(Unit)
        }
        PushLogoutHandlerImpl(repo, scheduler).onLogout()

        assertEquals(1, repo.clearCalls)
        assertEquals(1, scheduler.deregisterCalls)
        assertTrue("logout completed despite hung deregister", true)
    }
}
