package com.testlogon.android.data.push

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.test.StandardTestDispatcher
import kotlinx.coroutines.test.TestScope
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Test

/**
 * AND-110 / AND-106+109 — the registrar drives registration off onNewToken and the auth edge, and
 * falls back to the WorkManager job on failure. Uses fakes + a TestScope (no real coroutines/time).
 */
class FcmTokenRegistrarTest {

    private val authState = FakeAuthStateStore()
    private val scheduler = FakePushWorkScheduler()

    private class RecordingRepo(
        var result: ApiResult<Unit> = ApiResult.Success(Unit),
    ) : PushRepository {
        val registerTokens = mutableListOf<String?>()
        override suspend fun registerCurrentToken(forceToken: String?): ApiResult<Unit> {
            registerTokens += forceToken
            return result
        }

        override suspend fun deregisterCurrentToken() = ApiResult.Success(Unit)
        override suspend fun clearLocalPushState() {}
    }

    @Test
    fun onTokenRefreshed_triggers_registration_with_forced_token() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val repo = RecordingRepo()
        val scope = TestScope(dispatcher)
        val registrar = FcmTokenRegistrar(repo, authState, scheduler, scope)

        registrar.onTokenRefreshed("tok_rotated")
        scope.advanceUntilIdle()

        assertEquals(listOf("tok_rotated"), repo.registerTokens)
        assertEquals(0, scheduler.registerCalls)
    }

    @Test
    fun registration_failure_enqueues_worker_fallback() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val repo = RecordingRepo(ApiResult.Failure(ApiError(500, "boom")))
        val scope = TestScope(dispatcher)
        val registrar = FcmTokenRegistrar(repo, authState, scheduler, scope)

        registrar.onTokenRefreshed("tok_rotated")
        scope.advanceUntilIdle()

        assertEquals(1, scheduler.registerCalls)
    }

    @Test
    fun auth_edge_false_to_true_triggers_registration() = runTest {
        val dispatcher = StandardTestDispatcher(testScheduler)
        val repo = RecordingRepo()
        val scope = TestScope(dispatcher)
        val registrar = FcmTokenRegistrar(repo, authState, scheduler, scope)

        registrar.start()
        scope.advanceUntilIdle()
        // No registration on the initial replayed (false) value (drop(1)).
        assertEquals(0, repo.registerTokens.size)

        authState.setAuthenticated("user_1")
        scope.advanceUntilIdle()

        assertEquals(listOf<String?>(null), repo.registerTokens) // forceToken = null on login edge
    }
}
