package com.testlogon.android.data.account

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.bodyJson
import com.testlogon.android.core.testing.net.defaultTestClient
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.preferences.AccountStatusRepository
import com.testlogon.android.data.preferences.AccountStatusApi
import com.testlogon.android.data.preferences.AccountStatusRepositoryImpl
import kotlinx.coroutines.test.runTest
import okhttp3.Interceptor
import okhttp3.OkHttpClient
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-387 - contract tests for [DefaultAccountLifecycleRepository] against MockWebServer (TC-AND-387-02, 03,
 * 04, 05, 06, 09, 13). Asserts the REAL CORRECTED wire contract:
 *  - closure/start: NO body, returns {auth_required, challenge_id, required_factors},
 *  - closure/finalize: body {challenge_id} (NOT closure_id), 200 {status:"closed"}, teardown invoked,
 *  - suspend: body {reason} only (NO duration_days), teardown invoked,
 *  - reactivate: empty/omitted body accepted, getMe refreshed,
 *  - X-CSRF-Token present on every mutation; each mutation issued EXACTLY ONCE (no retry),
 *  - 422 detail-list mapping; undocumented 409 bubbles as Failure (the VM reconciles, not the repo).
 */
class AccountLifecycleRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private fun csrfClient(): OkHttpClient {
        val csrf = Interceptor { chain ->
            val req = chain.request()
            val out = if (req.method in MUTATING) {
                req.newBuilder().header("X-CSRF-Token", CSRF).build()
            } else {
                req
            }
            chain.proceed(out)
        }
        return defaultTestClient().newBuilder().addInterceptor(csrf).build()
    }

    private fun repo(
        auth: RecordingAuthRepository = RecordingAuthRepository(),
        client: OkHttpClient = csrfClient(),
    ): DefaultAccountLifecycleRepository {
        val rf = backend.retrofit(moshi, client)
        val statusRepo: AccountStatusRepository =
            AccountStatusRepositoryImpl(rf.create(AccountStatusApi::class.java), ApiErrorParser(moshi))
        return DefaultAccountLifecycleRepository(
            api = rf.create(AccountLifecycleApi::class.java),
            statusRepository = statusRepo,
            authRepository = auth,
            errorParser = ApiErrorParser(moshi),
        )
    }

    // TC-01: status read maps AccountState; GET issued.
    @Test
    fun status_mapsAccountState() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"active","updated_at":1749081600}"""))
        val r = repo().status()
        assertTrue(r is ApiResult.Success)
        val status = (r as ApiResult.Success).data
        assertEquals(AccountState.ACTIVE, status.state)
        assertEquals(1749081600L, status.updatedAtEpochSeconds)
        val req = backend.takeRequest()
        assertEquals("GET", req.method)
        assertEquals("/ui/account/status", req.requestUrl?.encodedPath)
    }

    // TC-03: closure/start has NO body and parses the re-auth challenge.
    @Test
    fun startClosure_noBody_parsesChallenge() = runTest {
        backend.enqueue(
            Fixtures.okBody("""{"auth_required":true,"challenge_id":"ch_re_19","required_factors":["password"]}"""),
        )
        val r = repo().startClosure()
        assertTrue(r is ApiResult.Success)
        val result = (r as ApiResult.Success).data
        assertTrue(result.authRequired)
        assertEquals("ch_re_19", result.challengeId)
        assertEquals(listOf("password"), result.requiredFactors)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/account/closure/start", req.requestUrl?.encodedPath)
        assertEquals(0L, req.bodySize) // no request body
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
    }

    // TC-04: closure/finalize body is {challenge_id}; on 200 teardown is invoked exactly once; sent once.
    @Test
    fun finalizeClosure_postsChallengeId_andTearsDown() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"closed"}"""))
        val auth = RecordingAuthRepository()
        val r = repo(auth).finalizeClosure("ch_re_19")
        assertTrue(r is ApiResult.Success)
        assertEquals(AccountState.CLOSED, (r as ApiResult.Success).data.state)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/account/closure/finalize", req.requestUrl?.encodedPath)
        assertEquals("ch_re_19", req.bodyJson()["challenge_id"])
        assertNull(req.bodyJson()["closure_id"]) // NOT closure_id
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        assertEquals(1, auth.logoutCalls) // AND-032 teardown
        assertEquals(1, backend.requestCount) // exactly one request, no retry
    }

    // TC-02: suspend body is {reason} only (no duration_days); teardown invoked.
    @Test
    fun suspend_postsReasonOnly_andTearsDown() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"suspended","reason":"taking a break"}"""))
        val auth = RecordingAuthRepository()
        val r = repo(auth).suspend("taking a break")
        assertTrue(r is ApiResult.Success)
        assertEquals(AccountState.SUSPENDED, (r as ApiResult.Success).data.state)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/account/suspend", req.requestUrl?.encodedPath)
        assertEquals("taking a break", req.bodyJson()["reason"])
        assertNull(req.bodyJson()["duration_days"]) // no duration_days in the contract
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        assertEquals(1, auth.logoutCalls)
        assertEquals(1, backend.requestCount)
    }

    // TC-05: reactivate accepts an (effectively empty) body; getMe refreshed; CSRF present.
    @Test
    fun reactivate_refreshesGetMe() = runTest {
        backend.enqueue(Fixtures.okBody("""{"status":"active"}"""))
        val auth = RecordingAuthRepository()
        val r = repo(auth).reactivate(null)
        assertTrue(r is ApiResult.Success)
        assertEquals(AccountState.ACTIVE, (r as ApiResult.Success).data.state)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/account/reactivate", req.requestUrl?.encodedPath)
        assertNull(req.bodyJson()["reason"]) // null reason -> omitted/null
        assertEquals(CSRF, req.getHeader("X-CSRF-Token"))
        assertEquals(1, auth.getMeCalls)
        assertEquals(0, auth.logoutCalls) // reactivate never tears down
    }

    // TC-06: a 422 detail-list on finalize -> Failure(mapped message); NO teardown; sent once.
    @Test
    fun finalize_422_detailList_mapsFailure_noTeardown() = runTest {
        backend.enqueue(Fixtures.error("""[{"msg":"challenge_id is required"}]""", code = 422))
        val auth = RecordingAuthRepository()
        val r = repo(auth).finalizeClosure("ch_bad")
        assertTrue(r is ApiResult.Failure)
        assertEquals(422, (r as ApiResult.Failure).error.status)
        assertEquals(0, auth.logoutCalls)
        assertEquals(1, backend.requestCount)
    }

    // TC-08: an undocumented 409 bubbles as Failure from the repo (the VM reconciles); no teardown.
    @Test
    fun suspend_409_bubblesFailure_noTeardown() = runTest {
        backend.enqueue(Fixtures.error("""{"code":"already_suspended"}""", code = 409))
        val auth = RecordingAuthRepository()
        val r = repo(auth).suspend(null)
        assertTrue(r is ApiResult.Failure)
        assertEquals(409, (r as ApiResult.Failure).error.status)
        assertEquals(0, auth.logoutCalls)
    }

    // TC-11: a transport timeout on finalize -> NetworkError; no teardown; one attempt.
    @Test
    fun finalize_timeout_networkError_noRetry() = runTest {
        backend.enqueue(Fixtures.timeout())
        val auth = RecordingAuthRepository()
        val r = repo(auth).finalizeClosure("ch_x")
        assertTrue(r is ApiResult.NetworkError)
        assertEquals(0, auth.logoutCalls)
        assertEquals(1, backend.requestCount)
    }

    private companion object {
        const val CSRF = "csrf-test-token"
        val MUTATING = setOf("POST", "PUT", "PATCH", "DELETE")
    }
}
