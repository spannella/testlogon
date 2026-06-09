package com.testlogon.android.data.push

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import com.testlogon.android.data.auth.FakeAuthStateStore
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-110 (FR-1..FR-5) — contract tests for [PushRepositoryImpl] against MockWebServer using real
 * Retrofit/Moshi and the REAL push contract:
 *   POST /ui/push/register {token, platform:"android"} -> PushDevice
 *   POST /ui/push/revoke   {device_id}                 -> OkResp
 * (verified: reference/openapi.index.txt + reference/src/api/types.ts + endpoints/push.ts).
 *
 * Hermetic: no live host, no Firebase. The FCM token is supplied via a fake token provider or the
 * forceToken/pending path.
 */
class PushRepositoryContractTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()
    private val store = FakePushRegistrationStore()
    private val authState = FakeAuthStateStore()

    private fun repo(
        tokenProvider: FakePushTokenProvider = FakePushTokenProvider(),
    ): PushRepositoryImpl {
        val api = backend.retrofit(moshi).create(PushApi::class.java)
        return PushRepositoryImpl(
            api = api,
            tokenProvider = tokenProvider,
            store = store,
            authState = authState,
            errorParser = ApiErrorParser(moshi),
        )
    }

    private fun authenticate(sub: String = "user_1") = runBlocking { authState.setAuthenticated(sub) }

    private val deviceBody =
        """{"device_id":"dev_123","platform":"android","created_at":1733443200,"last_seen_at":1733443200}"""

    @Test
    fun register_success_sends_correct_body_and_persists_tuple_and_device_id() = runTest {
        authenticate()
        backend.enqueue(Fixtures.okBody(deviceBody))

        val result = repo().registerCurrentToken(forceToken = "tok_abc")

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/push/register", req.requestUrl?.encodedPath)
        val body = req.body.readUtf8()
        assertTrue(body.contains("\"token\":\"tok_abc\""))
        assertTrue(body.contains("\"platform\":\"android\""))
        assertTrue("must not send app_version", !body.contains("app_version"))
        assertTrue("must not send device_id in request", !body.contains("device_id"))
        assertEquals("dev_123", store.deviceId)
        assertEquals(
            RegisteredTuple("user_1", "tok_abc", PUSH_CONTRACT_VERSION),
            store.tuple,
        )
    }

    @Test
    fun register_idempotent_noop_when_tuple_unchanged() = runTest {
        authenticate()
        store.tuple = RegisteredTuple("user_1", "tok_abc", PUSH_CONTRACT_VERSION)

        val result = repo().registerCurrentToken(forceToken = "tok_abc")

        assertTrue(result is ApiResult.Success)
        assertEquals("no network call expected", 0, backend.requestCount)
    }

    @Test
    fun register_unauthenticated_caches_pending_and_makes_no_call() = runTest {
        // authState starts unauthenticated.
        val result = repo().registerCurrentToken(forceToken = "tok_new")

        assertTrue(result is ApiResult.Success)
        assertEquals(0, backend.requestCount)
        assertEquals("tok_new", store.pending)
    }

    @Test
    fun register_uses_firebase_token_when_no_forceToken_or_pending() = runTest {
        authenticate()
        backend.enqueue(Fixtures.okBody(deviceBody))

        val result = repo(FakePushTokenProvider()).registerCurrentToken()

        assertTrue(result is ApiResult.Success)
        val body = backend.takeRequest().body.readUtf8()
        assertTrue(body.contains("\"token\":\"fcm-token-from-firebase\""))
    }

    @Test
    fun register_token_fetch_failure_returns_error_no_persist() = runTest {
        authenticate()
        val result = repo(FakePushTokenProvider.failing()).registerCurrentToken()

        assertTrue(result is ApiResult.Failure)
        assertEquals(0, backend.requestCount)
        assertTrue(store.tuple == null)
    }

    @Test
    fun register_422_maps_failure_and_does_not_persist() = runTest {
        authenticate()
        backend.enqueue(
            Fixtures.error(
                """[{"loc":["body","token"],"msg":"field required","type":"value_error.missing"}]""",
                code = 422,
            ),
        )

        val result = repo().registerCurrentToken(forceToken = "tok_abc")

        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertTrue("tuple not persisted on error", store.tuple == null)
    }

    @Test
    fun register_network_error_returns_networkError() = runTest {
        authenticate()
        backend.enqueue(Fixtures.timeout())

        val result = repo().registerCurrentToken(forceToken = "tok_abc")

        assertTrue(result is ApiResult.NetworkError)
        assertTrue(store.tuple == null)
    }

    @Test
    fun deregister_success_sends_device_id_body() = runTest {
        store.deviceId = "dev_123"
        backend.enqueue(Fixtures.okBody("""{"ok":true}"""))

        val result = repo().deregisterCurrentToken()

        assertTrue(result is ApiResult.Success)
        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/ui/push/revoke", req.requestUrl?.encodedPath)
        assertTrue(req.body.readUtf8().contains("\"device_id\":\"dev_123\""))
    }

    @Test
    fun deregister_noop_success_when_no_device_id() = runTest {
        // store.deviceId is null.
        val result = repo().deregisterCurrentToken()

        assertTrue(result is ApiResult.Success)
        assertEquals("no network call when nothing to revoke", 0, backend.requestCount)
    }

    @Test
    fun clearLocalPushState_clears_store() = runTest {
        store.tuple = RegisteredTuple("u", "t", PUSH_CONTRACT_VERSION)
        store.deviceId = "dev_123"

        repo().clearLocalPushState()

        assertEquals(1, store.clearCalls)
        assertTrue(store.tuple == null)
        assertTrue(store.deviceId == null)
    }
}
