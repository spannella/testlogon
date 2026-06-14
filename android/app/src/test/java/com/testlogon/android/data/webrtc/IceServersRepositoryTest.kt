package com.testlogon.android.data.webrtc

import com.squareup.moshi.Moshi
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.testing.net.Fixtures
import com.testlogon.android.core.testing.net.MockBackendRule
import com.testlogon.android.core.testing.net.retrofit
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-291 — tests for the TURN/STUN credential fetch + cache + mapping. Covers the wire contract (POST,
 * path, DTO->domain) via MockWebServer, plus cache/TTL/fallback via an in-process fake API + injected
 * [Clock].
 */
class IceServersRepositoryTest {

    @get:Rule
    val backend = MockBackendRule()

    private val moshi: Moshi = Moshi.Builder().build()

    private var nowMs = 1_000_000L
    private val clock = Clock { nowMs }

    private fun mwsRepo() = DefaultIceServersRepository(
        api = backend.retrofit(moshi).create(IceServersApi::class.java),
        errorParser = ApiErrorParser(moshi),
        clock = clock,
        config = TurnFetchConfig(),
    )

    // ── A fake API so cache/TTL tests don't depend on MockWebServer enqueue ordering. ──
    private class FakeIceServersApi(
        var dto: TurnCredentialsDto,
        var throwOnCall: Boolean = false,
    ) : IceServersApi {
        var calls = 0
        override suspend fun getTurnCredentials(callId: String): TurnCredentialsDto {
            calls++
            if (throwOnCall) throw java.io.IOException("offline")
            return dto
        }
    }

    private fun fakeRepo(
        api: FakeIceServersApi,
        config: TurnFetchConfig = TurnFetchConfig(),
    ) = DefaultIceServersRepository(
        api = api,
        errorParser = ApiErrorParser(moshi),
        clock = clock,
        config = config,
    )

    private fun sampleDto(expiresAtSec: Long, ttlSec: Long = 600) = TurnCredentialsDto(
        iceServers = listOf(
            TurnIceServerDto(
                urls = listOf(
                    "turn:turn.testlogon.example:3478?transport=udp",
                    "turn:turn.testlogon.example:3478?transport=tcp",
                    "turns:turn.testlogon.example:5349?transport=tcp",
                ),
                username = "1717603200:tl",
                credential = "secret==",
            ),
        ),
        ttlSeconds = ttlSec,
        expiresAtEpochSeconds = expiresAtSec,
    )

    @Test
    fun getTurnCredentials_postsEmptyBody_mapsAllFields() = runTest {
        backend.enqueue(
            Fixtures.okBody(
                """{"ttl_seconds":600,"expires_at":1717603800,"ice_servers":[
                    {"urls":["turn:h:3478?transport=udp","turn:h:3478?transport=tcp"],
                     "username":"u","credential":"c"}]}""",
            ),
        )
        val result = mwsRepo().getIceServers("call-123")
        assertTrue(result is ApiResult.Success)
        val servers = (result as ApiResult.Success).data
        assertEquals(600L, servers.ttlSeconds)
        assertEquals(1_717_603_800L * 1_000L, servers.expiresAtEpochMs)
        val entry = servers.servers.single()
        assertEquals(2, entry.urls.size)
        assertEquals("u", entry.username)
        assertEquals("c", entry.credential)

        val req = backend.takeRequest()
        assertEquals("POST", req.method)
        assertEquals("/messaging/messages/calls/call-123/turn-credentials", req.requestUrl?.encodedPath)
    }

    @Test
    fun freshCache_isReused_withoutSecondNetworkCall() = runTest {
        // expires far in the future so it stays fresh.
        val api = FakeIceServersApi(sampleDto(expiresAtSec = (nowMs / 1000) + 10_000))
        val repo = fakeRepo(api)

        val first = repo.getIceServers("call-1")
        assertTrue(first is ApiResult.Success)
        val second = repo.getIceServers("call-1")
        assertTrue(second is ApiResult.Success)

        assertEquals(1, api.calls) // cached on the second read
    }

    @Test
    fun staleCacheWithinSkew_triggersRefetch() = runTest {
        val skew = TurnFetchConfig().refreshSkewSeconds
        // expires only 'skew - 1' seconds out => within the skew window => not fresh.
        val nearExpirySec = (nowMs / 1000) + (skew - 1)
        val api = FakeIceServersApi(sampleDto(expiresAtSec = nearExpirySec))
        val repo = fakeRepo(api)

        repo.getIceServers("call-1")
        repo.getIceServers("call-1")
        assertEquals(2, api.calls) // refetched because cache was within the skew window
    }

    @Test
    fun networkFailure_withValidCache_returnsStaleCache() = runTest {
        val api = FakeIceServersApi(sampleDto(expiresAtSec = (nowMs / 1000) + 10_000))
        val repo = fakeRepo(api)

        val first = repo.getIceServers("call-1", forceRefresh = true)
        assertTrue(first is ApiResult.Success)

        // Now make the network fail and force a refresh; the still-valid cache should be served.
        api.throwOnCall = true
        val second = repo.getIceServers("call-1", forceRefresh = true)
        assertTrue(second is ApiResult.Success)
        assertEquals(
            (first as ApiResult.Success).data.expiresAtEpochMs,
            (second as ApiResult.Success).data.expiresAtEpochMs,
        )
    }

    @Test
    fun networkFailure_noCache_returnsFailure() = runTest {
        val api = FakeIceServersApi(sampleDto(expiresAtSec = 0), throwOnCall = true)
        val repo = fakeRepo(api)
        val result = repo.getIceServers("call-1")
        assertTrue(result is ApiResult.NetworkError)
    }

    @Test
    fun provider_onFailure_returnsStunFallback_neverThrows() = runTest {
        val api = FakeIceServersApi(sampleDto(expiresAtSec = 0), throwOnCall = true)
        val config = TurnFetchConfig()
        val provider = DefaultIceServersProvider(fakeRepo(api, config), config)
        val servers = provider.current("call-1")
        assertEquals(config.stunOnlyFallback, servers)
    }

    @Test
    fun provider_onSuccess_returnsServers() = runTest {
        val api = FakeIceServersApi(sampleDto(expiresAtSec = (nowMs / 1000) + 10_000))
        val config = TurnFetchConfig()
        val provider = DefaultIceServersProvider(fakeRepo(api, config), config)
        val servers = provider.current("call-1")
        assertEquals(1, servers.size)
        assertEquals("secret==", servers.single().credential)
    }
}
