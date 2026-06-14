package com.testlogon.android.data.webrtc

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.data.cache.Clock
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-291 — fetch + cache + TTL logic for TURN/STUN credentials. This is a plain authenticated network
 * read with a REAL backend endpoint, so it is fully implemented + testable (independent of the FLAGGED
 * native-WebRTC engine). The fetched [IceServers] are consumable verbatim as the PeerConnection config's
 * ICE-server list — but since [BroadcastPublisher]/[PeerConnectionController] are stubbed, nothing
 * actually opens a peer with them yet.
 *
 * Caching: an in-memory per-call cache is reused while it has at least `refreshSkewSeconds` of TTL left;
 * concurrent callers coalesce on a [Mutex] so only one network fetch is in flight per refresh. On fetch
 * failure a still-valid cache is returned (stale); else a STUN-only fallback so direct-connectable peers
 * still work. Credentials are never logged (redaction is the caller's contract; this layer never logs
 * username/credential).
 */
interface IceServersRepository {

    /** Returns fresh ICE servers for [callId], refetching if cache is stale/missing. */
    suspend fun getIceServers(callId: String, forceRefresh: Boolean = false): ApiResult<IceServers>
}

/**
 * Thin seam the call/broadcast feature depends on: never throws; always yields a usable list (fresh,
 * cached-valid, or STUN-only fallback).
 */
interface IceServersProvider {
    suspend fun current(callId: String): List<IceServer>
}

/** Tuning for the TURN fetch/cache. [stunOnlyFallback] is used only when no usable cache exists. */
data class TurnFetchConfig(
    val refreshSkewSeconds: Long = 60,
    val defaultTtlSeconds: Long = 600,
    val stunOnlyFallback: List<IceServer> =
        listOf(IceServer(urls = listOf("stun:stun.l.google.com:19302"))),
)

@Singleton
class DefaultIceServersRepository @Inject constructor(
    private val api: IceServersApi,
    private val errorParser: ApiErrorParser,
    private val clock: Clock,
    private val config: TurnFetchConfig,
) : IceServersRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO
    private val mutex = Mutex()

    /** In-memory per-call cache (most-recent set per callId). */
    private val cache = mutableMapOf<String, IceServers>()

    override suspend fun getIceServers(callId: String, forceRefresh: Boolean): ApiResult<IceServers> =
        mutex.withLock {
            val now = clock.now()
            val cached = cache[callId]
            if (!forceRefresh && cached != null && cached.isFreshAt(now, config.refreshSkewSeconds)) {
                return@withLock ApiResult.Success(cached)
            }
            when (val fetched = fetch(callId, now)) {
                is ApiResult.Success -> {
                    cache[callId] = fetched.data
                    fetched
                }
                is ApiResult.Failure, is ApiResult.NetworkError -> {
                    // Stale-while-revalidate: prefer a not-fully-expired cache over a hard failure.
                    val fallback = cache[callId]?.takeIf { now < it.expiresAtEpochMs }
                    if (fallback != null) ApiResult.Success(fallback) else fetched
                }
            }
        }

    private suspend fun fetch(callId: String, nowMs: Long): ApiResult<IceServers> = withContext(io) {
        call { api.getTurnCredentials(callId) }
            .map { it.toDomain(nowMs = nowMs, defaultTtlSec = config.defaultTtlSeconds) }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}

@Singleton
class DefaultIceServersProvider @Inject constructor(
    private val repository: IceServersRepository,
    private val config: TurnFetchConfig,
) : IceServersProvider {

    override suspend fun current(callId: String): List<IceServer> =
        when (val result = repository.getIceServers(callId)) {
            is ApiResult.Success -> result.data.servers
            is ApiResult.Failure, is ApiResult.NetworkError -> config.stunOnlyFallback
        }
}

// ─── DTO -> domain mapping ───────────────────────────────────────────────────────────────────────

internal fun TurnCredentialsDto.toDomain(nowMs: Long, defaultTtlSec: Long): IceServers {
    val ttl = if (ttlSeconds > 0) ttlSeconds else defaultTtlSec
    val expiresMs = if (expiresAtEpochSeconds > 0) {
        expiresAtEpochSeconds * 1_000L
    } else {
        nowMs + ttl * 1_000L
    }
    return IceServers(
        servers = iceServers.map { dto ->
            IceServer(urls = dto.urls, username = dto.username, credential = dto.credential)
        },
        ttlSeconds = ttl,
        expiresAtEpochMs = expiresMs,
        fetchedAtEpochMs = nowMs,
    )
}

/**
 * Redaction-safe summary of an ICE-server set (counts/schemes/ttl only — NEVER username/credential).
 * Provided so any log site can describe the fetched set without leaking secrets (AND-291 §10).
 */
internal fun IceServers.redactedSummary(): String {
    val schemes = servers
        .flatMap { it.urls }
        .mapNotNull { it.substringBefore(':', "").takeIf(String::isNotEmpty) }
    val counts = schemes.groupingBy { it }.eachCount().entries
        .joinToString(",") { "${it.value} ${it.key}" }
    return "ice servers: $counts, ttl=${ttlSeconds}s"
}
