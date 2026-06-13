package com.testlogon.android.data.broadcast

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import retrofit2.Response
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-315 — data layer for the host monetization surface: the small tip-config editor + the private-show
 * request -> accept -> active -> end lifecycle.
 *
 * Kept SEPARATE from [BroadcastRepository] / [InputsRepository] / [HostControlRepository] so the shared
 * broadcast fakes are NOT touched. Each call is wrapped in [ApiResult]; the wire DTO is mapped to the domain
 * BEFORE the typed result. CancellationException is re-thrown; HTTP errors fold to Failure (via
 * [ApiErrorParser]); transport failures to NetworkError. POSTs / PATCH are never auto-retried.
 *
 * READ-THROUGH only: tip-config is read via GET session (NO Room SWR cache — the AND-315 ticket defers the
 * cache; there is no DB change / migration). The current tip values come from the SAME [BroadcastSessionDto]
 * the rest of the broadcast domain already decodes (reusing [BroadcastSessionDto.toDomain]).
 *
 * DEFENSIVE conflict handling: accept / end may race a stale poll. On a 404/409 the ViewModel re-reads
 * [getPrivateStatus] to converge (the REST calls are idempotent). The repository surfaces the raw Failure;
 * the convergence policy lives in the ViewModel.
 */
interface BroadcastMonetizationRepository {

    /** GET the session and extract the SMALL tip-config (tip_enabled / tip_min_cents / tip_max_cents). */
    suspend fun getSessionTipConfig(sessionId: String): ApiResult<TipConfig>

    /** PATCH the tip-config (partial); maps the returned full session back to the persisted [TipConfig]. */
    suspend fun saveTipConfig(
        sessionId: String,
        enabled: Boolean?,
        minCents: Long?,
        maxCents: Long?,
    ): ApiResult<TipConfig>

    /** List pending / in-progress private-show requests. */
    suspend fun listPrivateRequests(sessionId: String): ApiResult<List<PrivateShowRequest>>

    /** The host's current private-show status. */
    suspend fun getPrivateStatus(sessionId: String): ApiResult<PrivateStatus>

    /** Accept [requestId] with [behavior] ("pause" | "end" | "continue"); returns the started session. */
    suspend fun acceptPrivateRequest(
        sessionId: String,
        requestId: String,
        behavior: String,
    ): ApiResult<PrivateShowSession>

    /** Decline [requestId] (empty / {ok} body -> success-by-isSuccessful). */
    suspend fun declinePrivateRequest(sessionId: String, requestId: String): ApiResult<Unit>

    /** End the ACTIVE private show keyed by [privateSessionId] (NOT the request id); returns the summary. */
    suspend fun endPrivateSession(
        sessionId: String,
        privateSessionId: String,
    ): ApiResult<PrivateShowSummary>
}

@Singleton
class BroadcastMonetizationRepositoryImpl @Inject constructor(
    private val api: BroadcastMonetizationApi,
    private val broadcastApi: BroadcastApi,
    private val errorParser: ApiErrorParser,
) : BroadcastMonetizationRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getSessionTipConfig(sessionId: String): ApiResult<TipConfig> = withContext(io) {
        call { broadcastApi.getSession(sessionId) }.map { it.toDomain().toTipConfig() }
    }

    override suspend fun saveTipConfig(
        sessionId: String,
        enabled: Boolean?,
        minCents: Long?,
        maxCents: Long?,
    ): ApiResult<TipConfig> = withContext(io) {
        val body = BroadcastTipConfigInDto(
            tipEnabled = enabled,
            tipMinCents = minCents,
            tipMaxCents = maxCents,
        )
        call { api.patchTipConfig(sessionId, body) }.map { it.toDomain().toTipConfig() }
    }

    override suspend fun listPrivateRequests(sessionId: String): ApiResult<List<PrivateShowRequest>> =
        withContext(io) {
            call { api.listPrivateRequests(sessionId) }.map { dto -> dto.requests.map { it.toDomain() } }
        }

    override suspend fun getPrivateStatus(sessionId: String): ApiResult<PrivateStatus> = withContext(io) {
        call { api.getPrivateStatus(sessionId) }.map { it.toDomain() }
    }

    override suspend fun acceptPrivateRequest(
        sessionId: String,
        requestId: String,
        behavior: String,
    ): ApiResult<PrivateShowSession> = withContext(io) {
        val body = PrivateRequestAcceptInDto(behavior = behavior)
        call { api.acceptPrivateRequest(sessionId, requestId, body) }.map { it.toDomain() }
    }

    override suspend fun declinePrivateRequest(
        sessionId: String,
        requestId: String,
    ): ApiResult<Unit> = withContext(io) {
        call { api.declinePrivateRequest(sessionId, requestId).unitOrThrow() }
    }

    override suspend fun endPrivateSession(
        sessionId: String,
        privateSessionId: String,
    ): ApiResult<PrivateShowSummary> = withContext(io) {
        call { api.endPrivateSession(sessionId, privateSessionId) }.map { it.toDomain() }
    }

    /** Treats any 2xx (incl. an empty body) as success; any other code throws an [HttpException]. */
    private fun Response<Unit>.unitOrThrow() {
        if (!isSuccessful) throw HttpException(this)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
