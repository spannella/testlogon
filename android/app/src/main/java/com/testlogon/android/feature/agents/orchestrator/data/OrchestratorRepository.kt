package com.testlogon.android.feature.agents.orchestrator.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.ClaimTicketRequest
import com.testlogon.android.core.network.agents.CompleteTicketRequest
import com.testlogon.android.core.network.agents.OrchestratorApi
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AGENT-ORCHESTRATOR (web-parity) - data layer for the agent-loop ORCHESTRATOR over [OrchestratorApi]. Folds
 * transport into [ApiResult] via [call] (HTTP -> Failure preserving status; malformed JSON -> Failure; transport
 * -> NetworkError; cancellation re-thrown) - matching the AGENTS-BASICS repository fold.
 *
 * DEGRADE-ON-404: [eligibleTickets] and [status] surface a 404 as ApiResult.Success(null) so the console shows
 * "worker not orchestratable / nothing yet" rather than a hard error (the worker may exist in the workers list
 * but have no orchestrator record). All mutations preserve their 4xx (409 busy / already-running etc.) so the
 * ViewModel can message the conflict.
 */
interface OrchestratorRepository {
    /** DEGRADE-ON-404: a 404 (no orchestrator record) becomes Success(null). */
    suspend fun status(workerId: String): ApiResult<AgentStatus?>
    suspend fun start(workerId: String): ApiResult<LoopActionResult>
    suspend fun pause(workerId: String): ApiResult<LoopActionResult>
    suspend fun resume(workerId: String): ApiResult<LoopActionResult>
    suspend fun stop(workerId: String): ApiResult<LoopActionResult>
    suspend fun claim(workerId: String, ticketId: String): ApiResult<Unit>
    suspend fun complete(workerId: String, summary: String?, prUrl: String?): ApiResult<TicketOpResult>
    suspend fun release(workerId: String): ApiResult<TicketOpResult>
    suspend fun heartbeat(workerId: String): ApiResult<HeartbeatResult>
    /** DEGRADE-ON-404: a 404 becomes Success(null). */
    suspend fun eligibleTickets(workerId: String): ApiResult<EligibleTickets?>
    suspend fun updateTicketFilter(workerId: String, filter: TicketFilter): ApiResult<Unit>
}

@Singleton
class DefaultOrchestratorRepository @Inject constructor(
    private val api: OrchestratorApi,
    private val errorParser: ApiErrorParser,
) : OrchestratorRepository {

    override suspend fun status(workerId: String): ApiResult<AgentStatus?> =
        withContext(Dispatchers.IO) { callDegradable { api.status(workerId).toDomain() } }

    override suspend fun start(workerId: String): ApiResult<LoopActionResult> =
        withContext(Dispatchers.IO) { call { api.start(workerId).toDomain() } }

    override suspend fun pause(workerId: String): ApiResult<LoopActionResult> =
        withContext(Dispatchers.IO) { call { api.pause(workerId).toDomain() } }

    override suspend fun resume(workerId: String): ApiResult<LoopActionResult> =
        withContext(Dispatchers.IO) { call { api.resume(workerId).toDomain() } }

    override suspend fun stop(workerId: String): ApiResult<LoopActionResult> =
        withContext(Dispatchers.IO) { call { api.stop(workerId).toDomain() } }

    override suspend fun claim(workerId: String, ticketId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call {
                api.claimTicket(workerId, ClaimTicketRequest(ticketId = ticketId))
                Unit
            }
        }

    override suspend fun complete(
        workerId: String,
        summary: String?,
        prUrl: String?,
    ): ApiResult<TicketOpResult> = withContext(Dispatchers.IO) {
        call {
            api.completeTicket(
                workerId,
                CompleteTicketRequest(
                    summary = summary?.takeIf { it.isNotBlank() },
                    prUrl = prUrl?.takeIf { it.isNotBlank() },
                ),
            ).toDomain()
        }
    }

    override suspend fun release(workerId: String): ApiResult<TicketOpResult> =
        withContext(Dispatchers.IO) { call { api.releaseTicket(workerId).toDomain() } }

    override suspend fun heartbeat(workerId: String): ApiResult<HeartbeatResult> =
        withContext(Dispatchers.IO) { call { api.heartbeat(workerId).toDomain() } }

    override suspend fun eligibleTickets(workerId: String): ApiResult<EligibleTickets?> =
        withContext(Dispatchers.IO) { callDegradable { api.eligibleTickets(workerId).toDomain() } }

    override suspend fun updateTicketFilter(workerId: String, filter: TicketFilter): ApiResult<Unit> =
        withContext(Dispatchers.IO) {
            call {
                api.updateTicketFilter(workerId, filter.toDto())
                Unit
            }
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

    /** Like [call] but a 404 becomes Success(null) (degrade-on-404). */
    private suspend fun <T> callDegradable(block: suspend () -> T): ApiResult<T?> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == 404) ApiResult.Success(null) else ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
