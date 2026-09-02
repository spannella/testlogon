package com.testlogon.android.feature.agents.prs.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.AgentPrApi
import com.testlogon.android.core.network.agents.AgentWorkCompleteRequest
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
 * AGENTS-BASICS (web-parity) - data layer for the agent-PR surface over [AgentPrApi]. Folds transport into
 * [ApiResult] via [call]. Mirrors the WORKERS repository fold. No cache / Room. [complete] runs the
 * work-completion pipeline (web completeWork) and is excluded from auto-retry by the interceptor.
 */
interface PrsRepository {
    suspend fun list(): ApiResult<List<AgentPr>>
    suspend fun get(prId: String): ApiResult<AgentPr>
    suspend fun complete(workerId: String, ticketId: String): ApiResult<AgentCompletion>
}

@Singleton
class DefaultPrsRepository @Inject constructor(
    private val api: AgentPrApi,
    private val errorParser: ApiErrorParser,
) : PrsRepository {

    override suspend fun list(): ApiResult<List<AgentPr>> =
        withContext(Dispatchers.IO) { call { api.list().prs.map { it.toDomain() } } }

    override suspend fun get(prId: String): ApiResult<AgentPr> =
        withContext(Dispatchers.IO) { call { api.get(prId).toDomain() } }

    override suspend fun complete(workerId: String, ticketId: String): ApiResult<AgentCompletion> =
        withContext(Dispatchers.IO) {
            call { api.complete(workerId, AgentWorkCompleteRequest(ticketId = ticketId)).toDomain() }
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
