package com.testlogon.android.feature.agents.workers.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.CreateWorkerRequest
import com.testlogon.android.core.network.agents.WorkersApi
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
 * AGENTS-BASICS (web-parity) - data layer for the WORKERS surface over [WorkersApi]. Folds transport into
 * [ApiResult] via [call] (HTTP -> Failure preserving status; malformed JSON -> Failure; transport -> NetworkError;
 * cancellation re-thrown). Mirrors the B-APIKEY repository fold. No cache / Room (single small page).
 */
interface WorkersRepository {
    suspend fun list(status: String? = null, agentType: String? = null): ApiResult<List<Worker>>
    suspend fun get(workerId: String): ApiResult<Worker>
    suspend fun create(request: CreateWorkerRequest): ApiResult<Worker>
    suspend fun start(workerId: String): ApiResult<Worker>
    suspend fun stop(workerId: String): ApiResult<Worker>
    suspend fun terminate(workerId: String): ApiResult<Worker>
    suspend fun tools(): ApiResult<List<ToolInfo>>
    suspend fun computeOptions(): ApiResult<List<ComputeOption>>
}

@Singleton
class DefaultWorkersRepository @Inject constructor(
    private val api: WorkersApi,
    private val errorParser: ApiErrorParser,
) : WorkersRepository {

    override suspend fun list(status: String?, agentType: String?): ApiResult<List<Worker>> =
        withContext(Dispatchers.IO) {
            call { api.list(status = status, agentType = agentType).workers.map { it.toDomain() } }
        }

    override suspend fun get(workerId: String): ApiResult<Worker> =
        withContext(Dispatchers.IO) { call { api.get(workerId).toDomain() } }

    override suspend fun create(request: CreateWorkerRequest): ApiResult<Worker> =
        withContext(Dispatchers.IO) { call { api.create(request).toDomain() } }

    override suspend fun start(workerId: String): ApiResult<Worker> =
        withContext(Dispatchers.IO) { call { api.start(workerId).toDomain() } }

    override suspend fun stop(workerId: String): ApiResult<Worker> =
        withContext(Dispatchers.IO) { call { api.stop(workerId).toDomain() } }

    override suspend fun terminate(workerId: String): ApiResult<Worker> =
        withContext(Dispatchers.IO) { call { api.terminate(workerId).toDomain() } }

    override suspend fun tools(): ApiResult<List<ToolInfo>> =
        withContext(Dispatchers.IO) { call { api.tools().tools.map { it.toDomain() } } }

    override suspend fun computeOptions(): ApiResult<List<ComputeOption>> =
        withContext(Dispatchers.IO) { call { api.computeOptions().options.map { it.toDomain() } } }

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
