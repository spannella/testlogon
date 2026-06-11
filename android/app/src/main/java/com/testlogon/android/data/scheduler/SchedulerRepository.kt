package com.testlogon.android.data.scheduler

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-275 — data layer over [SchedulerApi].
 *
 * Wraps each call in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError for
 * transport, Failure(parse) for malformed JSON). Maps DTOs to domain before returning. The single-action
 * GET (loadAction) and list are idempotent; create/reschedule/cancel mutations are never auto-retried by
 * this layer. CancellationException is re-thrown.
 */
interface SchedulerRepository {

    suspend fun listActions(
        types: String? = null,
        status: String? = null,
    ): ApiResult<List<ScheduledAction>>

    suspend fun loadAction(actionId: String): ApiResult<ScheduledAction>

    suspend fun create(request: ScheduledActionCreateInDto): ApiResult<ScheduledAction>

    suspend fun reschedule(
        actionId: String,
        request: ScheduledActionUpdateInDto,
    ): ApiResult<ScheduledAction>

    suspend fun cancel(actionId: String): ApiResult<Unit>
}

@Singleton
class SchedulerRepositoryImpl @Inject constructor(
    private val api: SchedulerApi,
    private val errorParser: ApiErrorParser,
) : SchedulerRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listActions(
        types: String?,
        status: String?,
    ): ApiResult<List<ScheduledAction>> = withContext(io) {
        call { api.listActions(types, status) }
            .map { resp -> resp.actions.map { it.toDomain() }.sortedBy { it.scheduledAt } }
    }

    override suspend fun loadAction(actionId: String): ApiResult<ScheduledAction> = withContext(io) {
        call { api.getAction(actionId) }.map { it.toDomain() }
    }

    override suspend fun create(request: ScheduledActionCreateInDto): ApiResult<ScheduledAction> =
        withContext(io) {
            call { api.createAction(request) }.map { it.toDomain() }
        }

    override suspend fun reschedule(
        actionId: String,
        request: ScheduledActionUpdateInDto,
    ): ApiResult<ScheduledAction> = withContext(io) {
        call { api.updateAction(actionId, request) }.map { it.toDomain() }
    }

    override suspend fun cancel(actionId: String): ApiResult<Unit> = withContext(io) {
        call { api.cancelAction(actionId) }.map { }
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
