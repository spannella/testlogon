package com.testlogon.android.feature.agents.fleet.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.FleetApi
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
 * AGENTS-BASICS (web-parity) - data layer for the FLEET dashboard over [FleetApi]. [status]/[capacity]/[templates]
 * are idempotent GETs; the bulk actions + template delete/create-from are NON-idempotent (no auto-retry). Same
 * [call] fold as the other agents-basics repositories.
 */
interface FleetRepository {
    suspend fun status(): ApiResult<FleetStatus>
    suspend fun capacity(): ApiResult<FleetCapacity>
    suspend fun startAll(): ApiResult<BulkActionResult>
    suspend fun stopAll(): ApiResult<BulkActionResult>
    suspend fun templates(): ApiResult<List<WorkerTemplate>>
    suspend fun deleteTemplate(templateId: String): ApiResult<Unit>
    suspend fun createFromTemplate(templateId: String): ApiResult<Unit>
}

@Singleton
class DefaultFleetRepository @Inject constructor(
    private val api: FleetApi,
    private val errorParser: ApiErrorParser,
) : FleetRepository {

    override suspend fun status(): ApiResult<FleetStatus> =
        withContext(Dispatchers.IO) { call { api.status().toDomain() } }

    override suspend fun capacity(): ApiResult<FleetCapacity> =
        withContext(Dispatchers.IO) { call { api.capacity().toDomain() } }

    override suspend fun startAll(): ApiResult<BulkActionResult> =
        withContext(Dispatchers.IO) { call { api.startAll().toDomain() } }

    override suspend fun stopAll(): ApiResult<BulkActionResult> =
        withContext(Dispatchers.IO) { call { api.stopAll().toDomain() } }

    override suspend fun templates(): ApiResult<List<WorkerTemplate>> =
        withContext(Dispatchers.IO) { call { api.templates().templates.map { it.toDomain() } } }

    override suspend fun deleteTemplate(templateId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.deleteTemplate(templateId) } }

    override suspend fun createFromTemplate(templateId: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.createFromTemplate(templateId); Unit } }

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
