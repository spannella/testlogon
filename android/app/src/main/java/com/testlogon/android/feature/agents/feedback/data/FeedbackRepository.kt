package com.testlogon.android.feature.agents.feedback.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.agents.FeedbackApi
import com.testlogon.android.core.network.agents.FeedbackRespondRequest
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
 * AGENTS-BASICS (web-parity) - data layer for the FEEDBACK surface over [FeedbackApi]. Folds transport into
 * [ApiResult] via [call] (HTTP -> Failure preserving status; malformed JSON -> Failure; transport -> NetworkError;
 * cancellation re-thrown). Mirrors the WORKERS repository fold. No cache / Room.
 */
interface FeedbackRepository {
    suspend fun list(status: String? = null): ApiResult<List<FeedbackRequest>>
    suspend fun respond(workerId: String, requestId: String, text: String): ApiResult<FeedbackRequest>
    suspend fun skip(workerId: String, requestId: String): ApiResult<FeedbackRequest>
}

@Singleton
class DefaultFeedbackRepository @Inject constructor(
    private val api: FeedbackApi,
    private val errorParser: ApiErrorParser,
) : FeedbackRepository {

    override suspend fun list(status: String?): ApiResult<List<FeedbackRequest>> =
        withContext(Dispatchers.IO) {
            call { api.list(status = status).requests.map { it.toDomain() } }
        }

    override suspend fun respond(workerId: String, requestId: String, text: String): ApiResult<FeedbackRequest> =
        withContext(Dispatchers.IO) {
            call { api.respond(workerId, requestId, FeedbackRespondRequest(responseText = text)).toDomain() }
        }

    override suspend fun skip(workerId: String, requestId: String): ApiResult<FeedbackRequest> =
        withContext(Dispatchers.IO) { call { api.skip(workerId, requestId).toDomain() } }

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
