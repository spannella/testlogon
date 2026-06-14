package com.testlogon.android.data.payouts

import com.squareup.moshi.JsonDataException
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
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
 * AND-261 — READ-ONLY bulk/batch payout data layer over [BulkPayoutsApi].
 *
 * Both endpoints return whole collections, so this is two simple suspend [ApiResult] methods — NO
 * Paging 3 / PagingSource (the contract has no cursor). Wraps every call like [PayoutsRepositoryImpl]:
 * CancellationException is re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport
 * failures to NetworkError. DTOs are mapped to domain before returning (no raw DTOs leak out). Both
 * calls are idempotent GETs (the core-network RetryInterceptor handles bounded retry on transient
 * IOException/timeout/5xx). There are NO mutation methods here (read-only ticket).
 */
interface BulkPayoutsRepository {

    /** All batch summaries (line items empty on the list call). Idempotent GET. */
    suspend fun getBatches(): ApiResult<List<PayoutBatch>>

    /** One batch including its embedded line items. Idempotent GET. */
    suspend fun getBatch(batchId: String): ApiResult<PayoutBatch>
}

@Singleton
class BulkPayoutsRepositoryImpl @Inject constructor(
    private val api: BulkPayoutsApi,
    private val errorParser: ApiErrorParser,
) : BulkPayoutsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getBatches(): ApiResult<List<PayoutBatch>> = withContext(io) {
        call { api.getBatches().map { it.toDomain() } }
    }

    override suspend fun getBatch(batchId: String): ApiResult<PayoutBatch> = withContext(io) {
        call { api.getBatch(batchId).toDomain() }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonDataException) {
        // Malformed/unexpected body from the (unreliable dev) backend -> a graceful Failure, never a crash.
        ApiResult.Failure(ApiError(status = 0, message = e.message ?: "Malformed server response"))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
