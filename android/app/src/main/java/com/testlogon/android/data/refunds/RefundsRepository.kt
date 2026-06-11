package com.testlogon.android.data.refunds

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
 * AND-244 — refund-requests data layer over [RefundsApi].
 *
 * Wraps every call in [ApiResult] (matching the invoices/billing repositories): CancellationException is
 * re-thrown; HTTP errors fold to Failure (via [ApiErrorParser]); transport failures to NetworkError.
 * DTOs are mapped to domain before returning (no raw DTOs leak out). The list is sorted newest-first by
 * created_at (the backend gives no ordering guarantee — AND-244 FR-2).
 *
 * GET reads (list/detail) are idempotent; the submit POST is non-idempotent and never auto-retried (the
 * ViewModel's in-flight guard is the duplicate protection — AND-244 §6/§7).
 */
interface RefundsRepository {

    /** All of my refund requests (single bounded fetch, newest-first). Idempotent GET. */
    suspend fun listRefunds(limit: Int = RefundsApi.DEFAULT_LIMIT): ApiResult<List<RefundRequest>>

    /** A single refund request's current status/detail. Idempotent GET. */
    suspend fun getRefund(id: String): ApiResult<RefundRequest>

    /** Submit a refund request. Non-idempotent (no auto-retry). */
    suspend fun submitRefund(input: SubmitRefundInput): ApiResult<RefundRequest>
}

@Singleton
class RefundsRepositoryImpl @Inject constructor(
    private val api: RefundsApi,
    private val errorParser: ApiErrorParser,
) : RefundsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listRefunds(limit: Int): ApiResult<List<RefundRequest>> = withContext(io) {
        call { api.listRefunds(limit) }.map { dto ->
            dto.items.map { it.toDomain() }.sortedByDescending { it.createdAtEpochSeconds ?: 0L }
        }
    }

    override suspend fun getRefund(id: String): ApiResult<RefundRequest> = withContext(io) {
        call { api.getRefund(id) }.map { it.toDomain() }
    }

    override suspend fun submitRefund(input: SubmitRefundInput): ApiResult<RefundRequest> = withContext(io) {
        call { api.submitRefund(input.toDto()) }.map { it.toDomain() }
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
