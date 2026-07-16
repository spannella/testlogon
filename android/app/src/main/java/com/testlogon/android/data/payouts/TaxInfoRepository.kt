package com.testlogon.android.data.payouts

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
 * PAY-22 — W-9 tax-info data layer over [TaxInfoApi] (the pre-withdrawal gate's tax leg).
 *
 * [getTaxInfo] is an idempotent GET (masked status). [submitTaxInfo] is a mutation (NEVER auto-retried)
 * that sends the raw TIN once over TLS; the response is always the masked view. All calls are
 * [ApiResult]-wrapped (CancellationException re-thrown; HTTP -> Failure via [ApiErrorParser]; transport
 * -> NetworkError). DTOs are mapped to domain before returning (no raw DTOs leak out).
 */
interface TaxInfoRepository {

    /** The caller's masked W-9 status (on_file + last-4 + certified). Idempotent GET. */
    suspend fun getTaxInfo(): ApiResult<PayoutTaxInfo>

    /** Submit the W-9. The raw TIN is tokenized+masked server-side; the result is the masked view. */
    suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo>
}

@Singleton
class TaxInfoRepositoryImpl @Inject constructor(
    private val api: TaxInfoApi,
    private val errorParser: ApiErrorParser,
) : TaxInfoRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun getTaxInfo(): ApiResult<PayoutTaxInfo> = withContext(io) {
        call { api.getTaxInfo() }.map { it.toDomain() }
    }

    override suspend fun submitTaxInfo(submission: W9Submission): ApiResult<PayoutTaxInfo> =
        withContext(io) {
            call { api.submitTaxInfo(submission.toDto()) }.map { it.toDomain() }
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
