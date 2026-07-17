package com.testlogon.android.data.disputes

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
 * AND-245 + DISP-021/023 — disputes data layer over [DisputesApi].
 *
 * Wraps every call in [ApiResult]: CancellationException is re-thrown; HTTP errors fold to Failure (via
 * [ApiErrorParser]); transport failures to NetworkError. DTOs are mapped to domain before returning.
 * Lists are sorted newest-first by created_at.
 *
 * GET reads (list/detail) are idempotent; the file-dispute POST and the creator-respond POST are
 * non-idempotent (no auto-retry).
 */
interface DisputesRepository {

    /** All of my (payer) disputes (single bounded fetch, newest-first). Idempotent GET. */
    suspend fun listDisputes(limit: Int = DisputesApi.DEFAULT_LIMIT): ApiResult<List<Dispute>>

    /** A single dispute's current status/detail. Idempotent GET. */
    suspend fun getDispute(id: String): ApiResult<Dispute>

    /** File (open) a dispute against a transaction. Non-idempotent (no auto-retry). */
    suspend fun fileDispute(input: FileDisputeInput): ApiResult<Dispute>

    /** DISP-021: my inbound queue — disputes filed against me as creator/seller. Idempotent GET. */
    suspend fun listCreatorDisputes(limit: Int = DisputesApi.DEFAULT_LIMIT): ApiResult<List<Dispute>>

    /** DISP-021: submit my rebuttal within the response window. Non-idempotent. */
    suspend fun creatorRespond(input: CreatorRespondInput): ApiResult<CreatorRespondResult>
}

@Singleton
class DisputesRepositoryImpl @Inject constructor(
    private val api: DisputesApi,
    private val errorParser: ApiErrorParser,
) : DisputesRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listDisputes(limit: Int): ApiResult<List<Dispute>> = withContext(io) {
        call { api.listDisputes(limit) }.map { dto ->
            dto.items.map { it.toDomain() }.sortedByDescending { it.createdAtEpochSeconds ?: 0L }
        }
    }

    override suspend fun getDispute(id: String): ApiResult<Dispute> = withContext(io) {
        call { api.getDispute(id) }.map { it.toDomain() }
    }

    override suspend fun fileDispute(input: FileDisputeInput): ApiResult<Dispute> = withContext(io) {
        call { api.fileDispute(input.toDto()) }.map { it.toDomain() }
    }

    override suspend fun listCreatorDisputes(limit: Int): ApiResult<List<Dispute>> = withContext(io) {
        call { api.listCreatorDisputes(limit) }.map { dto ->
            dto.items.map { it.toDomain() }.sortedByDescending { it.createdAtEpochSeconds ?: 0L }
        }
    }

    override suspend fun creatorRespond(input: CreatorRespondInput): ApiResult<CreatorRespondResult> =
        withContext(io) {
            call { api.creatorRespond(input.disputeId, input.toDto()) }.map { it.toDomain() }
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
