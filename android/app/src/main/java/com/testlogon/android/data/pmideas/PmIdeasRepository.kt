package com.testlogon.android.data.pmideas

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
 * PM-idea triage data layer over [PmIdeasApi].
 *
 * loadIdeas(status) issues the idempotent GET (by status tab) and maps to [PmIdeasPage]; the triage
 * mutations (approve/reject/archive) + trigger-review map 1:1. Every call is wrapped in [ApiResult].
 */
interface PmIdeasRepository {
    suspend fun loadIdeas(status: String): ApiResult<PmIdeasPage>
    suspend fun approve(ideaId: String): ApiResult<Unit>
    suspend fun reject(ideaId: String, reason: String): ApiResult<Unit>
    suspend fun archive(ideaId: String): ApiResult<Unit>
    suspend fun triggerReview(): ApiResult<Unit>
}

@Singleton
class PmIdeasRepositoryImpl @Inject constructor(
    private val api: PmIdeasApi,
    private val errorParser: ApiErrorParser,
) : PmIdeasRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadIdeas(status: String): ApiResult<PmIdeasPage> = withContext(io) {
        call { api.listIdeas(status = status).toDomain() }
    }

    override suspend fun approve(ideaId: String): ApiResult<Unit> = mutate { api.approveIdea(ideaId) }

    override suspend fun reject(ideaId: String, reason: String): ApiResult<Unit> =
        mutate { api.rejectIdea(ideaId, RejectIdeaReqDto(reason = reason.trim())) }

    override suspend fun archive(ideaId: String): ApiResult<Unit> = mutate { api.archiveIdea(ideaId) }

    override suspend fun triggerReview(): ApiResult<Unit> = mutate { api.triggerReview(TriggerReviewReqDto()) }

    private suspend fun mutate(block: suspend () -> Any?): ApiResult<Unit> = withContext(io) {
        call {
            block()
            Unit
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
