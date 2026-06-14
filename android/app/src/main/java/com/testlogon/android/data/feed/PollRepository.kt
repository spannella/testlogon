package com.testlogon.android.data.feed

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
 * AND-179 — poll vote data layer over [PollApi].
 *
 * Voting is keyed by (postId, questionId, optionId) and returns the per-question [PollVoteResult]
 * (VoteResponse), since the server reports per-question counts, not the whole poll. Voting is a
 * non-idempotent POST and is NEVER auto-retried. CancellationException is re-thrown.
 */
interface PollRepository {
    suspend fun vote(postId: String, questionId: String, optionId: String): ApiResult<PollVoteResult>
    suspend fun removeVote(postId: String, questionId: String): ApiResult<PollVoteResult>
}

@Singleton
class PollRepositoryImpl @Inject constructor(
    private val api: PollApi,
    private val errorParser: ApiErrorParser,
) : PollRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun vote(
        postId: String,
        questionId: String,
        optionId: String,
    ): ApiResult<PollVoteResult> = withContext(io) {
        apiCall { api.vote(postId, PollVoteRequestDto(questionId, optionId)).toDomain() }
    }

    override suspend fun removeVote(
        postId: String,
        questionId: String,
    ): ApiResult<PollVoteResult> = withContext(io) {
        apiCall { api.removeVote(postId, PollRemoveVoteRequestDto(questionId)).toDomain() }
    }

    private suspend fun <T> apiCall(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
