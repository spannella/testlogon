package com.testlogon.android.data.poll

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.poll.ArbitraryPoll
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
 * Vote / close / refresh an arbitrary poll on ANY surface (messaging, group, syndicate) via the shared
 * /ui/polls client. Each call returns the updated [ArbitraryPoll] snapshot so the card re-renders live.
 * Voting is a non-idempotent POST and is never auto-retried; a re-tap of the SAME option toggles it off
 * for a multi-select question (single-select just re-selects, idempotent server-side).
 */
interface PollVoter {
    suspend fun vote(pollId: String, questionId: String, optionId: String): ApiResult<ArbitraryPoll>
    suspend fun unvote(pollId: String, questionId: String): ApiResult<ArbitraryPoll>
    suspend fun close(pollId: String): ApiResult<ArbitraryPoll>
    suspend fun refresh(pollId: String): ApiResult<ArbitraryPoll>
}

@Singleton
class ArbitraryPollRepository @Inject constructor(
    private val api: ArbitraryPollApi,
    private val errorParser: ApiErrorParser,
) : PollVoter {

    override suspend fun vote(
        pollId: String,
        questionId: String,
        optionId: String,
    ): ApiResult<ArbitraryPoll> = withContext(Dispatchers.IO) {
        call { api.vote(pollId, ArbitraryPollVoteReq(optionId = optionId, questionId = questionId)).toDomain() }
    }

    override suspend fun unvote(pollId: String, questionId: String): ApiResult<ArbitraryPoll> =
        withContext(Dispatchers.IO) { call { api.unvote(pollId, questionId).toDomain() } }

    override suspend fun close(pollId: String): ApiResult<ArbitraryPoll> =
        withContext(Dispatchers.IO) { call { api.close(pollId).toDomain() } }

    override suspend fun refresh(pollId: String): ApiResult<ArbitraryPoll> =
        withContext(Dispatchers.IO) { call { api.get(pollId).toDomain() } }

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
