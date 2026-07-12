package com.testlogon.android.data.feed

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
 * AND-173 — like/unlike data layer over [EngagementApi].
 *
 * The like/unlike endpoints return only an ack ({ "ok": true }) with NO liked / like_count, so this
 * layer does NOT read state from the body: on any 2xx it returns the desired terminal [LikeState]
 * (the caller's optimistic liked + count carried forward). The server-authoritative count is picked
 * up by a later feed/post refetch, mirroring the web client's invalidateQueries(["feed"]). There is
 * no post Room cache in scope (the feed is network-only; see FeedRepository), so the like override
 * lives in the ViewModel and is reconciled on the next pager load — documented gap vs AND-173 §6.
 *
 * CancellationException is re-thrown so per-post supersede / structured cancellation works.
 */
interface PostEngagementRepository {

    /**
     * Applies the desired terminal [liked] state for [postId]. [desiredCount] is carried forward into
     * the returned [LikeState] because the API returns no count.
     */
    suspend fun setLiked(postId: String, liked: Boolean, desiredCount: Int): ApiResult<LikeState>

    /**
     * #20 — toggle an emoji reaction on a post. [add] true => react, false => unreact. The endpoints
     * return only an ack so the caller keeps its optimistic tallies; the authoritative counts land on
     * the next post refetch. 2xx => Success, non-2xx => Failure, IO => NetworkError.
     */
    suspend fun setReaction(postId: String, emoji: String, add: Boolean): ApiResult<Unit>
}

@Singleton
class PostEngagementRepositoryImpl @Inject constructor(
    private val api: EngagementApi,
    private val errorParser: ApiErrorParser,
) : PostEngagementRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun setLiked(
        postId: String,
        liked: Boolean,
        desiredCount: Int,
    ): ApiResult<LikeState> = withContext(io) {
        ackCall { if (liked) api.like(postId) else api.unlike(postId) }
            .map { LikeState(liked = liked, likeCount = desiredCount.coerceAtLeast(0)) }
    }

    override suspend fun setReaction(
        postId: String,
        emoji: String,
        add: Boolean,
    ): ApiResult<Unit> = withContext(io) {
        ackCall {
            if (add) api.react(postId, ReactionRequest(emoji)) else api.unreact(postId, ReactionRequest(emoji))
        }
    }

    /** Runs an ack-only call: a 2xx completes (Success), non-2xx -> HttpException -> mapped Failure. */
    private suspend fun ackCall(block: suspend () -> Unit): ApiResult<Unit> = try {
        block()
        ApiResult.Success(Unit)
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }
}
