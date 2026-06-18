package com.testlogon.android.data.feed

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.auth.AuthStateStore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-174 — comments data layer over [EngagementApi].
 *
 * Wraps GET /posts/{id}/comments (cursor-paged), POST (add), and DELETE (own) in [ApiResult], mapping
 * wire DTOs to the domain [Comment]. Deletability ([Comment.canDelete]) is derived client-side from
 * author_id == current user id (no server field). Replies are gated behind [repliesSupported] which is
 * false by default: the backend has a parent_comment_id field but NO replies endpoint and the web
 * renders comments flat, so threaded reply UI is off (AND-174 §FR-5).
 *
 * GETs benefit from the shared idempotent-GET backoff; mutations (add/delete) get a single attempt
 * (non-idempotent). CancellationException is re-thrown for Paging / structured cancellation.
 */
interface CommentsRepository {

    suspend fun getComments(
        postId: String,
        cursor: String?,
        limit: Int = EngagementApi.COMMENTS_PAGE_SIZE,
    ): ApiResult<CommentPage>

    suspend fun addComment(
        postId: String,
        body: String,
        parentId: String? = null,
    ): ApiResult<Comment>

    /** Post a GIF comment (kind="gif"). */
    suspend fun addGifComment(
        postId: String,
        gifUrl: String,
        altText: String? = null,
        parentId: String? = null,
    ): ApiResult<Comment>

    /** Post a sticker comment (kind="sticker"). */
    suspend fun addStickerComment(
        postId: String,
        stickerId: String,
        collectionId: String,
        stickerUrl: String,
        altText: String? = null,
        parentId: String? = null,
    ): ApiResult<Comment>

    /** Tip a comment (amount in integer cents). 2xx ack. */
    suspend fun tipComment(postId: String, commentId: String, amountCents: Int): ApiResult<Unit>

    suspend fun deleteComment(postId: String, commentId: String): ApiResult<Unit>

    suspend fun editComment(postId: String, commentId: String, body: String): ApiResult<Comment>

    /** Capability flag for threaded replies (backend accepts parent_comment_id). */
    val repliesSupported: Boolean
}

@Singleton
class CommentsRepositoryImpl @Inject constructor(
    private val api: EngagementApi,
    private val errorParser: ApiErrorParser,
    private val authStateStore: AuthStateStore,
) : CommentsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override val repliesSupported: Boolean = true

    override suspend fun getComments(
        postId: String,
        cursor: String?,
        limit: Int,
    ): ApiResult<CommentPage> = withContext(io) {
        val me = authStateStore.userSub.first()
        apiCall { api.getComments(postId = postId, cursor = cursor, limit = limit) }
            .map { it.toDomain(me) }
    }

    override suspend fun addComment(
        postId: String,
        body: String,
        parentId: String?,
    ): ApiResult<Comment> = withContext(io) {
        val me = authStateStore.userSub.first()
        apiCall {
            api.addComment(postId, CreateCommentRequest(body = body, parentCommentId = parentId))
        }.map { it.toDomain(me) }
    }

    override suspend fun addGifComment(
        postId: String,
        gifUrl: String,
        altText: String?,
        parentId: String?,
    ): ApiResult<Comment> = withContext(io) {
        val me = authStateStore.userSub.first()
        apiCall {
            api.addComment(
                postId,
                CreateCommentRequest(body = "", parentCommentId = parentId, kind = "gif", gifUrl = gifUrl, gifAltText = altText),
            )
        }.map { it.toDomain(me) }
    }

    override suspend fun addStickerComment(
        postId: String,
        stickerId: String,
        collectionId: String,
        stickerUrl: String,
        altText: String?,
        parentId: String?,
    ): ApiResult<Comment> = withContext(io) {
        val me = authStateStore.userSub.first()
        apiCall {
            api.addComment(
                postId,
                CreateCommentRequest(
                    body = "",
                    parentCommentId = parentId,
                    kind = "sticker",
                    stickerId = stickerId,
                    stickerCollectionId = collectionId,
                    stickerUrl = stickerUrl,
                    stickerAltText = altText,
                ),
            )
        }.map { it.toDomain(me) }
    }

    override suspend fun tipComment(postId: String, commentId: String, amountCents: Int): ApiResult<Unit> =
        withContext(io) { ackCall { api.tipComment(postId, commentId, TipRequest(amountCents = amountCents)) } }

    override suspend fun deleteComment(postId: String, commentId: String): ApiResult<Unit> =
        withContext(io) { ackCall { api.deleteComment(postId, commentId) } }

    override suspend fun editComment(
        postId: String,
        commentId: String,
        body: String,
    ): ApiResult<Comment> = withContext(io) {
        val me = authStateStore.userSub.first()
        apiCall { api.editComment(postId, commentId, EditCommentRequest(body = body)) }.map { it.toDomain(me) }
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
