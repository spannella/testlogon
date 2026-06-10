package com.testlogon.android.feature.feed

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.Comment
import com.testlogon.android.data.feed.CommentPage
import com.testlogon.android.data.feed.CommentsRepository
import com.testlogon.android.data.feed.LikeState
import com.testlogon.android.data.feed.PostActionsRepository
import com.testlogon.android.data.feed.PostEngagementRepository
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import java.io.IOException

/**
 * AND-173 — fake [PostEngagementRepository]. Records calls and returns a configurable result; can be
 * made to suspend (gated) so coalescing/supersede + optimistic-before-completion can be exercised.
 */
class FakeEngagementRepository(
    var result: (postId: String, liked: Boolean, count: Int) -> ApiResult<LikeState> =
        { _, liked, count -> ApiResult.Success(LikeState(liked, count)) },
) : PostEngagementRepository {

    val calls = mutableListOf<Triple<String, Boolean, Int>>()

    /** When non-null, setLiked awaits this gate before returning (to test in-flight states). */
    var gate: CompletableDeferred<Unit>? = null

    override suspend fun setLiked(postId: String, liked: Boolean, desiredCount: Int): ApiResult<LikeState> {
        calls += Triple(postId, liked, desiredCount)
        gate?.await()
        return result(postId, liked, desiredCount)
    }
}

/**
 * AND-175 — fake [PostActionsRepository]. Backs [suppressed] with an in-memory set so the feed filter
 * can be exercised; hide/notInterested/unhide mutate it and return a configurable result.
 */
class FakePostActionsRepository(
    initial: Set<String> = emptySet(),
    var hideResult: ApiResult<Unit> = ApiResult.Success(Unit),
    var unhideResult: ApiResult<Unit> = ApiResult.Success(Unit),
) : PostActionsRepository {

    val hideCalls = mutableListOf<String>()
    val notInterestedCalls = mutableListOf<String>()
    val unhideCalls = mutableListOf<String>()

    private val _suppressed = MutableStateFlow(initial)
    override val suppressed: StateFlow<Set<String>> = _suppressed

    override suspend fun hide(postId: String): ApiResult<Unit> {
        hideCalls += postId
        if (hideResult is ApiResult.Success) _suppressed.value = _suppressed.value + postId
        return hideResult
    }

    override suspend fun notInterested(postId: String): ApiResult<Unit> {
        notInterestedCalls += postId
        if (hideResult is ApiResult.Success) _suppressed.value = _suppressed.value + postId
        return hideResult
    }

    override suspend fun unhide(postId: String): ApiResult<Unit> {
        unhideCalls += postId
        if (unhideResult is ApiResult.Success) _suppressed.value = _suppressed.value - postId
        return unhideResult
    }
}

/**
 * AND-174 — fake [CommentsRepository]. Serves canned pages keyed by cursor and a configurable add /
 * delete result; records calls.
 */
class FakeCommentsRepository(
    private val pagesByCursor: Map<String?, CommentPage> = mapOf(null to CommentPage(emptyList(), null)),
    var addResult: ApiResult<Comment>? = null,
    var deleteResult: ApiResult<Unit> = ApiResult.Success(Unit),
    override val repliesSupported: Boolean = false,
) : CommentsRepository {

    val addCalls = mutableListOf<Triple<String, String, String?>>()
    val deleteCalls = mutableListOf<Pair<String, String>>()
    var getCalls = 0
        private set

    override suspend fun getComments(postId: String, cursor: String?, limit: Int): ApiResult<CommentPage> {
        getCalls++
        return ApiResult.Success(pagesByCursor[cursor] ?: CommentPage(emptyList(), null))
    }

    override suspend fun addComment(postId: String, body: String, parentId: String?): ApiResult<Comment> {
        addCalls += Triple(postId, body, parentId)
        return addResult ?: ApiResult.Success(
            comment(id = "srv_${addCalls.size}", postId = postId, body = body, parentId = parentId),
        )
    }

    override suspend fun deleteComment(postId: String, commentId: String): ApiResult<Unit> {
        deleteCalls += postId to commentId
        return deleteResult
    }

    companion object {
        fun comment(
            id: String,
            postId: String = "post_1",
            authorId: String = "u_other",
            body: String = "body $id",
            parentId: String? = null,
            canDelete: Boolean = false,
        ) = Comment(
            id = id,
            postId = postId,
            parentId = parentId,
            authorId = authorId,
            body = body,
            createdAtEpochSeconds = 1_780_000_000L,
            updatedAtEpochSeconds = null,
            canDelete = canDelete,
            localKey = id,
        )

        fun failure(status: Int) = ApiResult.Failure(ApiError(status = status, message = "err $status"))
        fun network() = ApiResult.NetworkError(IOException("offline"))
    }
}
