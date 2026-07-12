package com.testlogon.android.feature.feed

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.feed.FeedPage
import com.testlogon.android.data.feed.FeedPost
import com.testlogon.android.data.feed.FeedRepository
import com.testlogon.android.data.feed.Paywall
import java.io.IOException

/**
 * AND-104 — test fake for [FeedRepository]. Serves canned feed pages keyed by cursor and a canned
 * single-post result, with optional forced failures. Records call counts for refresh assertions.
 */
class FakeFeedRepository(
    private val pagesByCursor: Map<String?, FeedPage> = emptyMap(),
    var feedResult: ApiResult<FeedPage>? = null,
    var postResult: ApiResult<FeedPost>? = null,
) : FeedRepository {

    var feedCalls: Int = 0
        private set
    var postCalls: Int = 0
        private set

    override suspend fun getFeedPage(cursor: String?, limit: Int?, authorId: String?): ApiResult<FeedPage> {
        feedCalls++
        feedResult?.let { return it }
        val page = pagesByCursor[cursor] ?: FeedPage(emptyList(), nextCursor = null)
        return ApiResult.Success(page)
    }

    override suspend fun getPost(postId: String): ApiResult<FeedPost> {
        postCalls++
        return postResult ?: ApiResult.Success(post(postId))
    }

    companion object {
        fun post(
            id: String,
            authorId: String = "u_1",
            body: String? = "body $id",
            paywall: Paywall = Paywall.Unlocked,
        ) = FeedPost(
            id = id,
            authorId = authorId,
            createdAtEpochSeconds = 1_780_000_000L,
            body = if (paywall is Paywall.Locked) null else body,
            media = emptyList(),
            tags = emptyList(),
            likeCount = 0,
            commentCount = 0,
            likedByMe = false,
            paywall = paywall,
        )

        fun failure(status: Int) = ApiResult.Failure(ApiError(status = status, message = "err $status"))

        fun network() = ApiResult.NetworkError(IOException("offline"), isTimeout = true)
    }
}
