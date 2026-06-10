package com.testlogon.android.feature.videos

import com.testlogon.android.auth.AuthStateProvider
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.videos.LikeState
import com.testlogon.android.data.videos.VideoAccess
import com.testlogon.android.data.videos.VideoDetail
import com.testlogon.android.data.videos.VideoPage
import com.testlogon.android.data.videos.VideoSummary
import com.testlogon.android.data.videos.VideosRepository

/**
 * AND-189 / AND-190 — shared fake [VideosRepository] for paging + ViewModel tests. List pages are keyed
 * by the requested cursor; detail/like/similar are single configurable results.
 */
class FakeVideosRepository : VideosRepository {

    val pages = mutableMapOf<String?, ApiResult<VideoPage>>()
    val requestedCursors = mutableListOf<String?>()

    var detailResult: ApiResult<VideoDetail> = ApiResult.Success(detail("vid_1"))
    var likeResult: ApiResult<Boolean> = ApiResult.Success(false)
    var toggleResult: ApiResult<LikeState> = ApiResult.Success(LikeState(liked = true, likeCount = 1))
    var similarResult: ApiResult<List<VideoSummary>> = ApiResult.Success(emptyList())
    // Default: the access call "fails" (Failure) so the resolver falls back to the inline detail flag,
    // preserving the legacy behavior unless a test sets an explicit access result.
    var accessResult: ApiResult<VideoAccess> = ApiResult.Failure(ApiError(status = 500, message = "no access"))
    var toggleCalls = 0
    var detailCalls = 0
    var accessCalls = 0

    override suspend fun listVideos(
        cursor: String?,
        limit: Int,
        status: String?,
        visibility: String?,
    ): ApiResult<VideoPage> {
        requestedCursors += cursor
        return pages[cursor] ?: ApiResult.Success(VideoPage(emptyList(), null))
    }

    override suspend fun getVideoDetail(videoId: String): ApiResult<VideoDetail> {
        detailCalls++
        return detailResult
    }

    override suspend fun getSimilar(videoId: String, limit: Int): ApiResult<List<VideoSummary>> = similarResult

    override suspend fun checkLike(videoId: String): ApiResult<Boolean> = likeResult

    override suspend fun toggleLike(videoId: String): ApiResult<LikeState> {
        toggleCalls++
        return toggleResult
    }

    override suspend fun checkAccess(videoId: String): ApiResult<VideoAccess> {
        accessCalls++
        return accessResult
    }

    companion object {
        fun summary(id: String) = VideoSummary(id = id, title = "T-$id", thumbnailUrl = null, durationSec = 60)

        fun detail(
            id: String,
            status: String = "ready",
            playbackUrl: String? = "http://h/master.m3u8?token=tok",
            isEntitled: Boolean = true,
            accessMode: String? = null,
            priceCents: Int? = null,
            purchaseAvailable: Boolean = false,
            subscriptionAvailable: Boolean = false,
            subscriptionUpsell: Boolean = false,
        ) = VideoDetail(
            id = id,
            ownerUserId = "u",
            title = "T-$id",
            description = "desc",
            status = status,
            visibility = "public",
            durationSec = 60,
            thumbnailUrl = null,
            playbackUrl = playbackUrl,
            publishedAtEpochSeconds = null,
            reviewStatus = null,
            isEntitled = isEntitled,
            accessMode = accessMode,
            priceCentsOrNull = priceCents,
            purchaseAvailableOrFalse = purchaseAvailable,
            subscriptionAvailableOrFalse = subscriptionAvailable,
            subscriptionUpsellOrFalse = subscriptionUpsell,
        )

        fun access(
            entitled: Boolean,
            reason: String = "none",
            accessMode: String? = null,
            priceCents: Int? = null,
            purchaseAvailable: Boolean = false,
            subscriptionAvailable: Boolean = false,
            subscriptionUpsell: Boolean = false,
        ) = VideoAccess(
            entitled = entitled,
            reason = reason,
            accessMode = accessMode,
            priceCents = priceCents,
            purchaseAvailable = purchaseAvailable,
            subscriptionAvailable = subscriptionAvailable,
            subscriptionUpsell = subscriptionUpsell,
            expiresAtEpochSeconds = null,
            viewsRemaining = -1,
        )
    }
}

/** AND-197 — JVM fake [AuthStateProvider] with a settable authentication flag. */
class FakeAuthStateProvider(authenticated: Boolean = true) : AuthStateProvider {
    private val flow = kotlinx.coroutines.flow.MutableStateFlow(authenticated)
    override val isAuthenticated: kotlinx.coroutines.flow.StateFlow<Boolean> = flow

    fun set(value: Boolean) {
        flow.value = value
    }
}
