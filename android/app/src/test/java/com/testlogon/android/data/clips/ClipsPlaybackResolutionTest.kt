package com.testlogon.android.data.clips

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.videos.FakeVideosRepository
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * AND-198 — verifies [ClipsRepositoryImpl.resolvePlaybackUrl] REUSES the videos detail endpoint to turn
 * a clip's `video_id` into a tokenized HLS URL, and fails closed (null) for non-playable clips or when
 * the videos detail fetch fails. The clips API is never invoked here, so a stub api is fine.
 */
class ClipsPlaybackResolutionTest {

    private val videos = FakeVideosRepository()

    private fun repo(): ClipsRepositoryImpl {
        val api = stubApi()
        return ClipsRepositoryImpl(api = api, videosRepository = videos, errorParser = ApiErrorParser(Moshi.Builder().build()))
    }

    @Test
    fun readyClip_resolvesTokenizedUrl_fromSourceVideo() = runTest {
        videos.detailResult = ApiResult.Success(
            FakeVideosRepository.detail("vid_1", playbackUrl = "http://h/master.m3u8?token=tok"),
        )
        val clip = FakeClip.ready(videoId = "vid_1")
        assertEquals("http://h/master.m3u8?token=tok", repo().resolvePlaybackUrl(clip))
    }

    @Test
    fun processingClip_returnsNull_withoutHittingVideos() = runTest {
        val clip = FakeClip.ready(videoId = "vid_1").copy(status = ClipStatus.PROCESSING)
        assertNull(repo().resolvePlaybackUrl(clip))
        assertEquals(0, videos.detailCalls)
    }

    @Test
    fun videosDetailFailure_failsClosedToNull() = runTest {
        videos.detailResult = ApiResult.Failure(com.testlogon.android.core.model.ApiError(status = 403, message = "x"))
        val clip = FakeClip.ready(videoId = "vid_1")
        assertNull(repo().resolvePlaybackUrl(clip))
    }

    @Test
    fun videoWithoutSource_returnsNull() = runTest {
        videos.detailResult = ApiResult.Success(FakeVideosRepository.detail("vid_1", playbackUrl = null))
        val clip = FakeClip.ready(videoId = "vid_1")
        assertNull(repo().resolvePlaybackUrl(clip))
    }

    private object FakeClip {
        fun ready(videoId: String) = Clip(
            clipId = "clp_1",
            sessionId = "ses_1",
            videoId = videoId,
            creatorUserId = "c1",
            creatorDisplayName = "Alex",
            broadcasterUserId = "b1",
            title = "t",
            startSeconds = 0.0,
            endSeconds = 5.0,
            durationSeconds = 5.0,
            status = ClipStatus.READY,
            viewCount = 0,
            shareCount = 0,
            thumbnailUrl = null,
            createdAtEpochSeconds = 1L,
        )
    }

    /** Minimal [ClipsApi] stub; resolvePlaybackUrl never invokes it. */
    private fun stubApi(): ClipsApi = object : ClipsApi {
        override suspend fun getFeed(sort: String?, limit: Int, cursor: String?): ClipListResponseDto =
            throw UnsupportedOperationException()
        override suspend fun getMyClips(): ClipListResponseDto = throw UnsupportedOperationException()
        override suspend fun getClip(clipId: String): ClipDto = throw UnsupportedOperationException()
        override suspend fun getPublicClip(clipId: String): PublicClipDto = throw UnsupportedOperationException()
    }
}
