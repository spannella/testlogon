package com.testlogon.android.feature.clips

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.clips.Clip
import com.testlogon.android.data.clips.ClipStatus
import com.testlogon.android.data.clips.ClipsPage
import com.testlogon.android.data.clips.ClipsRepository

/**
 * AND-196 / AND-198 — shared fake [ClipsRepository] for paging + ViewModel tests. Feed pages are keyed
 * by the requested cursor; single/public clip + playback-url are single configurable results.
 */
class FakeClipsRepository : ClipsRepository {

    val pages = mutableMapOf<String?, ApiResult<ClipsPage>>()
    val requestedCursors = mutableListOf<String?>()

    var clipResult: ApiResult<Clip> = ApiResult.Success(sampleClip("clp_1"))
    var publicClipResult: ApiResult<Clip> = ApiResult.Success(sampleClip("clp_1"))
    var playbackUrlResult: String? = null
    var publicClipCalls = 0

    override suspend fun feed(cursor: String?, sort: String?, limit: Int): ApiResult<ClipsPage> {
        requestedCursors += cursor
        return pages[cursor] ?: ApiResult.Success(ClipsPage(emptyList(), null))
    }

    override suspend fun clip(clipId: String): ApiResult<Clip> = clipResult

    override suspend fun publicClip(clipId: String): ApiResult<Clip> {
        publicClipCalls++
        return publicClipResult
    }

    override suspend fun resolvePlaybackUrl(clip: Clip): String? = playbackUrlResult

    companion object {
        fun sampleClip(
            id: String,
            status: ClipStatus = ClipStatus.READY,
            videoId: String = "vid_$id",
            thumbnailUrl: String? = "http://h/$id.jpg",
        ) = Clip(
            clipId = id,
            sessionId = "ses_$id",
            videoId = videoId,
            creatorUserId = "usr_c_$id",
            creatorDisplayName = "Creator",
            broadcasterUserId = "usr_b_$id",
            title = "Clip $id",
            startSeconds = 12.0,
            endSeconds = 26.2,
            durationSeconds = 14.2,
            status = status,
            viewCount = 5400,
            shareCount = 12,
            thumbnailUrl = thumbnailUrl,
            createdAtEpochSeconds = 1_733_443_200L,
            broadcasterDisplayName = "Broadcaster",
            profileId = "prof_$id",
        )
    }
}
