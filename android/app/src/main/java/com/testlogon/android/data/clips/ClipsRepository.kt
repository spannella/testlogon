package com.testlogon.android.data.clips

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.map
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.videos.VideosRepository
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
 * AND-196 — data layer over [ClipsApi].
 *
 * Wraps each idempotent GET in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError
 * for transport failures), mapping wire DTOs to the redaction-safe domain. Never throws
 * (CancellationException is re-thrown so Paging cancellation works). No Room cache in this slice — the
 * feed uses Paging's in-memory cache + Coil thumbnail caching.
 *
 * PLAYBACK URL resolution: the clip schema has NO stream URL — it only carries a `video_id`. So a
 * playable tokenized HLS URL is resolved by REUSING [VideosRepository.getVideoDetail] on the clip's
 * source video (which returns `hls_manifest_url` + `playback_token`). This is best-effort: if the
 * detail fetch fails or yields no source, the clip renders thumbnail-only (web parity). The client
 * NEVER synthesizes a stream URL.
 */
interface ClipsRepository {

    /** One cursor-paged page of the clips gallery feed (GET ui/clips). */
    suspend fun feed(
        cursor: String?,
        sort: String? = ClipsApi.SORT_RECENT,
        limit: Int = ClipsApi.FEED_PAGE_SIZE,
    ): ApiResult<ClipsPage>

    /** A single authed clip (GET broadcast/clips/{clip_id}). */
    suspend fun clip(clipId: String): ApiResult<Clip>

    /** A single public, unauthenticated clip (GET broadcast/public/clips/{clip_id}). */
    suspend fun publicClip(clipId: String): ApiResult<Clip>

    /**
     * Best-effort playable HLS URL for a clip's source video, resolved via the videos detail endpoint.
     * Returns null when the clip has no source, the video is not playable/entitled, or the fetch fails.
     * Never throws and never synthesizes a URL.
     */
    suspend fun resolvePlaybackUrl(clip: Clip): String?
}

@Singleton
class ClipsRepositoryImpl @Inject constructor(
    private val api: ClipsApi,
    private val videosRepository: VideosRepository,
    private val errorParser: ApiErrorParser,
) : ClipsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun feed(cursor: String?, sort: String?, limit: Int): ApiResult<ClipsPage> =
        withContext(io) {
            call { api.getFeed(sort = sort, limit = limit, cursor = cursor) }.map { it.toDomain() }
        }

    override suspend fun clip(clipId: String): ApiResult<Clip> = withContext(io) {
        call { api.getClip(clipId) }.map { it.toDomain() }
    }

    override suspend fun publicClip(clipId: String): ApiResult<Clip> = withContext(io) {
        call { api.getPublicClip(clipId) }.map { it.toDomain() }
    }

    override suspend fun resolvePlaybackUrl(clip: Clip): String? = withContext(io) {
        if (!clip.isPlayable) return@withContext null
        when (val detail = videosRepository.getVideoDetail(clip.videoId)) {
            is ApiResult.Success -> detail.data.playbackUrl
            else -> null
        }
    }

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
