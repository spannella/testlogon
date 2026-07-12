package com.testlogon.android.data.videos

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
 * AND-189 / AND-190 — data layer over [VideosApi].
 *
 * Wraps each idempotent GET in [ApiResult] (Failure for HTTP errors via [ApiErrorParser], NetworkError
 * for transport failures), mapping wire DTOs to the redaction-safe domain. Never throws
 * (CancellationException is re-thrown so Paging cancellation works). No Room cache in this slice — the
 * library uses Paging's in-memory cache + Coil thumbnail caching; detail is cache-free for now.
 */
interface VideosRepository {

    /** One cursor-paged page of the caller's videos (GET ui/videos). */
    suspend fun listVideos(
        cursor: String?,
        limit: Int = VideosApi.LIBRARY_PAGE_SIZE,
        status: String? = null,
        visibility: String? = null,
    ): ApiResult<VideoPage>

    /** Full detail for a single video (GET ui/videos/{video_id}). */
    suspend fun getVideoDetail(videoId: String): ApiResult<VideoDetail>

    /** "Up next" / related videos (GET ui/videos/{video_id}/similar). */
    suspend fun getSimilar(videoId: String, limit: Int = VideosApi.SIMILAR_LIMIT): ApiResult<List<VideoSummary>>

    /** Current like state (GET ui/videos/{video_id}/like). */
    suspend fun checkLike(videoId: String): ApiResult<Boolean>

    /** Toggles like and returns the new (liked, likeCount) pair (POST ui/videos/{video_id}/like). */
    suspend fun toggleLike(videoId: String): ApiResult<LikeState>

    /** AND-197 — the authoritative per-video access check (GET ui/videos/{video_id}/access). */
    suspend fun checkAccess(videoId: String): ApiResult<VideoAccess>

    /** B-VIDSOCIAL2 — add an emoji reaction to a video; returns updated counts + my-reactions. */
    suspend fun reactVideo(videoId: String, emoji: String): ApiResult<VideoReactionState>

    /** B-VIDSOCIAL2 — remove an emoji reaction from a video; returns updated counts + my-reactions. */
    suspend fun unreactVideo(videoId: String, emoji: String): ApiResult<VideoReactionState>

    /** B-VIDSOCIAL2 — tip the video's creator; returns the new running tip total. */
    suspend fun tipVideo(videoId: String, amountCents: Int, paymentMethodId: String?): ApiResult<VideoTipState>
}

/** B-VIDSOCIAL2 — video reaction state surfaced to the detail screen. */
data class VideoReactionState(val reactions: Map<String, Int>, val myReactions: Set<String>)

/** B-VIDSOCIAL2 — video tip receipt surfaced to the detail screen. */
data class VideoTipState(val amountCents: Int, val tipTotalCents: Int)

/** AND-190 — like state surfaced to the detail screen. */
data class LikeState(val liked: Boolean, val likeCount: Int)

@Singleton
class VideosRepositoryImpl @Inject constructor(
    private val api: VideosApi,
    private val errorParser: ApiErrorParser,
) : VideosRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun listVideos(
        cursor: String?,
        limit: Int,
        status: String?,
        visibility: String?,
    ): ApiResult<VideoPage> = withContext(io) {
        call { api.listVideos(cursor = cursor, limit = limit, status = status, visibility = visibility) }
            .map { it.toDomain() }
    }

    override suspend fun getVideoDetail(videoId: String): ApiResult<VideoDetail> = withContext(io) {
        call { api.getVideoDetail(videoId) }.map { it.toDomain() }
    }

    override suspend fun getSimilar(videoId: String, limit: Int): ApiResult<List<VideoSummary>> =
        withContext(io) {
            call { api.getSimilar(videoId, limit) }.map { it.toDomain() }
        }

    override suspend fun checkLike(videoId: String): ApiResult<Boolean> = withContext(io) {
        call { api.checkLike(videoId) }.map { it.liked }
    }

    override suspend fun toggleLike(videoId: String): ApiResult<LikeState> = withContext(io) {
        call { api.toggleLike(videoId) }.map { LikeState(liked = it.liked, likeCount = it.likeCount) }
    }

    override suspend fun checkAccess(videoId: String): ApiResult<VideoAccess> = withContext(io) {
        call { api.checkAccess(videoId) }.map { it.toDomain() }
    }

    override suspend fun reactVideo(videoId: String, emoji: String): ApiResult<VideoReactionState> =
        withContext(io) {
            call { api.reactVideo(videoId, VideoReactionReq(emoji)) }
                .map { VideoReactionState(it.reactionsCounts.filterValues { c -> c > 0 }, it.myReactions.toSet()) }
        }

    override suspend fun unreactVideo(videoId: String, emoji: String): ApiResult<VideoReactionState> =
        withContext(io) {
            call { api.unreactVideo(videoId, VideoReactionReq(emoji)) }
                .map { VideoReactionState(it.reactionsCounts.filterValues { c -> c > 0 }, it.myReactions.toSet()) }
        }

    override suspend fun tipVideo(
        videoId: String,
        amountCents: Int,
        paymentMethodId: String?,
    ): ApiResult<VideoTipState> = withContext(io) {
        call { api.tipVideo(videoId, VideoTipReq(amountCents = amountCents, paymentMethodId = paymentMethodId)) }
            .map { VideoTipState(amountCents = it.amountCents, tipTotalCents = it.tipTotalCents) }
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
