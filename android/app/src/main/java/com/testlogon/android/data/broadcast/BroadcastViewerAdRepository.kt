package com.testlogon.android.data.broadcast

import com.testlogon.android.core.model.ApiResult
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
 * ADV FEATURE 1 — VIEWER broadcast pre-roll data layer over [BroadcastViewerAdApi].
 *
 * Kept SEPARATE from the shared [BroadcastRepository] (and its fakes / contract tests) — the same
 * convention AND-309..316 followed for the host control planes. [adJoin] resolves the served pre-roll +
 * ad-free flag; [track] is a best-effort fire-and-forget beacon (a failed impression/complete must never
 * block or crash the viewer) that FOLDS transport/HTTP failures into an ignored [ApiResult].
 */
interface BroadcastViewerAdRepository {

    /** Viewer join that returns the pre-roll creative (if any) + whether the viewer is ad-free. */
    suspend fun adJoin(sessionId: String): ApiResult<BroadcastAdJoin>

    /**
     * Records an ad event (impression|complete|skip) for the served creative. [adClickId] is the key the
     * backend joins to the AdClicks row to charge the advertiser + credit the broadcaster. Best-effort.
     */
    suspend fun track(
        sessionId: String,
        creativeId: String,
        event: String,
        adClickId: String,
        viewTimeMs: Int = 0,
    ): ApiResult<Unit>
}

/** A served broadcast pre-roll + the ad-free flag (domain projection of BroadcastJoinOut). */
data class BroadcastAdJoin(
    val sessionId: String,
    val streamUrl: String?,
    val preRoll: BroadcastPreRoll?,
    val adFree: Boolean,
)

/** One served pre-roll creative. [isImage] = an image creative (no player media); else a video creative. */
data class BroadcastPreRoll(
    val creativeId: String,
    val isImage: Boolean,
    val imageUrl: String?,
    val videoUrl: String?,
    val ctaUrl: String?,
    val skipAfterSeconds: Int,
    val adClickId: String,
)

object BroadcastAdEvents {
    const val IMPRESSION = "impression"
    const val COMPLETE = "complete"
    const val SKIP = "skip"
}

@Singleton
class BroadcastViewerAdRepositoryImpl @Inject constructor(
    private val api: BroadcastViewerAdApi,
    private val errorParser: ApiErrorParser,
) : BroadcastViewerAdRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun adJoin(sessionId: String): ApiResult<BroadcastAdJoin> = withContext(io) {
        try {
            val dto = api.adJoin(sessionId)
            ApiResult.Success(dto.toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun track(
        sessionId: String,
        creativeId: String,
        event: String,
        adClickId: String,
        viewTimeMs: Int,
    ): ApiResult<Unit> = withContext(io) {
        if (creativeId.isBlank() || adClickId.isBlank()) return@withContext ApiResult.Success(Unit)
        try {
            api.trackAdEvent(
                sessionId = sessionId,
                creativeId = creativeId,
                event = event,
                adClickId = adClickId,
                viewTimeMs = viewTimeMs,
            )
            ApiResult.Success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }
}

private fun BroadcastAdJoinDto.toDomain(): BroadcastAdJoin = BroadcastAdJoin(
    sessionId = sessionId,
    streamUrl = streamUrl,
    preRoll = preRoll?.takeIf { it.creativeId.isNotBlank() }?.toDomain(),
    adFree = adFree,
)

private fun BroadcastPreRollDto.toDomain(): BroadcastPreRoll {
    val hasVideo = !videoUrl.isNullOrBlank()
    val isImage = format != "video" || !hasVideo
    return BroadcastPreRoll(
        creativeId = creativeId,
        isImage = isImage,
        imageUrl = imageUrl?.takeIf { it.isNotBlank() },
        videoUrl = videoUrl?.takeIf { it.isNotBlank() },
        ctaUrl = ctaUrl?.takeIf { it.isNotBlank() },
        skipAfterSeconds = skipAfterSeconds.coerceAtLeast(0),
        adClickId = adClickId,
    )
}
