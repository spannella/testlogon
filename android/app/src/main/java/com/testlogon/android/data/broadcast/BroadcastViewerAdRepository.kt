package com.testlogon.android.data.broadcast

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.ads.CtaAction
import com.testlogon.android.data.ads.toCtaActions
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
        slotType: String = BroadcastAdEvents.SLOT_PRE_ROLL,
    ): ApiResult<Unit>

    /** ADV2-103 — read the current live ad-break state (drives the viewer interrupt poll). */
    suspend fun adBreakState(sessionId: String): ApiResult<BroadcastAdBreakState>

    /** ADV2-101 — serve a per-viewer mid-roll creative during an active break (mints the ad_click_id). */
    suspend fun serveMidRoll(sessionId: String): ApiResult<BroadcastMidRollServe>
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
    /** ADV2-207 (F2) — structured click-through CTA targets served with this broadcast ad (AdCtaBar). */
    val ctas: List<CtaAction> = emptyList(),
)

/** ADV2-103 — the poll-detectable live ad-break state (domain projection of AdBreakStateOut). */
data class BroadcastAdBreakState(
    val adBreakActive: Boolean,
    val adBreakStartedAt: Long?,
    val remainingSeconds: Int,
    val totalAdBreaks: Int,
    val skipAfterSeconds: Int,
)

/** ADV2-101 — a per-viewer mid-roll serve: the creative (reusing [BroadcastPreRoll]) + ad-free + remaining. */
data class BroadcastMidRollServe(
    val ad: BroadcastPreRoll?,
    val adFree: Boolean,
    val remainingSeconds: Int,
)

object BroadcastAdEvents {
    const val IMPRESSION = "impression"
    const val COMPLETE = "complete"
    const val SKIP = "skip"

    /** Track slot_type values the backend maps to the charge surface (broadcast_preroll / broadcast_midroll). */
    const val SLOT_PRE_ROLL = "pre_roll"
    const val SLOT_MID_ROLL = "mid_roll"
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
        slotType: String,
    ): ApiResult<Unit> = withContext(io) {
        if (creativeId.isBlank() || adClickId.isBlank()) return@withContext ApiResult.Success(Unit)
        try {
            api.trackAdEvent(
                sessionId = sessionId,
                creativeId = creativeId,
                event = event,
                adClickId = adClickId,
                slotType = slotType,
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

    override suspend fun adBreakState(sessionId: String): ApiResult<BroadcastAdBreakState> = withContext(io) {
        try {
            ApiResult.Success(api.adBreakState(sessionId).toDomain())
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun serveMidRoll(sessionId: String): ApiResult<BroadcastMidRollServe> = withContext(io) {
        try {
            ApiResult.Success(api.serveMidRoll(sessionId).toDomain())
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
        ctas = ctas.toCtaActions(),
    )
}

private fun BroadcastAdBreakStateDto.toDomain(): BroadcastAdBreakState = BroadcastAdBreakState(
    adBreakActive = adBreakActive,
    adBreakStartedAt = adBreakStartedAt,
    remainingSeconds = remainingSeconds.coerceAtLeast(0),
    totalAdBreaks = totalAdBreaks,
    skipAfterSeconds = skipAfterSeconds.coerceAtLeast(0),
)

private fun BroadcastMidRollServeDto.toDomain(): BroadcastMidRollServe = BroadcastMidRollServe(
    ad = midRoll?.takeIf { it.creativeId.isNotBlank() }?.toDomain(),
    adFree = adFree,
    remainingSeconds = remainingSeconds.coerceAtLeast(0),
)

private fun BroadcastMidRollDto.toDomain(): BroadcastPreRoll {
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
        ctas = ctas.toCtaActions(),
    )
}
