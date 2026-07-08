package com.testlogon.android.data.ads

import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.data.feed.SponsoredInfo
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/** ADV-106 — the two ad events the newsfeed sponsored card fires. */
enum class AdEvent(val wire: String) {
    IMPRESSION("impression"),
    CLICK("click"),
}

/**
 * ADV-106 — best-effort ad-event tracking for served sponsored units.
 *
 * Impression fires when the sponsored card becomes viewport-visible; click fires on the CTA/card tap.
 * Tracking is fire-and-forget from the caller's perspective (a failed beacon must never surface an
 * error to the viewer or block the CTA), so failures fold into [ApiResult] and are swallowed upstream.
 */
interface AdTrackRepository {
    suspend fun track(event: AdEvent, ad: SponsoredInfo): ApiResult<Unit>

    /**
     * ADV2-207 (F2) — record a structured CTA tap (POST /ui/ads/cta-click). The backend charges CPC to
     * the advertiser (funds-guarded, idempotent per {ad_click_id}#cta#{cta_type}) EXCEPT tip. Best-effort
     * / fire-and-forget: a failed beacon never surfaces to the viewer or blocks the CTA navigation.
     */
    suspend fun clickCta(adClickId: String, action: CtaAction): ApiResult<Unit>
}

@Singleton
class AdTrackRepositoryImpl @Inject constructor(
    private val api: AdTrackApi,
    private val errorParser: ApiErrorParser,
) : AdTrackRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun track(event: AdEvent, ad: SponsoredInfo): ApiResult<Unit> = withContext(io) {
        // The endpoint requires non-empty creative/campaign/account/surface/slot/content/creator; the
        // mapper already fills the surface/slot/creator/content defaults, so guard only the ids that
        // uniquely identify the paid unit.
        if (ad.creativeId.isBlank() || ad.campaignId.isBlank() || ad.accountId.isBlank()) {
            return@withContext ApiResult.Success(Unit)
        }
        val body = AdTrackEventDto(
            event = event.wire,
            creativeId = ad.creativeId,
            campaignId = ad.campaignId,
            accountId = ad.accountId,
            surface = ad.surface,
            slotType = ad.slotType,
            contentId = ad.contentId,
            creatorId = ad.creatorId,
            adClickId = ad.adClickId,
        )
        try {
            api.track(body)
            ApiResult.Success(Unit)
        } catch (e: CancellationException) {
            throw e
        } catch (e: HttpException) {
            ApiResult.Failure(errorParser.from(e))
        } catch (e: IOException) {
            ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
        }
    }

    override suspend fun clickCta(adClickId: String, action: CtaAction): ApiResult<Unit> = withContext(io) {
        if (adClickId.isBlank()) return@withContext ApiResult.Success(Unit)
        try {
            api.ctaClick(
                CtaClickDto(
                    adClickId = adClickId,
                    ctaType = action.ctaType.wire,
                    targetId = action.targetId,
                )
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
