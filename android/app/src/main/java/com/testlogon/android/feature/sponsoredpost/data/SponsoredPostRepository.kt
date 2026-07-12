package com.testlogon.android.feature.sponsoredpost.data

import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostApi
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostProposalReq
import com.testlogon.android.core.network.sponsoredpost.SponsoredPostRejectReq
import com.testlogon.android.data.ads.AdEvent
import com.testlogon.android.data.ads.AdTrackApi
import com.testlogon.android.data.ads.AdTrackEventDto
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * ADV2-E4 (F4) / ADV2-407..409 — data layer for the sponsored-as-creator (paid partnership) surface.
 *
 * WRITE: the advertiser [createProposal] (ADV2-407); the creator [approve] / [reject] from the review queue
 * (ADV2-408). READ: [inbox] (creator's pending queue) + [outbox] (advertiser's own). All folded into
 * [ApiResult] via [call]; the mutations are NON-idempotent (the VM owns confirm-then-POST, in-flight gating
 * and the NO-auto-retry policy). Distinct from the ADS-013 brand-deal [SponsorshipRepository].
 *
 * BILLING (ADV2-409): [fireImpression] / [fireClick] lazy-mint the per-viewer ad-click for a published
 * paid_partnership post ([placement]) then round-trip the handle to POST ui/ads/track so the advertiser is
 * billed (funds-guarded, idempotent) + the creator credited the placement share. Best-effort /
 * fire-and-forget — a failed billing beacon NEVER surfaces to the viewer or blocks the normal post UI.
 */
interface SponsoredPostRepository {

    suspend fun createProposal(req: SponsoredPostProposalReq): ApiResult<SponsoredPostProposal>

    suspend fun inbox(): ApiResult<List<SponsoredPostProposal>>

    suspend fun outbox(): ApiResult<List<SponsoredPostProposal>>

    suspend fun approve(proposalId: String): ApiResult<SponsoredPostApproveResult>

    suspend fun reject(proposalId: String, reason: String): ApiResult<Unit>

    /** GET the per-viewer billing handle for a published paid_partnership post. Idempotent. */
    suspend fun placement(postId: String): ApiResult<SponsoredPostPlacement>

    /** Best-effort: mint (if needed) + fire an IMPRESSION track for a paid_partnership post. */
    suspend fun fireImpression(postId: String)

    /** Best-effort: mint (if needed) + fire a CLICK track for a paid_partnership post. */
    suspend fun fireClick(postId: String)
}

@Singleton
class SponsoredPostRepositoryImpl @Inject constructor(
    private val api: SponsoredPostApi,
    private val trackApi: AdTrackApi,
    private val errorParser: ApiErrorParser,
) : SponsoredPostRepository {

    override suspend fun createProposal(req: SponsoredPostProposalReq): ApiResult<SponsoredPostProposal> =
        withContext(Dispatchers.IO) { call { api.createProposal(req).toDomain() } }

    override suspend fun inbox(): ApiResult<List<SponsoredPostProposal>> =
        withContext(Dispatchers.IO) { call { api.inbox().proposals.map { it.toDomain() } } }

    override suspend fun outbox(): ApiResult<List<SponsoredPostProposal>> =
        withContext(Dispatchers.IO) { call { api.outbox().proposals.map { it.toDomain() } } }

    override suspend fun approve(proposalId: String): ApiResult<SponsoredPostApproveResult> =
        withContext(Dispatchers.IO) { call { api.approve(proposalId).toDomain() } }

    override suspend fun reject(proposalId: String, reason: String): ApiResult<Unit> =
        withContext(Dispatchers.IO) { call { api.reject(proposalId, SponsoredPostRejectReq(reason = reason)); Unit } }

    override suspend fun placement(postId: String): ApiResult<SponsoredPostPlacement> =
        withContext(Dispatchers.IO) { call { api.placement(postId).toDomain() } }

    override suspend fun fireImpression(postId: String) = fire(postId, AdEvent.IMPRESSION)

    override suspend fun fireClick(postId: String) = fire(postId, AdEvent.CLICK)

    /**
     * Mint (idempotent per viewer+post) then POST the ad event. Swallows every failure — billing must never
     * disturb the normal creator-post experience. A non-billable placement (organic post / self-view / an
     * incomplete linkage) is a silent no-op.
     */
    private suspend fun fire(postId: String, event: AdEvent) {
        try {
            withContext(Dispatchers.IO) {
                val handle = api.placement(postId)
                if (!handle.billable) return@withContext
                val creative = handle.creativeId.orEmpty()
                val campaign = handle.campaignId.orEmpty()
                val account = handle.accountId.orEmpty()
                if (creative.isBlank() || campaign.isBlank() || account.isBlank()) return@withContext
                trackApi.track(
                    AdTrackEventDto(
                        event = event.wire,
                        creativeId = creative,
                        campaignId = campaign,
                        accountId = account,
                        surface = SURFACE,
                        slotType = SURFACE,
                        contentId = postId,
                        creatorId = handle.contentOwnerId.orEmpty(),
                        adClickId = handle.adClickId,
                    )
                )
            }
        } catch (e: CancellationException) {
            throw e
        } catch (_: Exception) {
            // best-effort beacon: never surface a billing failure to the viewer.
        }
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        // Must match backend sponsored_creator_posts.SURFACE (NOT in track_ad_event's charge-skip set).
        const val SURFACE = "sponsored_creator_post"
    }
}
