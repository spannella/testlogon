package com.testlogon.android.data.marketing.campaigns

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
 * Data layer over [MarketingCampaignsApi] for OFBiz Marketing CAMPAIGNS.
 *
 * Degrade-on-404: the backend read endpoints are ungated, but when the MARKETING_CAMPAIGNS_ENABLED
 * flag is off the WHOLE router may 404. Reads therefore fold a 404 into an honest-EMPTY result so the
 * UI shows an empty hub rather than an error; mutations surface the failure (Failure) so the user sees
 * "not enabled". Every call is wrapped in [ApiResult].
 */
interface MarketingCampaignsRepository {
    suspend fun loadCampaigns(): ApiResult<MarketingCampaignPage>
    suspend fun createCampaign(
        name: String,
        objective: MarketingMath.CampaignObjective,
        budgetCents: Long,
    ): ApiResult<MarketingCampaign>
    suspend fun transition(campaignId: String, target: MarketingMath.CampaignStatus): ApiResult<Unit>
    suspend fun send(campaignId: String): ApiResult<CampaignSendResult>

    suspend fun loadLists(): ApiResult<List<ContactList>>
    suspend fun createList(name: String, description: String?): ApiResult<ContactList>
    suspend fun loadListMembers(listId: String): ApiResult<List<ContactListMember>>

    suspend fun loadSegments(): ApiResult<List<PartySegment>>
    suspend fun getSegment(segmentId: String): ApiResult<PartySegment>
}

/** Send result surfaced to the UI. */
data class CampaignSendResult(
    val sentCount: Int,
    val skippedCount: Int,
)

@Singleton
class MarketingCampaignsRepositoryImpl @Inject constructor(
    private val api: MarketingCampaignsApi,
    private val errorParser: ApiErrorParser,
) : MarketingCampaignsRepository {

    private val io: CoroutineDispatcher = Dispatchers.IO

    override suspend fun loadCampaigns(): ApiResult<MarketingCampaignPage> = withContext(io) {
        readOrEmpty(MarketingCampaignPage(emptyList(), null)) {
            api.listCampaigns(limit = PAGE_SIZE).toDomain()
        }
    }

    override suspend fun createCampaign(
        name: String,
        objective: MarketingMath.CampaignObjective,
        budgetCents: Long,
    ): ApiResult<MarketingCampaign> = withContext(io) {
        call {
            api.createCampaign(
                MarketingCampaignCreateInDto(
                    name = name.trim(),
                    objective = objective.wire,
                    budgetCents = budgetCents,
                ),
            ).toDomain()
        }
    }

    override suspend fun transition(
        campaignId: String,
        target: MarketingMath.CampaignStatus,
    ): ApiResult<Unit> = withContext(io) {
        call {
            api.transitionCampaign(campaignId, CampaignTransitionInDto(targetStatus = target.wire))
            Unit
        }
    }

    override suspend fun send(campaignId: String): ApiResult<CampaignSendResult> = withContext(io) {
        call {
            val r = api.sendCampaign(campaignId)
            CampaignSendResult(sentCount = r.sentCount, skippedCount = r.skippedCount)
        }
    }

    override suspend fun loadLists(): ApiResult<List<ContactList>> = withContext(io) {
        readOrEmpty(emptyList()) { api.listContactLists().map { it.toDomain() } }
    }

    override suspend fun createList(name: String, description: String?): ApiResult<ContactList> =
        withContext(io) {
            call {
                api.createContactList(
                    ContactListCreateInDto(
                        name = name.trim(),
                        description = description?.trim()?.takeIf { it.isNotEmpty() },
                    ),
                ).toDomain()
            }
        }

    override suspend fun loadListMembers(listId: String): ApiResult<List<ContactListMember>> =
        withContext(io) {
            readOrEmpty(emptyList()) {
                api.listContactListMembers(listId).map { it.toDomain() }
            }
        }

    override suspend fun loadSegments(): ApiResult<List<PartySegment>> = withContext(io) {
        readOrEmpty(emptyList()) { api.listSegments().map { it.toDomain() } }
    }

    override suspend fun getSegment(segmentId: String): ApiResult<PartySegment> = withContext(io) {
        call { api.getSegment(segmentId).toDomain() }
    }

    /**
     * Runs an idempotent read, folding a 404 (module disabled / not found) into [empty] so the hub
     * degrades to an honest-empty state instead of an error.
     */
    private suspend fun <T> readOrEmpty(empty: T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(empty) else ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private suspend fun <T> call(block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        ApiResult.Failure(errorParser.from(e))
    } catch (e: com.squareup.moshi.JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        private const val PAGE_SIZE = 50
        private const val HTTP_NOT_FOUND = 404
    }
}
