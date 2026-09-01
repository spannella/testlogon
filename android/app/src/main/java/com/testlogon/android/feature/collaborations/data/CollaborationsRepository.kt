package com.testlogon.android.feature.collaborations.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.collaborations.CollabContent
import com.testlogon.android.core.model.collaborations.CollabDispute
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.CollabSplitRecordModel
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.CollaborationSettings
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollabDisputeIn
import com.testlogon.android.core.network.collaborations.CollabDisputeResolveIn
import com.testlogon.android.core.network.collaborations.CollaborationCounterIn
import com.testlogon.android.core.network.collaborations.CollaborationSettingsIn
import com.testlogon.android.core.network.collaborations.CollaborationTerminateIn
import com.testlogon.android.core.network.collaborations.CollaborationsApi
import com.testlogon.android.core.network.error.ApiErrorParser
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-358 / PAR-04 / FIN-011 - data layer for the collaborations surface, over the [CollaborationsApi].
 *
 * The LIST is Paging 3: [listPager] wraps the network [CollaborationsPagingSource] in a [Pager]. The non-paged
 * reads (detail / split history / revisions / disputes / revenue records / settings) map the RAW DTO to the
 * core-model domain and fold into [ApiResult] via [call] (mirrors AND-356 SyndicateRepository).
 *
 * PAR-04 adds the STATE-only deal-action mutations. FIN-011 adds the REVENUE-SPLITTING + DISPUTE + SETTINGS
 * surface: disputes (list/file/resolve), revenue reads (split records + assigned content), and settings
 * (get/put). The dispute + settings mutations are agreement/state only (money movement is server-side in the
 * revenue-event path) so they are NOT routed through BillingAuthorizer.
 *
 * DEGRADE-ON-404: the READ helpers ([getDisputes] / [getSplitRecords] / [getContent] / [getSettings]) return an
 * honest-empty / default value on a 404 (the surface simply shows nothing yet); the MUTATIONS surface the
 * error to the caller.
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed cache this wave; the detail keeps an in-memory
 * last-good snapshot with an isStale flag.
 */
interface CollaborationsRepository {

    /** A cold [PagingData] stream of the viewer's collaborations; re-collect to refresh. */
    fun listPager(): Flow<PagingData<Collaboration>>

    /** GET a single collaboration by id, mapped (status kept raw + parsed; split percents kept verbatim). */
    suspend fun getCollaboration(collabId: String): ApiResult<Collaboration>

    /**
     * GET the OPTIONAL split-history distributions (per-party amount_cents), flattened across records. The
     * detail screen tolerates a failure here (falls back to an empty list).
     */
    suspend fun getSplits(collabId: String): ApiResult<List<SplitDistribution>>

    /**
     * GET the OPTIONAL negotiation revision history (prior proposed splits). The detail screen tolerates a
     * failure here (falls back to an empty list).
     */
    suspend fun getRevisions(collabId: String): ApiResult<List<CollabRevision>>

    /** POST accept the current proposal; returns the updated collaboration. State-only. */
    suspend fun accept(collabId: String): ApiResult<Collaboration>

    /** POST reject the current proposal; returns the updated collaboration. State-only. */
    suspend fun reject(collabId: String): ApiResult<Collaboration>

    /** POST a counter-offer ([splitPct] = the initiator's new percent, 1..99); returns the updated collab. */
    suspend fun counter(collabId: String, splitPct: Int): ApiResult<Collaboration>

    /** POST cancel the pending request (initiator only); returns the updated collaboration. State-only. */
    suspend fun cancel(collabId: String): ApiResult<Collaboration>

    /** POST terminate the active agreement (optional [reason]); returns the updated collaboration. */
    suspend fun terminate(collabId: String, reason: String?): ApiResult<Collaboration>

    // ---- FIN-011: revenue reads (degrade-on-404 -> empty) -----------------------------------------------

    /** GET the executed split records (revenue view). A 404 degrades to an empty list. */
    suspend fun getSplitRecords(collabId: String): ApiResult<List<CollabSplitRecordModel>>

    /** GET the content assigned to the collaboration. A 404 degrades to an empty list. */
    suspend fun getContent(collabId: String): ApiResult<List<CollabContent>>

    // ---- FIN-011: disputes ------------------------------------------------------------------------------

    /** GET the disputes for the collaboration (optionally filtered by [status]). A 404 degrades to empty. */
    suspend fun getDisputes(collabId: String, status: String? = null): ApiResult<List<CollabDispute>>

    /** POST file a dispute on a split record. Returns the resulting dispute_status. */
    suspend fun fileDispute(
        collabId: String,
        splitId: String,
        reason: String,
        proposedSplit: Map<String, Int>? = null,
    ): ApiResult<String>

    /** POST resolve an open dispute (accept/reject the proposed re-split). Returns the resulting status. */
    suspend fun resolveDispute(
        collabId: String,
        disputeId: String,
        resolution: String,
        accept: Boolean,
    ): ApiResult<String>

    // ---- FIN-011: inbound-request settings --------------------------------------------------------------

    /** GET the viewer's inbound-collaboration settings. A 404 degrades to the domain defaults. */
    suspend fun getSettings(): ApiResult<CollaborationSettings>

    /** PUT a partial update of the viewer's inbound-collaboration settings. Returns the merged settings. */
    suspend fun updateSettings(
        acceptingRequests: Boolean? = null,
        minSplitPct: Int? = null,
        allowedContentTypes: List<String>? = null,
        autoExpireDays: Int? = null,
    ): ApiResult<CollaborationSettings>

    companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 6
    }
}

@Singleton
class CollaborationsRepositoryImpl @Inject constructor(
    private val api: CollaborationsApi,
    private val errorParser: ApiErrorParser,
) : CollaborationsRepository {

    override fun listPager(): Flow<PagingData<Collaboration>> =
        Pager(
            config = pagingConfig(),
            pagingSourceFactory = { CollaborationsPagingSource(api) },
        ).flow

    override suspend fun getCollaboration(collabId: String): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.getCollaboration(collabId).toDomain() }
        }

    override suspend fun getSplits(collabId: String): ApiResult<List<SplitDistribution>> =
        withContext(Dispatchers.IO) {
            call { api.getSplits(collabId).toDistributions() }
        }

    override suspend fun getRevisions(collabId: String): ApiResult<List<CollabRevision>> =
        withContext(Dispatchers.IO) {
            call { api.getRevisions(collabId).toRevisions() }
        }

    override suspend fun accept(collabId: String): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.acceptCollaboration(collabId).toDomain() }
        }

    override suspend fun reject(collabId: String): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.rejectCollaboration(collabId).toDomain() }
        }

    override suspend fun counter(collabId: String, splitPct: Int): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.counterCollaboration(collabId, CollaborationCounterIn(counterSplitPct = splitPct)).toDomain() }
        }

    override suspend fun cancel(collabId: String): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.cancelCollaboration(collabId).toDomain() }
        }

    override suspend fun terminate(collabId: String, reason: String?): ApiResult<Collaboration> =
        withContext(Dispatchers.IO) {
            call { api.terminateCollaboration(collabId, CollaborationTerminateIn(reason = reason)).toDomain() }
        }

    override suspend fun getSplitRecords(collabId: String): ApiResult<List<CollabSplitRecordModel>> =
        withContext(Dispatchers.IO) {
            callDegrading(onNotFound = { emptyList() }) { api.getSplits(collabId).toRecords() }
        }

    override suspend fun getContent(collabId: String): ApiResult<List<CollabContent>> =
        withContext(Dispatchers.IO) {
            callDegrading(onNotFound = { emptyList() }) { api.listContent(collabId).toContent() }
        }

    override suspend fun getDisputes(collabId: String, status: String?): ApiResult<List<CollabDispute>> =
        withContext(Dispatchers.IO) {
            callDegrading(onNotFound = { emptyList() }) { api.listDisputes(collabId, status).toDisputes() }
        }

    override suspend fun fileDispute(
        collabId: String,
        splitId: String,
        reason: String,
        proposedSplit: Map<String, Int>?,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call {
            val ack = api.fileDispute(collabId, splitId, CollabDisputeIn(reason = reason, proposedSplit = proposedSplit))
            ack.disputeStatus ?: ack.status ?: "disputed"
        }
    }

    override suspend fun resolveDispute(
        collabId: String,
        disputeId: String,
        resolution: String,
        accept: Boolean,
    ): ApiResult<String> = withContext(Dispatchers.IO) {
        call {
            val ack = api.resolveDispute(collabId, disputeId, CollabDisputeResolveIn(resolution = resolution, accept = accept))
            ack.status ?: "resolved"
        }
    }

    override suspend fun getSettings(): ApiResult<CollaborationSettings> =
        withContext(Dispatchers.IO) {
            callDegrading(onNotFound = { CollaborationSettings() }) { api.getSettings().toDomain() }
        }

    override suspend fun updateSettings(
        acceptingRequests: Boolean?,
        minSplitPct: Int?,
        allowedContentTypes: List<String>?,
        autoExpireDays: Int?,
    ): ApiResult<CollaborationSettings> = withContext(Dispatchers.IO) {
        call {
            api.updateSettings(
                CollaborationSettingsIn(
                    acceptingRequests = acceptingRequests,
                    minSplitPct = minSplitPct,
                    allowedContentTypes = allowedContentTypes,
                    autoExpireDays = autoExpireDays,
                ),
            ).toDomain()
        }
    }

    private fun pagingConfig() = PagingConfig(
        pageSize = CollaborationsRepository.PAGE_SIZE,
        initialLoadSize = CollaborationsRepository.PAGE_SIZE,
        prefetchDistance = CollaborationsRepository.PREFETCH_DISTANCE,
        enablePlaceholders = false,
    )

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status, so a
     * 401 surfaces as Failure(status=401) for the SessionExpired mapping); malformed JSON -> Failure; transport
     * failures -> NetworkError. JsonEncodingException precedes IOException (it is a subtype). Cancellation is
     * re-thrown. Mirrors AND-356.
     */
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

    /**
     * Like [call] but DEGRADES a 404 to a Success carrying [onNotFound] (the surface is simply empty / default
     * on a not-yet-provisioned collaboration). All other outcomes match [call] (a 401 still surfaces as a
     * Failure so the SessionExpired mapping fires).
     */
    private suspend fun <T> callDegrading(onNotFound: () -> T, block: suspend () -> T): ApiResult<T> = try {
        ApiResult.Success(block())
    } catch (e: CancellationException) {
        throw e
    } catch (e: HttpException) {
        if (e.code() == HTTP_NOT_FOUND) ApiResult.Success(onNotFound()) else ApiResult.Failure(errorParser.from(e))
    } catch (e: JsonEncodingException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: JsonDataException) {
        ApiResult.Failure(errorParser.fromThrowable(e))
    } catch (e: IOException) {
        ApiResult.NetworkError(e, isTimeout = e is SocketTimeoutException)
    }

    private companion object {
        const val HTTP_NOT_FOUND = 404
    }
}
