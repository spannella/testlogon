package com.testlogon.android.feature.collaborations.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.collaborations.CollabRevision
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.network.collaborations.CollaborationCounterIn
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
 * AND-358 / PAR-04 - data layer for the collaborations surface, over the [CollaborationsApi].
 *
 * The LIST is Paging 3: [listPager] wraps the network [CollaborationsPagingSource] in a [Pager] (re-collect
 * to refresh, re-anchoring at the first page). The non-paged reads (detail / split history / revision history)
 * map the RAW DTO to the core-model domain and fold into [ApiResult] via [call] (mirrors AND-356
 * SyndicateRepository).
 *
 * PAR-04 adds the STATE-only deal-action mutations (accept / reject / counter / cancel / terminate). Each
 * returns the UPDATED [Collaboration] (the backend is the source of truth; the ViewModel reloads the detail).
 * These are NOT money-bearing (agreement state only) so they are NOT routed through BillingAuthorizer.
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed cache and NO Room migration this wave. The
 * stale-while-offline snapshot is kept IN-MEMORY in the detail ViewModel (an isStale flag), NOT on disk;
 * persistence across process death is DEFERRED to a later ticket.
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
}
