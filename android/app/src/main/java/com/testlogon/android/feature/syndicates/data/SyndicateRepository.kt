package com.testlogon.android.feature.syndicates.data

import androidx.paging.Pager
import androidx.paging.PagingConfig
import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.model.syndicates.RegistrationResult
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateListItem
import com.testlogon.android.core.model.syndicates.SyndicateMember
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.syndicates.SyndicateApi
import com.testlogon.android.core.network.syndicates.SyndicateCreateIn
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingRegisterIn
import com.testlogon.android.core.network.syndicates.SyndicatePostCreateIn
import com.testlogon.android.data.auth.AuthStateStore
import com.squareup.moshi.JsonDataException
import com.squareup.moshi.JsonEncodingException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import retrofit2.HttpException
import java.io.IOException
import java.net.SocketTimeoutException
import javax.inject.Inject
import javax.inject.Singleton

/**
 * AND-356 - READ-ONLY data layer for the syndicate overview surface, over the [SyndicateApi].
 *
 * The non-paged reads (overview / treasury summary / revenue-split) map the RAW DTO to the core-model
 * domain and fold into [ApiResult] via [call] (mirrors AND-355 GroupsRepository). The FEED and the LEDGER
 * are Paging 3: [feedPager] / [treasuryLedgerPager] wrap the network PagingSources in a [Pager] (re-collect
 * to refresh, re-anchoring at the first page).
 *
 * The overview derives the role badge (admin_user_id == the viewer's own user id from [AuthStateStore]) at
 * the mapper boundary. This ticket performs NO mutations (join / propose / payout are downstream / OUT OF
 * SCOPE).
 *
 * ROOM CACHE DEFERRED: there is intentionally NO Room-backed cache and NO Room migration this wave. The
 * stale-while-offline snapshot is kept IN-MEMORY in the ViewModel (an isStale flag), NOT on disk;
 * persistence across process death is DEFERRED to a later ticket.
 */
interface SyndicateRepository {

    /** Batch-7 - GET the caller's syndicates (bare-array list -> mapped). Idempotent GET. */
    suspend fun listMySyndicates(): ApiResult<List<SyndicateListItem>>

    /**
     * Batch-7 - POST a new syndicate (creator becomes admin). On success returns the created
     * [SyndicateListItem]; a 4xx surfaces as Failure; transport failures -> NetworkError.
     */
    suspend fun createSyndicate(name: String, description: String?): ApiResult<SyndicateListItem>

    /** GET the syndicate overview / profile, mapped (role badge derived from the viewer's user id). */
    suspend fun getOverview(syndicateId: String): ApiResult<SyndicateOverview>

    /** GET the treasury summary (balance + totals), mapped. The ledger pages via [treasuryLedgerPager]. */
    suspend fun getTreasury(syndicateId: String): ApiResult<TreasurySummary>

    /** GET the revenue-split policy, mapped (mode via SplitMode.from; weightSumOk computed in-domain). */
    suspend fun getRevenueSplit(syndicateId: String): ApiResult<RevenueSplitPolicy>

    /** A cold [PagingData] stream of the reverse-chronological feed; re-collect to refresh. */
    fun feedPager(syndicateId: String): Flow<PagingData<SyndicateFeedItem>>

    /** A cold [PagingData] stream of the treasury ledger; re-collect to refresh. */
    fun treasuryLedgerPager(syndicateId: String): Flow<PagingData<TreasuryEntry>>

    /**
     * AND-357 - GET the syndicate's open-licensing content, mapped. NOT paginated (a single bounded {items}
     * page), so this returns the full list in one [ApiResult].
     */
    suspend fun getOpenLicensingContent(syndicateId: String): ApiResult<List<OpenLicensingContent>>

    /**
     * AND-357 - register [contentId] of [contentType] for open licensing (a CSRF-protected mutation). On
     * success returns the [RegistrationResult] receipt; the caller REFETCHES the list (does NOT optimistically
     * prepend). A 422 surfaces as Failure (status=422) carrying the raw detail for per-field mapping.
     */
    suspend fun registerOpenLicensing(
        syndicateId: String,
        contentId: String,
        contentType: LicensingContentType,
    ): ApiResult<RegistrationResult>

    /** Batch-9 (#12) - POST a new syndicate feed post (text + optional single image). */
    suspend fun createPost(
        syndicateId: String,
        text: String,
        imageUrl: String? = null,
        poll: com.testlogon.android.core.network.poll.PollInputDto? = null,
    ): ApiResult<SyndicateFeedItem>

    /** Batch-9 (#12) - GET the syndicate member roster (bare array -> mapped). */
    suspend fun listMembers(syndicateId: String): ApiResult<List<SyndicateMember>>

    companion object {
        const val PAGE_SIZE = 20
        const val PREFETCH_DISTANCE = 6
    }
}

@Singleton
class SyndicateRepositoryImpl @Inject constructor(
    private val api: SyndicateApi,
    private val authStateStore: AuthStateStore,
    private val errorParser: ApiErrorParser,
) : SyndicateRepository {

    override suspend fun listMySyndicates(): ApiResult<List<SyndicateListItem>> =
        withContext(Dispatchers.IO) {
            call { api.listMySyndicates().map { it.toDomain() } }
        }

    override suspend fun createSyndicate(
        name: String,
        description: String?,
    ): ApiResult<SyndicateListItem> = withContext(Dispatchers.IO) {
        call {
            api.createSyndicate(
                SyndicateCreateIn(name = name, description = description?.takeIf { it.isNotBlank() }),
            ).toListItem()
        }
    }

    override suspend fun getOverview(syndicateId: String): ApiResult<SyndicateOverview> =
        withContext(Dispatchers.IO) {
            val me = authStateStore.userSub.first()?.takeIf { it.isNotBlank() }
            call { api.getProfile(syndicateId).toDomain(currentUserId = me) }
        }

    override suspend fun getTreasury(syndicateId: String): ApiResult<TreasurySummary> =
        withContext(Dispatchers.IO) {
            call { api.getTreasury(syndicateId).toSummary() }
        }

    override suspend fun getRevenueSplit(syndicateId: String): ApiResult<RevenueSplitPolicy> =
        withContext(Dispatchers.IO) {
            call { api.getRevenueSplit(syndicateId).toDomain() }
        }

    override fun feedPager(syndicateId: String): Flow<PagingData<SyndicateFeedItem>> =
        Pager(
            config = pagingConfig(),
            pagingSourceFactory = { SyndicateFeedPagingSource(api, syndicateId) },
        ).flow

    override fun treasuryLedgerPager(syndicateId: String): Flow<PagingData<TreasuryEntry>> =
        Pager(
            config = pagingConfig(),
            pagingSourceFactory = { TreasuryLedgerPagingSource(api, syndicateId) },
        ).flow

    override suspend fun getOpenLicensingContent(
        syndicateId: String,
    ): ApiResult<List<OpenLicensingContent>> = withContext(Dispatchers.IO) {
        call { api.getOpenLicensingContent(syndicateId).items.map { it.toDomain() } }
    }

    override suspend fun registerOpenLicensing(
        syndicateId: String,
        contentId: String,
        contentType: LicensingContentType,
    ): ApiResult<RegistrationResult> = withContext(Dispatchers.IO) {
        call {
            api.registerOpenLicensing(
                syndicateId = syndicateId,
                body = SyndicateOpenLicensingRegisterIn(
                    contentId = contentId,
                    contentType = contentType.wire,
                ),
            ).toDomain()
        }
    }

    override suspend fun createPost(
        syndicateId: String,
        text: String,
        imageUrl: String?,
        poll: com.testlogon.android.core.network.poll.PollInputDto?,
    ): ApiResult<SyndicateFeedItem> = withContext(Dispatchers.IO) {
        call {
            api.createPost(
                syndicateId,
                SyndicatePostCreateIn(
                    text = text,
                    imageUrl = imageUrl?.takeIf { it.isNotBlank() },
                    poll = poll,
                ),
            ).toDomain()
        }
    }

    override suspend fun listMembers(syndicateId: String): ApiResult<List<SyndicateMember>> =
        withContext(Dispatchers.IO) {
            call { api.listMembers(syndicateId).map { it.toDomain() } }
        }

    private fun pagingConfig() = PagingConfig(
        pageSize = SyndicateRepository.PAGE_SIZE,
        initialLoadSize = SyndicateRepository.PAGE_SIZE,
        prefetchDistance = SyndicateRepository.PREFETCH_DISTANCE,
        enablePlaceholders = false,
    )

    /**
     * Folds a block into [ApiResult]. HTTP errors -> Failure (via [ApiErrorParser], preserving the status,
     * so a 403 surfaces as Failure(status=403) for the NotMember mapping); malformed JSON -> Failure;
     * transport failures -> NetworkError. JsonEncodingException precedes IOException (it is a subtype).
     * Cancellation is re-thrown. Mirrors AND-355.
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
