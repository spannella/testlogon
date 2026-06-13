package com.testlogon.android.feature.syndicates.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.network.syndicates.MemberEarningsOut
import com.testlogon.android.core.network.syndicates.SplitConfigOut
import com.testlogon.android.core.network.syndicates.SyndicateApi
import com.testlogon.android.core.network.syndicates.SyndicateFeedOut
import com.testlogon.android.core.network.syndicates.SyndicateProfileOut
import com.testlogon.android.core.network.syndicates.SyndicateTreasuryOut
import com.testlogon.android.data.auth.AuthStateStore
import com.testlogon.android.feature.syndicates.data.SyndicateRepository
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.flowOf
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-356 - in-memory fakes for the syndicate-overview unit tests.
 *
 * The app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [SyndicateApi] (no Moshi). Each call RECORDS its args / call-count BEFORE honouring a configured throw,
 * so a test can assert the @Path syndicateId was passed even when the call fails. Helper / recording names
 * are distinct and never shadow an interface method.
 */
class FakeSyndicateApi(
    var profile: () -> SyndicateProfileOut = {
        SyndicateProfileOut(id = "syn_1", name = "Aces", memberCount = 4, adminUserId = "usr_admin",
            currency = "usd", isMember = true)
    },
    var feed: () -> SyndicateFeedOut = { SyndicateFeedOut(posts = emptyList(), nextCursor = null) },
    var treasury: () -> SyndicateTreasuryOut = {
        SyndicateTreasuryOut(balanceCents = 150000, totalDepositedCents = 200000,
            totalDisbursedCents = 50000, currency = "usd", ledger = emptyList(), nextCursor = null)
    },
    var split: () -> SplitConfigOut = { SplitConfigOut(mode = "equal", platformFeeBps = 0) },
) : SyndicateApi {

    val profileSyndicateIds = mutableListOf<String>()
    val feedSyndicateIds = mutableListOf<String>()
    val treasurySyndicateIds = mutableListOf<String>()
    val splitSyndicateIds = mutableListOf<String>()

    override suspend fun getProfile(syndicateId: String): SyndicateProfileOut {
        profileSyndicateIds += syndicateId
        return profile()
    }

    override suspend fun getFeed(syndicateId: String, cursor: String?, page: Int?): SyndicateFeedOut {
        feedSyndicateIds += syndicateId
        return feed()
    }

    override suspend fun getTreasury(syndicateId: String, cursor: String?, page: Int?): SyndicateTreasuryOut {
        treasurySyndicateIds += syndicateId
        return treasury()
    }

    override suspend fun getRevenueSplit(syndicateId: String): SplitConfigOut {
        splitSyndicateIds += syndicateId
        return split()
    }

    override suspend fun getMyEarnings(syndicateId: String): MemberEarningsOut = MemberEarningsOut()

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 403 / 500). */
        fun http(status: Int): HttpException = HttpException(
            Response.error<Any>(status, """{"detail":"boom"}""".toResponseBody("application/json".toMediaType())),
        )
    }
}

/** A fake AuthStateStore exposing a fixed viewer user_id (distinct name from the groups-package fake). */
class FakeSyndicateAuthStore(viewerId: String?) : AuthStateStore {
    private val sub = MutableStateFlow(viewerId)
    override val userSub: StateFlow<String?> = sub.asStateFlow()
    override val isAuthenticated: StateFlow<Boolean> = MutableStateFlow(viewerId != null).asStateFlow()
    override suspend fun setAuthenticated(userSub: String) {
        sub.value = userSub
    }
    override suspend fun clear(reason: LogoutReason) {
        sub.value = null
    }
    override suspend fun lastLogoutReason(): LogoutReason? = null
    override suspend fun clearLogoutReason() = Unit
}

/**
 * A fake [SyndicateRepository] for the ViewModel tests (the VM does not page in these tests, so the paged
 * flows return empty PagingData). Each non-paged result is independently configurable; mutating helpers are
 * not present (the surface is READ-ONLY).
 */
class FakeSyndicateRepo(
    var overviewResult: ApiResult<SyndicateOverview> = ApiResult.Success(
        SyndicateOverview(id = "syn_1", name = "Aces", memberCount = 4, isAdmin = true,
            isMember = true, currency = "USD"),
    ),
    var treasuryResult: ApiResult<TreasurySummary> = ApiResult.Success(
        TreasurySummary(balanceCents = 150000, depositedCents = 200000, disbursedCents = 50000,
            currency = "USD"),
    ),
    var splitResult: ApiResult<RevenueSplitPolicy> = ApiResult.Success(
        RevenueSplitPolicy(mode = SplitMode.EQUAL, platformFeeBps = 0),
    ),
) : SyndicateRepository {

    var overviewCallCount = 0

    override suspend fun getOverview(syndicateId: String): ApiResult<SyndicateOverview> {
        overviewCallCount++
        return overviewResult
    }

    override suspend fun getTreasury(syndicateId: String): ApiResult<TreasurySummary> = treasuryResult

    override suspend fun getRevenueSplit(syndicateId: String): ApiResult<RevenueSplitPolicy> = splitResult

    override fun feedPager(syndicateId: String): Flow<PagingData<SyndicateFeedItem>> =
        flowOf(PagingData.empty())

    override fun treasuryLedgerPager(syndicateId: String): Flow<PagingData<TreasuryEntry>> =
        flowOf(PagingData.empty())

    companion object {
        fun failure(status: Int = 500, code: String? = null): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom", code = code))
    }
}
