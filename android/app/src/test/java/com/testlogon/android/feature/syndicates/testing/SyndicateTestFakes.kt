package com.testlogon.android.feature.syndicates.testing

import androidx.paging.PagingData
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.model.syndicates.RegistrationResult
import com.testlogon.android.core.model.syndicates.RevenueSplitPolicy
import com.testlogon.android.core.model.syndicates.SplitMode
import com.testlogon.android.core.model.syndicates.SyndicateFeedItem
import com.testlogon.android.core.model.syndicates.SyndicateOverview
import com.testlogon.android.core.model.syndicates.TreasuryEntry
import com.testlogon.android.core.model.syndicates.TreasurySummary
import com.testlogon.android.core.network.syndicates.MemberEarningsOut
import com.testlogon.android.core.network.syndicates.OpenLicensingContentListResponse
import com.testlogon.android.core.network.syndicates.SplitConfigOut
import com.testlogon.android.core.network.syndicates.SyndicateApi
import com.testlogon.android.core.network.syndicates.SyndicateFeedOut
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingRegisterIn
import com.testlogon.android.core.network.syndicates.SyndicateOpenLicensingRegistrationOut
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
    var licensingContent: () -> OpenLicensingContentListResponse = {
        OpenLicensingContentListResponse(items = emptyList())
    },
    var register: () -> SyndicateOpenLicensingRegistrationOut = {
        SyndicateOpenLicensingRegistrationOut(contentId = "c1", syndicateId = "syn_1", licensesCreated = 1)
    },
) : SyndicateApi {

    val profileSyndicateIds = mutableListOf<String>()
    val feedSyndicateIds = mutableListOf<String>()
    val treasurySyndicateIds = mutableListOf<String>()
    val splitSyndicateIds = mutableListOf<String>()

    // AND-357 - recording of the open-licensing calls (recorded BEFORE any configured throw).
    val licensingContentSyndicateIds = mutableListOf<String>()
    val registerSyndicateIds = mutableListOf<String>()
    val registerBodies = mutableListOf<SyndicateOpenLicensingRegisterIn>()

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

    override suspend fun getOpenLicensingContent(syndicateId: String): OpenLicensingContentListResponse {
        licensingContentSyndicateIds += syndicateId
        return licensingContent()
    }

    override suspend fun registerOpenLicensing(
        syndicateId: String,
        body: SyndicateOpenLicensingRegisterIn,
    ): SyndicateOpenLicensingRegistrationOut {
        registerSyndicateIds += syndicateId
        registerBodies += body
        return register()
    }

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 403 / 500). */
        fun http(status: Int): HttpException = HttpException(
            Response.error<Any>(status, """{"detail":"boom"}""".toResponseBody("application/json".toMediaType())),
        )

        /**
         * AND-357 - builds a 422 HttpException whose detail[{loc,msg,type}] targets the given field tails,
         * so the repository's ApiErrorParser preserves the raw body for per-field mapping.
         */
        fun http422(vararg locTails: Pair<String, String>): HttpException {
            val items = locTails.joinToString(",") { (loc, msg) ->
                """{"loc":["body","$loc"],"msg":"$msg","type":"value_error"}"""
            }
            val body = """{"detail":[$items]}"""
            return HttpException(
                Response.error<Any>(422, body.toResponseBody("application/json".toMediaType())),
            )
        }
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
    // AND-357 - open-licensing results. licensingResult is a lambda so a test can swap the list between the
    // initial load and the post-register REFETCH (to assert the list was re-fetched, not optimistically
    // prepended).
    var licensingResult: () -> ApiResult<List<OpenLicensingContent>> = { ApiResult.Success(emptyList()) },
    var registerResult: ApiResult<RegistrationResult> = ApiResult.Success(
        RegistrationResult(contentId = "c1", licensesCreated = 2),
    ),
) : SyndicateRepository {

    var overviewCallCount = 0

    // AND-357 - recording for the open-licensing methods.
    var licensingContentCallCount = 0
    var registerCallCount = 0
    val registeredContentIds = mutableListOf<String>()
    val registeredContentTypes = mutableListOf<LicensingContentType>()

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

    override suspend fun getOpenLicensingContent(
        syndicateId: String,
    ): ApiResult<List<OpenLicensingContent>> {
        licensingContentCallCount++
        return licensingResult()
    }

    override suspend fun registerOpenLicensing(
        syndicateId: String,
        contentId: String,
        contentType: LicensingContentType,
    ): ApiResult<RegistrationResult> {
        registerCallCount++
        registeredContentIds += contentId
        registeredContentTypes += contentType
        return registerResult
    }

    companion object {
        fun failure(status: Int = 500, code: String? = null): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom", code = code))

        /**
         * AND-357 - a 422 Failure carrying a FastAPI detail[{loc,msg,type}] body as ApiError.raw, so the
         * ViewModel's per-field loc-tail mapper can route the messages to content_id / content_type.
         */
        fun failure422(vararg locTails: Pair<String, String>): ApiResult.Failure {
            val items = locTails.joinToString(",") { (loc, msg) ->
                """{"loc":["body","$loc"],"msg":"$msg","type":"value_error"}"""
            }
            return ApiResult.Failure(
                ApiError(status = 422, message = "Unprocessable", raw = """{"detail":[$items]}"""),
            )
        }
    }
}
