package com.testlogon.android.feature.sponsorship.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.sponsorship.SponsorshipApi
import com.testlogon.android.core.network.sponsorship.SponsorshipCounterReq
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDetailDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealEventDto
import com.testlogon.android.core.network.sponsorship.SponsorshipRejectReq
import com.testlogon.android.feature.sponsorship.data.SponsorshipRepository
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-365 / AND-366 - in-memory fakes for the sponsorship unit tests.
 *
 * The app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [SponsorshipApi] (no Moshi). Each call RECORDS its arguments / call-count BEFORE honouring a configured
 * throw, so a test can assert the call happened even when it fails. Helper / recording names are distinct (the
 * -Sponsorship- infix) and never shadow an interface method.
 */
class FakeSponsorshipApi(
    var deals: () -> List<SponsorshipDealDto> = { emptyList() },
    var dealDetail: () -> SponsorshipDealDetailDto = { SponsorshipDealDetailDto(dealId = "d1") },
    var history: () -> List<SponsorshipDealEventDto> = { emptyList() },
    var acceptResult: () -> SponsorshipDealDetailDto = { SponsorshipDealDetailDto(dealId = "d1", status = "accepted") },
    var rejectResult: () -> SponsorshipDealDetailDto = { SponsorshipDealDetailDto(dealId = "d1", status = "rejected") },
    var counterResult: () -> SponsorshipDealDetailDto = { SponsorshipDealDetailDto(dealId = "d1", status = "negotiating") },
) : SponsorshipApi {

    var listDealsCallCount = 0
    var getDealCallCount = 0
    var getHistoryCallCount = 0
    var acceptCallCount = 0
    var rejectCallCount = 0
    var counterCallCount = 0

    var lastDealIdArg: String? = null
    var lastRejectReq: SponsorshipRejectReq? = null
    var lastCounterReq: SponsorshipCounterReq? = null

    override suspend fun listDeals(): List<SponsorshipDealDto> {
        listDealsCallCount++
        return deals()
    }

    override suspend fun getDeal(dealId: String): SponsorshipDealDetailDto {
        getDealCallCount++
        lastDealIdArg = dealId
        return dealDetail()
    }

    override suspend fun getHistory(dealId: String): List<SponsorshipDealEventDto> {
        getHistoryCallCount++
        lastDealIdArg = dealId
        return history()
    }

    override suspend fun accept(dealId: String): SponsorshipDealDetailDto {
        acceptCallCount++
        lastDealIdArg = dealId
        return acceptResult()
    }

    override suspend fun reject(dealId: String, body: SponsorshipRejectReq): SponsorshipDealDetailDto {
        rejectCallCount++
        lastDealIdArg = dealId
        lastRejectReq = body
        return rejectResult()
    }

    override suspend fun counter(dealId: String, body: SponsorshipCounterReq): SponsorshipDealDetailDto {
        counterCallCount++
        lastDealIdArg = dealId
        lastCounterReq = body
        return counterResult()
    }

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 401 / 422 / 500). */
        fun httpSponsorshipError(status: Int, body: String = """{"detail":"boom"}"""): HttpException =
            HttpException(
                Response.error<Any>(
                    status,
                    body.toResponseBody("application/json".toMediaType()),
                ),
            )
    }
}

/**
 * A fake [SponsorshipRepository] for the ViewModel tests. The list result is swappable; the detail / history /
 * action outcomes are swappable per test, and every action RECORDS its args before returning so a test can
 * assert the call shape (e.g. the reject reason, the counter compensation + note).
 */
class FakeSponsorshipRepo(
    var dealsResult: ApiResult<List<SponsorshipDeal>> = ApiResult.Success(emptyList()),
) : SponsorshipRepository {

    var listDealsCallCount = 0
    var getDealCallCount = 0
    var getHistoryCallCount = 0
    var acceptCallCount = 0
    var rejectCallCount = 0
    var counterCallCount = 0

    var dealResult: ApiResult<SponsorshipDealDetail> = ApiResult.Success(detail("d1", "proposed"))
    var historyResult: ApiResult<List<SponsorshipDealEvent>> = ApiResult.Success(emptyList())
    var acceptResult: ApiResult<SponsorshipDealDetail> = ApiResult.Success(detail("d1", "accepted"))
    var rejectResult: ApiResult<SponsorshipDealDetail> = ApiResult.Success(detail("d1", "rejected"))
    var counterResult: ApiResult<SponsorshipDealDetail> = ApiResult.Success(detail("d1", "negotiating"))

    var lastRejectReason: String? = null
    var lastCounterCompensation: Long? = null
    var lastCounterNote: String? = null

    override suspend fun listDeals(): ApiResult<List<SponsorshipDeal>> {
        listDealsCallCount++
        return dealsResult
    }

    override suspend fun getDeal(dealId: String): ApiResult<SponsorshipDealDetail> {
        getDealCallCount++
        return dealResult
    }

    override suspend fun getHistory(dealId: String): ApiResult<List<SponsorshipDealEvent>> {
        getHistoryCallCount++
        return historyResult
    }

    override suspend fun accept(dealId: String): ApiResult<SponsorshipDealDetail> {
        acceptCallCount++
        return acceptResult
    }

    override suspend fun reject(dealId: String, reason: String): ApiResult<SponsorshipDealDetail> {
        rejectCallCount++
        lastRejectReason = reason
        return rejectResult
    }

    override suspend fun counter(
        dealId: String,
        compensationCents: Long?,
        note: String?,
    ): ApiResult<SponsorshipDealDetail> {
        counterCallCount++
        lastCounterCompensation = compensationCents
        lastCounterNote = note
        return counterResult
    }

    companion object {
        fun sponsorshipFailure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))

        /** A 422 failure carrying a FastAPI detail[{loc,msg}] body on ApiError.raw (loc tail routing). */
        fun sponsorship422(loc: String): ApiResult.Failure = ApiResult.Failure(
            ApiError(
                status = 422,
                message = "validation",
                raw = """{"detail":[{"loc":["body","$loc"],"msg":"bad","type":"value_error"}]}""",
            ),
        )

        /** A small inbox-row domain deal builder for the inbox ViewModel tests. */
        fun deal(
            id: String,
            status: String,
            createdAt: Long?,
        ): SponsorshipDeal = SponsorshipDeal(
            dealId = id,
            advertiserSub = "adv_$id",
            brief = "brief $id",
            status = status,
            statusEnum = SponsorshipDealStatus.from(status),
            compensationCents = 100000L,
            deadline = "2026-07-01",
            createdAt = createdAt,
        )

        /** A FULL-deal domain builder for the deal-detail ViewModel tests. */
        fun detail(
            id: String,
            status: String,
            advertiserSub: String? = "adv_$id",
            creatorSub: String? = "cre_$id",
            compensationCents: Long? = 250000L,
        ): SponsorshipDealDetail = SponsorshipDealDetail(
            dealId = id,
            advertiserSub = advertiserSub,
            creatorSub = creatorSub,
            brief = "brief $id",
            status = status,
            statusEnum = SponsorshipDealStatus.from(status),
            compensationCents = compensationCents,
            deliverables = listOf("post", "story"),
            deadline = "2026-07-01",
            cpmBonusCents = 500L,
            platformCommissionBps = 1000,
            contentId = null,
            hasPaymentDetails = false,
        )
    }
}
