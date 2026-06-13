package com.testlogon.android.feature.sponsorship.testing

import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDeal
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.sponsorship.SponsorshipApi
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto
import com.testlogon.android.feature.sponsorship.data.SponsorshipRepository
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.ResponseBody.Companion.toResponseBody
import retrofit2.HttpException
import retrofit2.Response

/**
 * AND-365 - in-memory fakes for the sponsorship inbox unit tests.
 *
 * The app unit-test classpath has NO moshi-kotlin KotlinJsonAdapterFactory, so :app tests use a FAKE
 * [SponsorshipApi] (no Moshi). The call RECORDS its call-count BEFORE honouring a configured throw, so a test
 * can assert the call happened even when it fails. Helper / recording names are distinct (the -Sponsorship-
 * infix) and never shadow an interface method.
 */
class FakeSponsorshipApi(
    var deals: () -> List<SponsorshipDealDto> = { emptyList() },
) : SponsorshipApi {

    var listDealsCallCount = 0

    override suspend fun listDeals(): List<SponsorshipDealDto> {
        listDealsCallCount++
        return deals()
    }

    companion object {
        /** Builds an HttpException with [status] (used to simulate a 401 / 500). */
        fun httpSponsorshipError(status: Int): HttpException = HttpException(
            Response.error<Any>(
                status,
                """{"detail":"boom"}""".toResponseBody("application/json".toMediaType()),
            ),
        )
    }
}

/**
 * A fake [SponsorshipRepository] for the ViewModel tests. The list result is swappable so a test can vary the
 * second (refresh) read. Mutating helpers are absent (the surface is READ-ONLY).
 */
class FakeSponsorshipRepo(
    var dealsResult: ApiResult<List<SponsorshipDeal>> = ApiResult.Success(emptyList()),
) : SponsorshipRepository {

    var listDealsCallCount = 0

    override suspend fun listDeals(): ApiResult<List<SponsorshipDeal>> {
        listDealsCallCount++
        return dealsResult
    }

    companion object {
        fun sponsorshipFailure(status: Int = 500): ApiResult.Failure =
            ApiResult.Failure(ApiError(status = status, message = "boom"))

        /** A small domain deal builder for the ViewModel tests. */
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
    }
}
