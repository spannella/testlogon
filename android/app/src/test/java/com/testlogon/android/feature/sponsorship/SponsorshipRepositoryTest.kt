package com.testlogon.android.feature.sponsorship

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto
import com.testlogon.android.feature.sponsorship.data.SponsorshipRepositoryImpl
import com.testlogon.android.feature.sponsorship.testing.FakeSponsorshipApi
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * AND-365 - tests for [SponsorshipRepositoryImpl]: listDeals maps the bare array (id, raw + typed status,
 * cents, deadline string, created_at kept), an unknown status survives raw with a typed UNKNOWN, and an
 * HttpException surfaces as Failure (status preserved). The fake records the call BEFORE throwing.
 */
class SponsorshipRepositoryTest {

    private fun repo(api: FakeSponsorshipApi) = SponsorshipRepositoryImpl(
        api = api,
        errorParser = ApiErrorParser(Moshi.Builder().build()),
    )

    @Test
    fun listDeals_mapsBareArray_keepsRawAndCents() = runTest {
        val api = FakeSponsorshipApi(
            deals = {
                listOf(
                    SponsorshipDealDto(
                        dealId = "d1",
                        advertiserSub = "adv_1",
                        brief = "Promote",
                        status = "proposed",
                        compensationCents = 250000L,
                        deadline = "2026-07-01",
                        createdAt = 1700000000L,
                    ),
                )
            },
        )

        val result = repo(api).listDeals()

        assertTrue(result is ApiResult.Success)
        val deal = (result as ApiResult.Success).data.single()
        assertEquals("d1", deal.dealId)
        assertEquals("adv_1", deal.advertiserSub)
        assertEquals("proposed", deal.status)
        assertEquals(SponsorshipDealStatus.PROPOSED, deal.statusEnum)
        assertEquals(250000L, deal.compensationCents)
        assertEquals("2026-07-01", deal.deadline)
        assertEquals(1700000000L, deal.createdAt)
        assertEquals(1, api.listDealsCallCount)
    }

    @Test
    fun listDeals_unknownStatus_keptRaw_typedUnknown() = runTest {
        val api = FakeSponsorshipApi(
            deals = { listOf(SponsorshipDealDto(dealId = "d1", status = "weird")) },
        )
        val deal = (repo(api).listDeals() as ApiResult.Success).data.single()
        assertEquals("weird", deal.status)
        assertEquals(SponsorshipDealStatus.UNKNOWN, deal.statusEnum)
    }

    @Test
    fun listDeals_emptyArray_isSuccessEmpty() = runTest {
        val api = FakeSponsorshipApi(deals = { emptyList() })
        val result = repo(api).listDeals()
        assertTrue(result is ApiResult.Success)
        assertTrue((result as ApiResult.Success).data.isEmpty())
    }

    @Test
    fun listDeals_401_isFailureWithStatus401() = runTest {
        val api = FakeSponsorshipApi(deals = { throw FakeSponsorshipApi.httpSponsorshipError(401) })
        val result = repo(api).listDeals()
        assertTrue(result is ApiResult.Failure)
        assertEquals(401, (result as ApiResult.Failure).error.status)
        // recorded BEFORE throwing
        assertEquals(1, api.listDealsCallCount)
    }
}
