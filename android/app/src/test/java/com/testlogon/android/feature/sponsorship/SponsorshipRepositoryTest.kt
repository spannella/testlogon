package com.testlogon.android.feature.sponsorship

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.core.network.sponsorship.SponsorshipCounterReq
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDetailDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealDto
import com.testlogon.android.core.network.sponsorship.SponsorshipDealEventDto
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

    // ---- AND-366: getDeal / getHistory / accept / reject / counter ----

    @Test
    fun getDeal_mapsFullDeal() = runTest {
        val api = FakeSponsorshipApi(
            dealDetail = {
                SponsorshipDealDetailDto(
                    dealId = "d1",
                    advertiserSub = "adv_1",
                    creatorSub = "cre_1",
                    brief = "Promote",
                    status = "proposed",
                    compensationCents = 250000L,
                    deliverables = listOf("post", "story"),
                    deadline = "2026-07-01",
                    cpmBonusCents = 500L,
                    platformCommissionBps = 1000,
                    paymentDetails = mapOf("method" to "wallet"),
                )
            },
        )

        val result = repo(api).getDeal("d1")

        assertTrue(result is ApiResult.Success)
        val deal = (result as ApiResult.Success).data
        assertEquals("d1", deal.dealId)
        assertEquals("cre_1", deal.creatorSub)
        assertEquals(SponsorshipDealStatus.PROPOSED, deal.statusEnum)
        assertEquals(listOf("post", "story"), deal.deliverables)
        assertEquals(1000, deal.platformCommissionBps)
        assertTrue(deal.hasPaymentDetails)
        assertEquals("d1", api.lastDealIdArg)
        assertEquals(1, api.getDealCallCount)
    }

    @Test
    fun getHistory_mapsEvents_flattensDetails() = runTest {
        val api = FakeSponsorshipApi(
            history = {
                listOf(
                    SponsorshipDealEventDto(
                        eventId = "e1",
                        eventType = "countered",
                        actorSub = "adv_1",
                        details = mapOf("compensation_cents" to 300000),
                        createdAt = 1700000100L,
                    ),
                    SponsorshipDealEventDto(eventId = "e2", details = "please reconsider"),
                )
            },
        )

        val events = (repo(api).getHistory("d1") as ApiResult.Success).data
        assertEquals(2, events.size)
        assertEquals("countered", events[0].eventType)
        assertEquals("compensation_cents: 300000", events[0].detailsText)
        assertEquals("please reconsider", events[1].detailsText)
    }

    @Test
    fun accept_mapsAcceptedDeal() = runTest {
        val api = FakeSponsorshipApi(
            acceptResult = { SponsorshipDealDetailDto(dealId = "d1", status = "accepted") },
        )
        val deal = (repo(api).accept("d1") as ApiResult.Success).data
        assertEquals(SponsorshipDealStatus.ACCEPTED, deal.statusEnum)
        assertEquals(1, api.acceptCallCount)
    }

    @Test
    fun reject_sendsReason_mapsRejectedDeal() = runTest {
        val api = FakeSponsorshipApi(
            rejectResult = { SponsorshipDealDetailDto(dealId = "d1", status = "rejected") },
        )
        val deal = (repo(api).reject("d1", "budget too low") as ApiResult.Success).data
        assertEquals(SponsorshipDealStatus.REJECTED, deal.statusEnum)
        assertEquals("budget too low", api.lastRejectReq?.reason)
    }

    @Test
    fun counter_sendsCompensationAndNote() = runTest {
        val api = FakeSponsorshipApi(
            counterResult = { SponsorshipDealDetailDto(dealId = "d1", status = "negotiating") },
        )
        val deal = (repo(api).counter("d1", 300000L, "counter") as ApiResult.Success).data
        assertEquals(SponsorshipDealStatus.NEGOTIATING, deal.statusEnum)
        assertEquals(SponsorshipCounterReq(compensationCents = 300000L, note = "counter"), api.lastCounterReq)
    }

    @Test
    fun accept_422_isFailureRecordedBeforeThrow() = runTest {
        val api = FakeSponsorshipApi(acceptResult = { throw FakeSponsorshipApi.httpSponsorshipError(422) })
        val result = repo(api).accept("d1")
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        assertEquals(1, api.acceptCallCount)
    }
}
