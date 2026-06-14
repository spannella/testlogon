package com.testlogon.android.feature.donation

import com.squareup.moshi.Moshi
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.network.donation.DonateRequestDto
import com.testlogon.android.core.network.donation.DonationApi
import com.testlogon.android.core.network.donation.DonationDto
import com.testlogon.android.core.network.donation.DonationReceiptDto
import com.testlogon.android.core.network.donation.PublicFundraiserDto
import com.testlogon.android.core.network.error.ApiErrorParser
import com.testlogon.android.feature.donation.data.DonationRepositoryImpl
import com.testlogon.android.feature.donation.model.DonationRequest
import com.testlogon.android.feature.donation.model.DonationStatus
import com.testlogon.android.feature.donation.model.FundraiserStatus
import kotlinx.coroutines.test.runTest
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import retrofit2.Response

/**
 * AND-393 - unit tests for [DonationRepositoryImpl] with a FAKE [DonationApi] (no Moshi on the :app test
 * classpath -> fake apis). DTO->domain mapping (status derived, money in cents); donate threads the body
 * and reaches a receipt; the SOFT-FALLBACK builds a minimal receipt when the receipt GET errors; the
 * donate request omits blank donor fields (anonymous). org.junit.Test; distinct fake-helper names.
 */
class DonationRepositoryTest {

    private val errorParser = ApiErrorParser(Moshi.Builder().build())

    /** A recording fake api. The donate body is captured; each endpoint result is configurable. */
    private class FakeApi(
        var fundraiser: Response<PublicFundraiserDto> = Response.success(fundraiserDto()),
        var donation: Response<DonationDto> = Response.success(donationDto()),
        var receipt: Response<DonationReceiptDto> = Response.success(receiptDto()),
    ) : DonationApi {
        var lastDonateBody: DonateRequestDto? = null
        var lastFundraiserId: String? = null
        var receiptCalls = 0
        override suspend fun getFundraiser(fundraiserId: String): Response<PublicFundraiserDto> {
            lastFundraiserId = fundraiserId
            return fundraiser
        }
        override suspend fun donate(
            fundraiserId: String,
            body: DonateRequestDto,
        ): Response<DonationDto> {
            lastDonateBody = body
            return donation
        }
        override suspend fun getReceipt(
            fundraiserId: String,
            donationId: String,
        ): Response<DonationReceiptDto> {
            receiptCalls++
            return receipt
        }
    }

    private fun repo(api: FakeApi) = DonationRepositoryImpl(api, errorParser)

    @Test
    fun getFundraiser_mapsDtoToDomain() = runTest {
        val api = FakeApi()
        val result = repo(api).getFundraiser("fr_123")
        assertTrue(result is ApiResult.Success)
        val f = (result as ApiResult.Success).data
        assertEquals("fr_123", api.lastFundraiserId)
        assertEquals(FundraiserStatus.ACTIVE, f.status)
        assertEquals(500_000L, f.goalCents)
        assertEquals(132_500L, f.raisedCents)
        assertEquals("Westside Library Friends", f.groupName)
        assertEquals("https://x/cover.jpg", f.coverImageUrl)
    }

    @Test
    fun donate_threadsBody_omitsBlankDonor_andReturnsReceipt() = runTest {
        val api = FakeApi()
        val result = repo(api).donate(
            fundraiserId = "fr_123",
            request = DonationRequest(amountCents = 2500L, donorName = null, donorEmail = null),
            currency = "usd",
            groupName = "Westside Library Friends",
            fundraiserTitle = "Help Build the Library",
        )
        assertTrue(result is ApiResult.Success)
        val receipt = (result as ApiResult.Success).data
        assertEquals(2500L, api.lastDonateBody?.amountCents)
        assertNull(api.lastDonateBody?.donorEmail)
        assertNull(api.lastDonateBody?.donorName)
        assertEquals("don_789", receipt.donationId)
        assertEquals(DonationStatus.COMPLETED, receipt.status)
        assertEquals(1, api.receiptCalls)
    }

    @Test
    fun donate_softFallback_whenReceiptErrors() = runTest {
        val api = FakeApi(
            receipt = Response.error(404, "".toResponseBody("application/json".toMediaTypeOrNull())),
        )
        val result = repo(api).donate(
            fundraiserId = "fr_123",
            request = DonationRequest(amountCents = 2500L, donorName = "Sean P.", donorEmail = null),
            currency = "usd",
            groupName = "Westside Library Friends",
            fundraiserTitle = "Help Build the Library",
        )
        // The donation still succeeds: the minimal receipt is built from the 201.
        assertTrue(result is ApiResult.Success)
        val receipt = (result as ApiResult.Success).data
        assertEquals("don_789", receipt.donationId)
        assertEquals(2500L, receipt.amountCents)
        assertEquals("Help Build the Library", receipt.fundraiserTitle)
        assertEquals(1, api.receiptCalls)
    }

    @Test
    fun donate_failure_whenDonatePostErrors() = runTest {
        val api = FakeApi(
            donation = Response.error(422, "{}".toResponseBody("application/json".toMediaTypeOrNull())),
        )
        val result = repo(api).donate(
            fundraiserId = "fr_123",
            request = DonationRequest(amountCents = 2500L, donorName = null, donorEmail = null),
            currency = "usd",
            groupName = null,
            fundraiserTitle = null,
        )
        assertTrue(result is ApiResult.Failure)
        assertEquals(422, (result as ApiResult.Failure).error.status)
        // The receipt GET is never attempted when the donate POST fails.
        assertEquals(0, api.receiptCalls)
    }
}

// ---- Distinct fake-helper names (top-level). ----

private fun fundraiserDto() = PublicFundraiserDto(
    fundraiserId = "fr_123",
    groupId = "grp_1",
    groupName = "Westside Library Friends",
    title = "Help Build the Library",
    status = "active",
    description = "Short blurb",
    currency = "usd",
    goalCents = 500_000L,
    raisedCents = 132_500L,
    donationCount = 42,
    coverImageUrl = "https://x/cover.jpg",
    endsAt = 1_735_689_600L,
)

private fun donationDto() = DonationDto(
    donationId = "don_789",
    amountCents = 2500L,
    status = "completed",
    createdAt = 1_717_804_800L,
    donorName = "Sean P.",
    isExternal = true,
    checkoutUrl = null,
)

private fun receiptDto() = DonationReceiptDto(
    donationId = "don_789",
    amountCents = 2500L,
    groupName = "Westside Library Friends",
    fundraiserTitle = "Help Build the Library",
    createdAt = 1_717_804_800L,
    status = "completed",
    currency = "usd",
    donorName = "Sean P.",
)
