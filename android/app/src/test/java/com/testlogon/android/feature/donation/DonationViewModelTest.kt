package com.testlogon.android.feature.donation

import androidx.lifecycle.SavedStateHandle
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.testing.MainDispatcherRule
import com.testlogon.android.feature.donation.data.DonationRepository
import com.testlogon.android.feature.donation.model.DonationReceipt
import com.testlogon.android.feature.donation.model.DonationRequest
import com.testlogon.android.feature.donation.model.DonationStatus
import com.testlogon.android.feature.donation.model.Fundraiser
import com.testlogon.android.feature.donation.model.FundraiserStatus
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test

/**
 * AND-393 - unit tests for [DonationViewModel] with a fake repo. init load -> Form; amount/email
 * validation + canSubmit gating; submit success -> Confirmed; submit failure -> transientError; closed
 * fundraiser -> Unavailable; 422 -> field errors; anonymous (no donor fields) submit. MainDispatcherRule
 * + runCurrent (NO advanceUntilIdle); org.junit.Test; distinct fake-helper names.
 */
class DonationViewModelTest {

    @get:Rule
    val mainDispatcher = MainDispatcherRule()

    /** A recording fake repo. Records the call BEFORE returning; field-error lookup is configurable. */
    private class FakeRepo(
        var fundraiserResult: ApiResult<Fundraiser> = ApiResult.Success(activeFundraiser()),
        var donateResult: ApiResult<DonationReceipt> = ApiResult.Success(receipt()),
        var fieldErrors: Map<String, String> = emptyMap(),
    ) : DonationRepository {
        var lastRequest: DonationRequest? = null
        var donateCalls = 0
        override suspend fun getFundraiser(id: String): ApiResult<Fundraiser> = fundraiserResult
        override suspend fun donate(
            fundraiserId: String,
            request: DonationRequest,
            currency: String,
            groupName: String?,
            fundraiserTitle: String?,
        ): ApiResult<DonationReceipt> {
            donateCalls++
            lastRequest = request
            return donateResult
        }
        override fun fieldError(error: ApiError, locTail: String): String? = fieldErrors[locTail]
    }

    private fun vm(
        repo: DonationRepository,
        id: String = "fr_123",
    ): DonationViewModel =
        DonationViewModel(repo, SavedStateHandle(mapOf(DonationViewModel.ARG_FUNDRAISER_ID to id)))

    @Test
    fun init_loadsActiveFundraiser_toForm() = runTest {
        val sheet = vm(FakeRepo())
        runCurrent()
        val state = sheet.uiState.value
        assertEquals(Phase.Form, state.phase)
        assertEquals("Help Build the Library", state.fundraiser?.title)
    }

    @Test
    fun closedFundraiser_toUnavailable() = runTest {
        val repo = FakeRepo(fundraiserResult = ApiResult.Success(activeFundraiser(FundraiserStatus.PAUSED)))
        val sheet = vm(repo)
        runCurrent()
        assertEquals(Phase.Unavailable, sheet.uiState.value.phase)
    }

    @Test
    fun loadServerError_toLoadError_withRetry() = runTest {
        val repo = FakeRepo(fundraiserResult = ApiResult.Failure(ApiError(500, "boom")))
        val sheet = vm(repo)
        runCurrent()
        assertEquals(Phase.LoadError, sheet.uiState.value.phase)
        // Retry succeeds on the second load.
        repo.fundraiserResult = ApiResult.Success(activeFundraiser())
        sheet.loadFundraiser()
        runCurrent()
        assertEquals(Phase.Form, sheet.uiState.value.phase)
    }

    @Test
    fun loadNotFound_4xx_toUnavailable() = runTest {
        val repo = FakeRepo(fundraiserResult = ApiResult.Failure(ApiError(404, "nope")))
        val sheet = vm(repo)
        runCurrent()
        assertEquals(Phase.Unavailable, sheet.uiState.value.phase)
    }

    @Test
    fun amountValidation_blocksInvalid_allowsValid() = runTest {
        val sheet = vm(FakeRepo())
        runCurrent()

        sheet.onAmountChanged("")
        assertFalse(sheet.uiState.value.canSubmit)
        assertTrue(sheet.uiState.value.fieldErrors.containsKey(DonationField.Amount))

        sheet.onAmountChanged("abc")
        assertTrue(sheet.uiState.value.fieldErrors.containsKey(DonationField.Amount))

        sheet.onAmountChanged("0.50") // 50 cents < min 100
        assertTrue(sheet.uiState.value.fieldErrors.containsKey(DonationField.Amount))

        sheet.onAmountChanged("100001") // > 10,000,000 cents
        assertTrue(sheet.uiState.value.fieldErrors.containsKey(DonationField.Amount))

        sheet.onAmountChanged("25.00")
        val ok = sheet.uiState.value
        assertNull(ok.fieldErrors[DonationField.Amount])
        assertEquals(2500L, ok.amountCents)
        assertTrue(ok.canSubmit)
    }

    @Test
    fun emailOptional_blankAllowed_malformedBlocks() = runTest {
        val sheet = vm(FakeRepo())
        runCurrent()
        sheet.onAmountChanged("25.00")

        // (a) blank email never blocks
        sheet.onEmailChanged("")
        assertTrue(sheet.uiState.value.canSubmit)

        // (b) malformed email blocks
        sheet.onEmailChanged("not-an-email")
        assertFalse(sheet.uiState.value.canSubmit)
        assertTrue(sheet.uiState.value.fieldErrors.containsKey(DonationField.Email))

        // (c) valid email clears the error
        sheet.onEmailChanged("spannella@gmail.com")
        assertNull(sheet.uiState.value.fieldErrors[DonationField.Email])
        assertTrue(sheet.uiState.value.canSubmit)
    }

    @Test
    fun preset_setsAmountCents() = runTest {
        val sheet = vm(FakeRepo())
        runCurrent()
        sheet.onPresetSelected(2500L)
        assertEquals(2500L, sheet.uiState.value.amountCents)
        assertTrue(sheet.uiState.value.canSubmit)
    }

    @Test
    fun submitSuccess_anonymous_toConfirmed() = runTest {
        val repo = FakeRepo()
        val sheet = vm(repo)
        runCurrent()
        sheet.onAmountChanged("25.00")
        // No donor name/email -> truly anonymous.
        sheet.submit()
        runCurrent()
        val state = sheet.uiState.value
        assertEquals(Phase.Confirmed, state.phase)
        assertFalse(state.isSubmitting)
        assertEquals("don_789", state.receipt?.donationId)
        assertNull(repo.lastRequest?.donorEmail)
        assertNull(repo.lastRequest?.donorName)
        assertEquals(2500L, repo.lastRequest?.amountCents)
    }

    @Test
    fun submitTransientFailure_keepsForm_setsTransientError() = runTest {
        val repo = FakeRepo(donateResult = ApiResult.Failure(ApiError(500, "server")))
        val sheet = vm(repo)
        runCurrent()
        sheet.onAmountChanged("25.00")
        sheet.submit()
        runCurrent()
        val state = sheet.uiState.value
        assertEquals(Phase.Form, state.phase)
        assertFalse(state.isSubmitting)
        assertEquals("server", state.transientError)
        // NOT auto-retried: exactly one POST.
        assertEquals(1, repo.donateCalls)
    }

    @Test
    fun submit422_mapsFieldError() = runTest {
        val repo = FakeRepo(
            donateResult = ApiResult.Failure(ApiError(422, "Validation error")),
            fieldErrors = mapOf("amount_cents" to "Amount is too small"),
        )
        val sheet = vm(repo)
        runCurrent()
        sheet.onAmountChanged("25.00")
        sheet.submit()
        runCurrent()
        val state = sheet.uiState.value
        assertEquals(Phase.Form, state.phase)
        assertEquals("Amount is too small", state.fieldErrors[DonationField.Amount])
        assertNull(state.transientError)
    }
}

// ---- Distinct fake-helper names (top-level). ----

private fun activeFundraiser(status: FundraiserStatus = FundraiserStatus.ACTIVE) = Fundraiser(
    fundraiserId = "fr_123",
    groupId = "grp_1",
    groupName = "Westside Library Friends",
    title = "Help Build the Library",
    status = status,
    description = "Short blurb",
    currency = "usd",
    goalCents = 500_000L,
    raisedCents = 132_500L,
    donationCount = 42,
    coverImageUrl = null,
    endsAt = null,
)

private fun receipt() = DonationReceipt(
    donationId = "don_789",
    amountCents = 2500L,
    status = DonationStatus.COMPLETED,
    createdAt = 1_717_804_800L,
    currency = "usd",
    donorName = null,
    groupName = "Westside Library Friends",
    fundraiserTitle = "Help Build the Library",
)
