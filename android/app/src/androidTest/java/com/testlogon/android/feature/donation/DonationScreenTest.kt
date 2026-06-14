package com.testlogon.android.feature.donation

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.donation.model.DonationReceipt
import com.testlogon.android.feature.donation.model.DonationStatus
import com.testlogon.android.feature.donation.model.Fundraiser
import com.testlogon.android.feature.donation.model.FundraiserStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-393 - Compose UI tests for the stateless [DonationScreen] driven by an in-test reducer. The form +
 * disabled-submit-while-invalid + confirmation + unavailable terminal are exercised. useUnmergedTree for
 * nested controls; the reducer mirrors the ViewModel's amount validation so the submit gate is realistic.
 */
@RunWith(AndroidJUnit4::class)
class DonationScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun fundraiser(status: FundraiserStatus = FundraiserStatus.ACTIVE) = Fundraiser(
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

    private fun launch(initial: DonationUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                DonationScreen(
                    state = state,
                    onClose = {},
                    onRetry = {},
                    onAmountChanged = { raw ->
                        val cents = raw.toDoubleOrNull()?.let { (it * 100).toLong() }
                        val valid = cents != null && cents >= 100L && cents <= 10_000_000L
                        state = state.copy(
                            amountInput = raw,
                            amountCents = if (valid) cents else null,
                            fieldErrors = if (valid) {
                                state.fieldErrors - DonationField.Amount
                            } else {
                                state.fieldErrors + (DonationField.Amount to "bad")
                            },
                        )
                    },
                    onPresetSelected = {},
                    onEmailChanged = { state = state.copy(donorEmail = it) },
                    onNameChanged = { state = state.copy(donorName = it) },
                    onSubmit = {
                        state = state.copy(
                            phase = Phase.Confirmed,
                            receipt = DonationReceipt(
                                donationId = "don_789",
                                amountCents = state.amountCents ?: 0L,
                                status = DonationStatus.COMPLETED,
                                createdAt = 1L,
                                currency = "usd",
                                donorName = null,
                                groupName = "Westside Library Friends",
                                fundraiserTitle = "Help Build the Library",
                            ),
                        )
                    },
                )
            }
        }
    }

    @Test
    fun form_rendersAndSubmitDisabledUntilValid() {
        launch(DonationUiState(fundraiserId = "fr_123", phase = Phase.Form, fundraiser = fundraiser()))
        rule.onNodeWithTag(DonationTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(DonationTestTags.SUBMIT, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun enterAmount_thenSubmit_showsConfirmation() {
        launch(DonationUiState(fundraiserId = "fr_123", phase = Phase.Form, fundraiser = fundraiser()))
        rule.onNodeWithTag(DonationTestTags.AMOUNT, useUnmergedTree = true).performTextInput("25.00")
        rule.onNodeWithTag(DonationTestTags.SUBMIT, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(DonationTestTags.CONFIRMATION, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun closedFundraiser_showsUnavailable_noForm() {
        launch(
            DonationUiState(
                fundraiserId = "fr_123",
                phase = Phase.Unavailable,
                fundraiser = fundraiser(FundraiserStatus.PAUSED),
            ),
        )
        rule.onNodeWithTag(DonationTestTags.UNAVAILABLE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(DonationTestTags.SUBMIT, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun confirmation_rendersReceipt() {
        launch(
            DonationUiState(
                fundraiserId = "fr_123",
                phase = Phase.Confirmed,
                receipt = DonationReceipt(
                    donationId = "don_789",
                    amountCents = 2500L,
                    status = DonationStatus.COMPLETED,
                    createdAt = 1L,
                    currency = "usd",
                    donorName = null,
                    groupName = "Westside Library Friends",
                    fundraiserTitle = "Help Build the Library",
                ),
            ),
        )
        rule.onNodeWithTag(DonationTestTags.CONFIRMATION, useUnmergedTree = true).assertIsDisplayed()
    }
}
