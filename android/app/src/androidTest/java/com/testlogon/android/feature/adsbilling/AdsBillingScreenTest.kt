package com.testlogon.android.feature.adsbilling

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.ads.AdInvoiceLine
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.adsbilling.ui.AdsBillingScreen
import com.testlogon.android.feature.adsbilling.ui.AdsBillingTestTags
import com.testlogon.android.feature.adsbilling.ui.AdsBillingUiState
import com.testlogon.android.feature.adsbilling.ui.DepositState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-367 - Compose UI tests for the stateless [AdsBillingScreen]. Drives an in-test reducer over the screen
 * state (USD -> cents validation mirroring the VM) so summary + ledger + invoice rendering and the deposit
 * sheet gating are exercised without Hilt. useUnmergedTree for nested controls; assertDoesNotExist is used as
 * a MEMBER (a chain call, not an import).
 */
@RunWith(AndroidJUnit4::class)
class AdsBillingScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun content() = AdsBillingUiState.Content(
        account = AdAccountSummary(
            accountId = "acc_1",
            companyName = "Acme Ads",
            status = "active",
            balanceCents = 150000L,
            lifetimeSpendCents = 9_500_000_000L,
        ),
        ledger = listOf(
            AdBillingEntry(entryType = "charge", amountCents = 2500L, state = "settled", reason = "spend"),
            AdBillingEntry(entryType = "deposit", amountCents = 50000L, state = "settled"),
        ),
        invoice = AdInvoice(
            month = "2026-06",
            totalChargesCents = 750000L,
            totalDepositsCents = 100000L,
            entryCount = 2,
            campaigns = listOf(AdInvoiceLine(campaignId = "cmp_1", totalCents = 500000L)),
        ),
    )

    private fun launch(initial: AdsBillingUiState = content()) {
        rule.setContent {
            TestLogonTheme {
                var sheetVisible by remember { mutableStateOf(false) }
                var amount by remember { mutableStateOf("") }
                var deposit by remember { mutableStateOf<DepositState>(DepositState.Idle) }
                val cents = parseUsd(amount)
                val canSubmit = cents != null && cents in 5_000L..10_000_000L
                AdsBillingScreen(
                    state = initial,
                    depositState = deposit,
                    depositSheetVisible = sheetVisible,
                    amountText = amount,
                    canSubmitDeposit = canSubmit,
                    onBack = {},
                    onRetry = {},
                    onOpenDeposit = {
                        amount = ""
                        deposit = DepositState.Idle
                        sheetVisible = true
                    },
                    onDismissDeposit = { sheetVisible = false },
                    onAmountChanged = { amount = it },
                    onConfirmDeposit = { deposit = DepositState.Success(200000L) },
                    paymentMethods = emptyList(),
                    selectedPaymentMethodId = null,
                    onPaymentMethodSelected = {},
                )
            }
        }
    }

    private fun parseUsd(text: String): Long? {
        val cleaned = text.trim().removePrefix("$").replace(",", "")
        if (cleaned.isEmpty()) return null
        val dollars = cleaned.toBigDecimalOrNull() ?: return null
        if (dollars.signum() < 0) return null
        return dollars.movePointRight(2).toLong()
    }

    @Test
    fun content_rendersSummaryLedgerInvoice() {
        launch()
        rule.onNodeWithTag(AdsBillingTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(AdsBillingTestTags.BALANCE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdsBillingTestTags.ledgerRow(0), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdsBillingTestTags.ledgerRow(1), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdsBillingTestTags.INVOICE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun addFunds_opensSheet_confirmDisabledUntilValid() {
        launch()
        rule.onNodeWithTag(AdsBillingTestTags.ADD_FUNDS).performClick()
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_AMOUNT, useUnmergedTree = true).assertIsDisplayed()
        // Empty -> confirm disabled.
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_CONFIRM).assertIsNotEnabled()
        // Below the $50 min -> still disabled.
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_AMOUNT, useUnmergedTree = true)
            .performTextReplacement("10.00")
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_CONFIRM).assertIsNotEnabled()
        // In range -> enabled.
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_AMOUNT, useUnmergedTree = true)
            .performTextReplacement("50.00")
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_CONFIRM).assertIsEnabled()
    }

    @Test
    fun deposit_confirm_showsSuccess() {
        launch()
        rule.onNodeWithTag(AdsBillingTestTags.ADD_FUNDS).performClick()
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_AMOUNT, useUnmergedTree = true)
            .performTextReplacement("50.00")
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_CONFIRM).performClick()
        // DEPOSIT_SUCCESS lives inside the ModalBottomSheet; under full-suite load the assert can race
        // the sheet enter/relayout animation, so poll until it is actually displayed before asserting.
        rule.waitUntil(timeoutMillis = 5_000) {
            runCatching {
                rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_SUCCESS, useUnmergedTree = true)
                    .assertIsDisplayed()
            }.isSuccess
        }
        rule.onNodeWithTag(AdsBillingTestTags.DEPOSIT_SUCCESS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun loading_hidesAddFunds() {
        launch(AdsBillingUiState.Loading)
        rule.onNodeWithTag(AdsBillingTestTags.ADD_FUNDS).assertDoesNotExist()
    }
}
