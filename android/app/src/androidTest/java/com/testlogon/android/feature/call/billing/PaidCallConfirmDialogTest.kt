package com.testlogon.android.feature.call.billing

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-301 — Compose UI tests for the [PaidCallConfirmDialog] + [RunningCostOverlay]/[FinalCostSummary].
 * Hand-built state, wrapped in [TestLogonTheme]; useUnmergedTree for nested nodes.
 */
@RunWith(AndroidJUnit4::class)
class PaidCallConfirmDialogTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun dialog_rendersRateLabel_andButtons() {
        rule.setContent {
            TestLogonTheme {
                PaidCallConfirmDialog(
                    rateCentsPerMinute = 5,
                    balanceRemainingCents = null,
                    onConfirm = {},
                    onCancel = {},
                )
            }
        }
        rule.onNodeWithText("\$0.05/min").assertExists()
        rule.onNodeWithTag("paid_call_start").assertExists()
        rule.onNodeWithTag("paid_call_cancel").assertExists()
        // Unknown balance (FLAGGED seam) -> "balance unavailable" note + Start still enabled.
        rule.onNodeWithTag("paid_call_balance_unavailable", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag("paid_call_start").assertIsEnabled()
    }

    @Test
    fun cancel_invokesOnCancel() {
        var cancelled = false
        rule.setContent {
            TestLogonTheme {
                PaidCallConfirmDialog(
                    rateCentsPerMinute = 5,
                    balanceRemainingCents = null,
                    onConfirm = {},
                    onCancel = { cancelled = true },
                )
            }
        }
        rule.onNodeWithTag("paid_call_cancel").performClick()
        assertTrue(cancelled)
    }

    @Test
    fun start_invokesOnConfirm() {
        var confirmed = false
        rule.setContent {
            TestLogonTheme {
                PaidCallConfirmDialog(
                    rateCentsPerMinute = 5,
                    balanceRemainingCents = 1000,
                    onConfirm = { confirmed = true },
                    onCancel = {},
                )
            }
        }
        rule.onNodeWithTag("paid_call_start").performClick()
        assertTrue(confirmed)
    }

    @Test
    fun start_disabled_whenBalanceBelowRate() {
        rule.setContent {
            TestLogonTheme {
                PaidCallConfirmDialog(
                    rateCentsPerMinute = 50,
                    balanceRemainingCents = 10,
                    onConfirm = {},
                    onCancel = {},
                )
            }
        }
        rule.onNodeWithTag("paid_call_start").assertIsNotEnabled()
    }

    @Test
    fun runningCost_showsEstimateSuffix() {
        rule.setContent {
            TestLogonTheme {
                RunningCostOverlay(
                    runningCostCents = 5,
                    isEstimate = true,
                    condition = BillingCondition.None,
                )
            }
        }
        rule.onNodeWithText("\$0.05 (estimated)").assertExists()
    }

    @Test
    fun runningCost_authoritative_hasNoEstimateSuffix() {
        rule.setContent {
            TestLogonTheme {
                RunningCostOverlay(
                    runningCostCents = 120,
                    isEstimate = false,
                    condition = BillingCondition.LowBalance,
                )
            }
        }
        rule.onNodeWithText("\$1.20").assertExists()
        rule.onNodeWithTag("running_cost_warning", useUnmergedTree = true).assertExists()
    }

    @Test
    fun finalSummary_showsTotal_onEnded() {
        rule.setContent {
            TestLogonTheme {
                FinalCostSummary(finalCostCents = 120, finalIsEstimate = false)
            }
        }
        rule.onNodeWithText("Total: \$1.20").assertExists()
    }

    @Test
    fun finalSummary_labelsEstimate() {
        rule.setContent {
            TestLogonTheme {
                FinalCostSummary(finalCostCents = 120, finalIsEstimate = true)
            }
        }
        rule.onNodeWithText("Total: \$1.20 (estimated)").assertExists()
    }

    @Test
    fun confirm_inTestReducer_opensGate() {
        rule.setContent {
            TestLogonTheme {
                val delegate = remember { CallBillingDelegate() }
                var state by remember {
                    mutableStateOf(delegate.onInvite(paid = true, rateCentsPerMinute = 5))
                }
                val confirm = state.confirm
                if (confirm is PaidCallConfirmState.AwaitingConfirm) {
                    PaidCallConfirmDialog(
                        rateCentsPerMinute = confirm.rateCentsPerMinute,
                        balanceRemainingCents = confirm.balanceRemainingCents,
                        onConfirm = { state = delegate.confirmPaidCall(state) },
                        onCancel = { state = delegate.cancel(state) },
                    )
                }
            }
        }
        rule.onNodeWithTag("paid_call_start").performClick()
        // After confirming, the dialog is gone.
        rule.onNodeWithTag("paid_call_confirm").assertDoesNotExist()
    }

    @Test
    fun delegate_confirm_isPure() {
        // Sanity: the in-test reducer matches the pure delegate result.
        val delegate = CallBillingDelegate()
        val confirmed = delegate.confirmPaidCall(delegate.onInvite(paid = true, rateCentsPerMinute = 5))
        assertEquals(PaidCallConfirmState.Confirmed, confirmed.confirm)
    }
}
