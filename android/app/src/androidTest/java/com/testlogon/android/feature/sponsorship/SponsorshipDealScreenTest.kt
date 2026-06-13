package com.testlogon.android.feature.sponsorship

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.sponsorship.DealAction
import com.testlogon.android.core.model.sponsorship.SponsorshipDealDetail
import com.testlogon.android.core.model.sponsorship.SponsorshipDealEvent
import com.testlogon.android.core.model.sponsorship.SponsorshipDealStatus
import com.testlogon.android.core.model.sponsorship.ViewerRole
import com.testlogon.android.core.model.sponsorship.availableActions
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.sponsorship.ui.CounterFieldError
import com.testlogon.android.feature.sponsorship.ui.CounterForm
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealScreen
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealTestTags
import com.testlogon.android.feature.sponsorship.ui.SponsorshipDealUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-366 - Compose UI tests for the stateless [SponsorshipDealScreen]. A small in-test reducer drives the
 * Content state (opening the counter form, applying a CLIENT-side compensation-min check mirroring the VM) so
 * the action affordances / terminal read-only / confirm dialog / counter validation render without Hilt.
 * useUnmergedTree for nested controls; assertDoesNotExist is a MEMBER (chained, not imported).
 */
@RunWith(AndroidJUnit4::class)
class SponsorshipDealScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun deal(status: String) = SponsorshipDealDetail(
        dealId = "d1",
        advertiserSub = "adv_1",
        creatorSub = "cre_1",
        brief = "Promote our app",
        status = status,
        statusEnum = SponsorshipDealStatus.from(status),
        compensationCents = 250000L,
        deliverables = listOf("post", "story"),
        deadline = "2026-07-01",
        cpmBonusCents = 500L,
        platformCommissionBps = 1000,
    )

    private fun content(status: String): SponsorshipDealUiState.Content {
        val d = deal(status)
        return SponsorshipDealUiState.Content(
            deal = d,
            history = listOf(SponsorshipDealEvent(eventId = "e1", eventType = "proposed", actorSub = "adv_1")),
            viewerRole = ViewerRole.ADVERTISER,
            availableActions = availableActions(d.statusEnum, ViewerRole.ADVERTISER),
        )
    }

    private fun launch(initial: SponsorshipDealUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                SponsorshipDealScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onAccept = {},
                    onReject = {},
                    onOpenCounter = {
                        (state as? SponsorshipDealUiState.Content)?.let {
                            state = it.copy(counterForm = CounterForm(compensationText = "2500.00"))
                        }
                    },
                    onDismissCounter = {
                        (state as? SponsorshipDealUiState.Content)?.let { state = it.copy(counterForm = null) }
                    },
                    onCounterCompensationChanged = { text ->
                        (state as? SponsorshipDealUiState.Content)?.let { c ->
                            c.counterForm?.let { f ->
                                state = c.copy(counterForm = f.copy(compensationText = text, compensationError = null))
                            }
                        }
                    },
                    onCounterNoteChanged = { text ->
                        (state as? SponsorshipDealUiState.Content)?.let { c ->
                            c.counterForm?.let { f ->
                                state = c.copy(counterForm = f.copy(note = text))
                            }
                        }
                    },
                    onSubmitCounter = {
                        // In-test reducer mirrors the VM's client min-cents check (>= 1000 cents).
                        (state as? SponsorshipDealUiState.Content)?.let { c ->
                            c.counterForm?.let { f ->
                                val cents = f.compensationText.trim().toBigDecimalOrNull()
                                    ?.movePointRight(2)?.toLong()
                                state = if (cents != null && cents < 1000L) {
                                    c.copy(
                                        counterForm = f.copy(
                                            compensationError = CounterFieldError.CLIENT_COMPENSATION_TOO_LOW,
                                        ),
                                    )
                                } else {
                                    c.copy(counterForm = null)
                                }
                            }
                        }
                    },
                )
            }
        }
    }

    @Test
    fun actionableStatus_showsAcceptRejectNegotiate() {
        launch(content("proposed"))
        rule.onNodeWithTag(SponsorshipDealTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipDealTestTags.ACCEPT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipDealTestTags.REJECT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipDealTestTags.NEGOTIATE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun terminalStatus_hidesActions_showsStatus() {
        launch(content("completed"))
        rule.onNodeWithTag(SponsorshipDealTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SponsorshipDealTestTags.ACCEPT).assertDoesNotExist()
        rule.onNodeWithTag(SponsorshipDealTestTags.REJECT).assertDoesNotExist()
        rule.onNodeWithTag(SponsorshipDealTestTags.NEGOTIATE).assertDoesNotExist()
    }

    @Test
    fun acceptShowsConfirmDialog() {
        launch(content("proposed"))
        rule.onNodeWithTag(SponsorshipDealTestTags.ACCEPT, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(SponsorshipDealTestTags.CONFIRM, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun negotiate_opensCounterForm_validationBlocksTooLow() {
        launch(content("proposed"))
        rule.onNodeWithTag(SponsorshipDealTestTags.NEGOTIATE, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(SponsorshipDealTestTags.COUNTER_COMPENSATION, useUnmergedTree = true)
            .assertIsDisplayed()

        rule.onNodeWithTag(SponsorshipDealTestTags.COUNTER_COMPENSATION, useUnmergedTree = true)
            .performTextReplacement("5.00")
        rule.onNodeWithTag(SponsorshipDealTestTags.COUNTER_SUBMIT, useUnmergedTree = true).performClick()

        // Form stays open (still showing the compensation field) after the too-low validation failure.
        rule.onNodeWithTag(SponsorshipDealTestTags.COUNTER_COMPENSATION, useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun inFlight_disablesActions() {
        val c = content("proposed").copy(actionInFlight = DealAction.ACCEPT)
        launch(c)
        rule.onNodeWithTag(SponsorshipDealTestTags.REJECT, useUnmergedTree = true).assertIsNotEnabled()
        rule.onNodeWithTag(SponsorshipDealTestTags.NEGOTIATE, useUnmergedTree = true).assertIsNotEnabled()
    }
}
