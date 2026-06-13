package com.testlogon.android.feature.kyc.prooffunds

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSource
import com.testlogon.android.feature.kyc.prooffunds.model.PoFStatus
import com.testlogon.android.feature.kyc.prooffunds.model.PoFSummary
import com.testlogon.android.feature.kyc.prooffunds.model.ProofOfFunds
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-327 - Compose UI smoke tests for the stateless [ProofOfFundsScreen]. An in-test reducer over a
 * remembered [ProofOfFundsUiState] drives the screen; actions swap the state so the rendered surface can be
 * asserted (no VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER.
 */
@RunWith(AndroidJUnit4::class)
class ProofOfFundsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launchForm(initial: ProofOfFundsUiState.Form) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf<ProofOfFundsUiState>(initial) }
                ProofOfFundsScreen(
                    state = state,
                    onBack = {},
                    onSourceChanged = { src ->
                        (state as? ProofOfFundsUiState.Form)?.let {
                            state = it.copy(
                                source = src,
                                submitEnabled = it.amountRaw.isNotBlank() && it.documentKey != null,
                            )
                        }
                    },
                    onAmountChanged = { v ->
                        (state as? ProofOfFundsUiState.Form)?.let {
                            state = it.copy(
                                amountRaw = v,
                                submitEnabled = it.source != null && it.documentKey != null,
                            )
                        }
                    },
                    onCurrencyChanged = { v ->
                        (state as? ProofOfFundsUiState.Form)?.let { state = it.copy(currency = v) }
                    },
                    onNoteChanged = { v ->
                        (state as? ProofOfFundsUiState.Form)?.let { state = it.copy(note = v) }
                    },
                    onCapture = {
                        (state as? ProofOfFundsUiState.Form)?.let {
                            state = it.copy(
                                documentKey = "kyc/pof/x.jpg",
                                documentLabel = "doc.jpg",
                                submitEnabled = it.source != null && it.amountRaw.isNotBlank(),
                            )
                        }
                    },
                    onPick = {},
                    onRemoveDocument = {
                        (state as? ProofOfFundsUiState.Form)?.let {
                            state = it.copy(documentKey = null, documentLabel = null, submitEnabled = false)
                        }
                    },
                    onSubmit = {},
                    onResubmit = {},
                    onRetry = {},
                )
            }
        }
    }

    private fun launchStatus(initial: ProofOfFundsUiState.Status) {
        rule.setContent {
            TestLogonTheme {
                ProofOfFundsScreen(
                    state = initial,
                    onBack = {},
                    onSourceChanged = {},
                    onAmountChanged = {},
                    onCurrencyChanged = {},
                    onNoteChanged = {},
                    onCapture = {},
                    onPick = {},
                    onRemoveDocument = {},
                    onSubmit = {},
                    onResubmit = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun form_showsSourceAmountAndAddDoc() {
        launchForm(ProofOfFundsUiState.Form(summary = summary()))
        rule.onNodeWithTag(ProofOfFundsTestTags.SOURCE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ProofOfFundsTestTags.AMOUNT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ProofOfFundsTestTags.ADD_DOC, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun form_submitDisabledUntilComplete() {
        launchForm(ProofOfFundsUiState.Form(summary = summary(), submitEnabled = false))
        rule.onNodeWithTag(ProofOfFundsTestTags.SUBMIT, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun form_submitEnabledWhenComplete() {
        launchForm(
            ProofOfFundsUiState.Form(
                summary = summary(),
                source = PoFSource.BANK_STATEMENT,
                amountRaw = "1234.50",
                documentKey = "kyc/pof/x.jpg",
                documentLabel = "doc.jpg",
                submitEnabled = true,
            ),
        )
        rule.onNodeWithTag(ProofOfFundsTestTags.SUBMIT, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun status_showsStatusPanelAndResubmit() {
        launchStatus(
            ProofOfFundsUiState.Status(
                summary = summary(),
                latest = submission(PoFStatus.NEEDS_MORE_INFO),
                history = listOf(submission(PoFStatus.NEEDS_MORE_INFO)),
                canResubmit = true,
            ),
        )
        rule.onNodeWithTag(ProofOfFundsTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ProofOfFundsTestTags.RESUBMIT, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun status_verified_hidesResubmit() {
        launchStatus(
            ProofOfFundsUiState.Status(
                summary = summary(),
                latest = submission(PoFStatus.VERIFIED),
                history = listOf(submission(PoFStatus.VERIFIED)),
                canResubmit = false,
            ),
        )
        rule.onNodeWithTag(ProofOfFundsTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ProofOfFundsTestTags.RESUBMIT, useUnmergedTree = true).assertDoesNotExist()
    }

    private fun summary() = PoFSummary(
        count = 1,
        verifiedCount = 0,
        activeRiskContribution = 0.1,
        verifiedAmountCents = null,
        verifiedCategories = emptyList(),
        userSub = null,
    )

    private fun submission(status: PoFStatus) = ProofOfFunds(
        submissionId = "sub_1",
        status = status,
        source = PoFSource.BANK_STATEMENT,
        declaredAmountCents = 250_00L,
        currency = "USD",
        documentS3Key = "kyc/pof/x.jpg",
        note = "see attached",
        reviewerNote = if (status.invitesResubmit) "needs work" else null,
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
    )
}
