package com.testlogon.android.feature.kyc.eidv

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.eidv.model.EidAssuranceLevel
import com.testlogon.android.feature.kyc.eidv.model.EidAuthFlow
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancy
import com.testlogon.android.feature.kyc.eidv.model.EidDiscrepancySeverity
import com.testlogon.android.feature.kyc.eidv.model.EidScheme
import com.testlogon.android.feature.kyc.eidv.model.EidVerification
import com.testlogon.android.feature.kyc.eidv.model.SchemeInfo
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-325 - Compose UI smoke tests for the stateless [EidvScreen]. An in-test reducer over a remembered
 * [EidvUiState] drives the screen (no VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist
 * is used as a MEMBER on the node.
 */
@RunWith(AndroidJUnit4::class)
class EidvScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: EidvUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                EidvScreen(
                    state = state,
                    onBack = {},
                    onSchemeSelected = { picked ->
                        (state as? EidvUiState.SchemeSelection)?.let { state = it.copy(selected = picked) }
                    },
                    onStart = {},
                    onReopen = {},
                    onCheckStatus = {},
                    onDone = {},
                    onRestart = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun schemeSelection_showsRows_and_startEnablesOnSelect() {
        launch(EidvUiState.SchemeSelection(schemes = listOf(scheme(EidScheme.EIDAS), scheme(EidScheme.DIGID))))
        rule.onNodeWithTag(EidvTestTags.SCREEN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.scheme(EidScheme.EIDAS), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.scheme(EidScheme.DIGID), useUnmergedTree = true).assertIsDisplayed()

        rule.onNodeWithTag(EidvTestTags.scheme(EidScheme.EIDAS), useUnmergedTree = true).performClick()
        rule.onNodeWithTag(EidvTestTags.START, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun awaiting_showsReopenAndCheck() {
        launch(
            EidvUiState.AwaitingProvider(
                caseId = "kyc_1",
                sessionId = "sess_1",
                scheme = EidScheme.EIDAS,
                redirectUrl = "https://eid.example/redirect/abc",
                expiresAt = 1_780_000_000L,
            ),
        )
        rule.onNodeWithTag(EidvTestTags.AWAITING, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.REOPEN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.CHECK_STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun result_showsDiscrepancyRows() {
        launch(
            EidvUiState.Result(
                caseId = "kyc_1",
                verification = verification(
                    discrepancies = listOf(
                        EidDiscrepancy("date_of_birth", "1990-01-01", "1990-02-01", EidDiscrepancySeverity.CRITICAL),
                    ),
                ),
                hasCriticalDiscrepancy = true,
                autoTierUpgrade = true,
            ),
        )
        rule.onNodeWithTag(EidvTestTags.RESULT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.discrepancy("date_of_birth"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun expired_showsRestart() {
        launch(EidvUiState.Expired)
        rule.onNodeWithTag(EidvTestTags.EXPIRED, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(EidvTestTags.RESTART, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun error_showsErrorSurface() {
        launch(EidvUiState.Error(message = "boom", retry = EidvUiState.Retry.LOAD))
        rule.onNodeWithTag(EidvTestTags.ERROR, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun awaiting_absentInSchemeSelection() {
        launch(EidvUiState.SchemeSelection(schemes = listOf(scheme(EidScheme.EIDAS))))
        rule.onNodeWithTag(EidvTestTags.AWAITING).assertDoesNotExist()
    }

    private fun scheme(scheme: EidScheme) = SchemeInfo(
        scheme = scheme,
        name = scheme.wire,
        assuranceLevel = EidAssuranceLevel.SUBSTANTIAL,
        authFlow = EidAuthFlow.BROWSER_REDIRECT,
        countries = listOf("NL"),
        description = "Test scheme",
    )

    private fun verification(discrepancies: List<EidDiscrepancy>) = EidVerification(
        assertionId = "assertion_1",
        assuranceLevel = EidAssuranceLevel.HIGH,
        verifiedAt = Instant.ofEpochSecond(1_779_990_000L),
        discrepancies = discrepancies,
    )
}
