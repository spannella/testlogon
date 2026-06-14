package com.testlogon.android.feature.kyc.residency

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performScrollTo
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.residency.model.AddrDecision
import com.testlogon.android.feature.kyc.residency.model.AddrStatus
import com.testlogon.android.feature.kyc.residency.model.AddressVerification
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocType
import com.testlogon.android.feature.kyc.residency.model.ResidencyDocument
import com.testlogon.android.feature.kyc.residency.model.ResidencyStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-326 - Compose UI smoke tests for the stateless [ResidencyScreen]. An in-test reducer over a remembered
 * [ResidencyUiState] drives the screen; actions swap the state so the rendered surface can be asserted (no VM
 * / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is used as a MEMBER on the node.
 */
@RunWith(AndroidJUnit4::class)
class ResidencyScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(
        initial: ResidencyUiState,
        canVerifyAddress: Boolean = true,
    ) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                ResidencyScreen(
                    state = state,
                    canVerifyAddress = canVerifyAddress,
                    onBack = {},
                    onProofTypeSelected = { type ->
                        (state as? ResidencyUiState.Editing)?.let {
                            state = it.copy(
                                selectedProofType = type,
                                submitEnabled = it.issuingEntity.isNotBlank() &&
                                    it.documentDate.isNotBlank() && it.proof != null,
                            )
                        }
                    },
                    onIssuerChanged = { v ->
                        (state as? ResidencyUiState.Editing)?.let { state = it.copy(issuingEntity = v) }
                    },
                    onDateChanged = { v ->
                        (state as? ResidencyUiState.Editing)?.let { state = it.copy(documentDate = v) }
                    },
                    onCapture = {},
                    onPick = {},
                    onRemoveProof = {},
                    onAddressFieldChanged = { transform ->
                        (state as? ResidencyUiState.Editing)?.let {
                            state = it.copy(addressForm = transform(it.addressForm))
                        }
                    },
                    onSubmitResidency = {},
                    onVerifyAddress = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun editing_showsProofAndAddressControls() {
        launch(ResidencyUiState.Editing())
        rule.onNodeWithTag(ResidencyTestTags.TYPE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ResidencyTestTags.ISSUER, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ResidencyTestTags.CAPTURE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ResidencyTestTags.PICK, useUnmergedTree = true).assertIsDisplayed()
        // The address controls live below the fold in the verticalScroll Column - scroll them into view.
        rule.onNodeWithTag(ResidencyTestTags.ADDRESS_LINE1, useUnmergedTree = true)
            .performScrollTo().assertIsDisplayed()
        rule.onNodeWithTag(ResidencyTestTags.ADDRESS_VERIFY, useUnmergedTree = true)
            .performScrollTo().assertIsDisplayed()
    }

    @Test
    fun editing_submitDisabledUntilFormComplete() {
        launch(
            ResidencyUiState.Editing(
                selectedProofType = ResidencyDocType.UTILITY_BILL,
                issuingEntity = "Acme",
                documentDate = "2026-05-01",
                proof = ProofAttachment(java.io.File("bill.jpg"), "bill.jpg"),
                submitEnabled = true,
            ),
        )
        rule.onNodeWithTag(ResidencyTestTags.SUBMIT, useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun editing_submitDisabledWhenIncomplete() {
        launch(ResidencyUiState.Editing(submitEnabled = false))
        rule.onNodeWithTag(ResidencyTestTags.SUBMIT, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun editing_verifyDisabledWithoutCase() {
        launch(ResidencyUiState.Editing(), canVerifyAddress = false)
        rule.onNodeWithTag(ResidencyTestTags.ADDRESS_VERIFY, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun pendingStatus_showsStatusPanel() {
        launch(ResidencyUiState.Pending(document(ResidencyStatus.PENDING)))
        rule.onNodeWithTag(ResidencyTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun rejectedStatus_showsStatusPanel() {
        launch(ResidencyUiState.Rejected(document(ResidencyStatus.REJECTED), reason = "blurry"))
        rule.onNodeWithTag(ResidencyTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun addressResult_showsResultSurface() {
        launch(ResidencyUiState.AddressResult(verification()))
        rule.onNodeWithTag(ResidencyTestTags.ADDRESS_RESULT, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun addressResultInline_isShownWhenPresentInEditing() {
        launch(ResidencyUiState.Editing(addressResult = verification()))
        // The inline address-result card is the last element in the verticalScroll Column - scroll to it.
        rule.onNodeWithTag(ResidencyTestTags.ADDRESS_RESULT, useUnmergedTree = true)
            .performScrollTo().assertIsDisplayed()
    }

    private fun document(status: ResidencyStatus) = ResidencyDocument(
        documentId = "doc_1",
        docType = ResidencyDocType.UTILITY_BILL,
        status = status,
        fileName = "bill.jpg",
        issuingEntity = "Acme Power",
        documentDate = "2026-05-01",
        reviewNote = if (status == ResidencyStatus.REJECTED) "blurry" else null,
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
    )

    private fun verification() = AddressVerification(
        status = AddrStatus.PARTIAL_MATCH,
        decision = AddrDecision.NEEDS_REVIEW,
        discrepancies = listOf("postal_code"),
        confidenceScore = 72,
        standardizedAddress = mapOf("line_1" to "MAIN ST 1"),
    )
}
