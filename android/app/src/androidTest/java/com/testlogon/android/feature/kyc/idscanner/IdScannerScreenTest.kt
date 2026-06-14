package com.testlogon.android.feature.kyc.idscanner

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.idscanner.model.ExtractionSummary
import com.testlogon.android.feature.kyc.idscanner.model.IdDocumentType
import com.testlogon.android.feature.kyc.idscanner.model.IdSide
import com.testlogon.android.feature.kyc.idscanner.model.ScanResult
import com.testlogon.android.feature.kyc.idscanner.model.ScanStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * AND-322 - Compose UI smoke tests for the stateless [IdScannerScreen]. An in-test reducer over a remembered
 * [IdScannerUiState] drives the screen; actions swap the state so the rendered surface can be asserted (no VM
 * / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is used as a MEMBER on the node.
 */
@RunWith(AndroidJUnit4::class)
class IdScannerScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: IdScannerUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                IdScannerScreen(
                    state = state,
                    onSelectType = {
                        state = state.copy(
                            selectedType = it,
                            step = IdScannerStep.CAPTURE,
                            currentSide = IdSide.FRONT,
                            mediaUnavailable = true,
                        )
                    },
                    onTakePhoto = {},
                    onPickFromLibrary = {},
                    onRetake = {
                        state = state.copy(captured = state.captured - it, step = IdScannerStep.CAPTURE)
                    },
                    onConfirm = { state = state.copy(step = IdScannerStep.UPLOADING) },
                    onRestart = { state = state.copy(step = IdScannerStep.CAPTURE, results = emptyList()) },
                    onDone = {},
                )
            }
        }
    }

    @Test
    fun typeSelect_showsAllFourTypes() {
        launch(IdScannerUiState(step = IdScannerStep.TYPE_SELECT))
        rule.onNodeWithTag(IdScannerTestTags.typeTag(IdDocumentType.PASSPORT), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.typeTag(IdDocumentType.NATIONAL_ID_CARD), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.typeTag(IdDocumentType.DRIVING_LICENSE), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.typeTag(IdDocumentType.RESIDENCE_PERMIT), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun capture_showsButtons_andAutoCaptureUnavailableNote() {
        launch(
            IdScannerUiState(
                step = IdScannerStep.CAPTURE,
                selectedType = IdDocumentType.PASSPORT,
                currentSide = IdSide.FRONT,
                mediaUnavailable = true,
            ),
        )
        rule.onNodeWithTag(IdScannerTestTags.TAKE_PHOTO, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.PICK, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.UNAVAILABLE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun review_showsRetakePerSide_andConfirm() {
        launch(
            IdScannerUiState(
                step = IdScannerStep.REVIEW,
                selectedType = IdDocumentType.NATIONAL_ID_CARD,
                captured = mapOf(
                    IdSide.FRONT to CapturedSide(IdSide.FRONT, File("front.jpg")),
                    IdSide.BACK to CapturedSide(IdSide.BACK, File("back.jpg")),
                ),
            ),
        )
        rule.onNodeWithTag(IdScannerTestTags.retakeTag(IdSide.FRONT), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.retakeTag(IdSide.BACK), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.CONFIRM, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun result_success_showsRowsAndNoRestart() {
        launch(
            IdScannerUiState(
                step = IdScannerStep.RESULT,
                selectedType = IdDocumentType.PASSPORT,
                results = listOf(result(IdSide.FRONT, ScanStatus.MATCHED)),
            ),
        )
        rule.onNodeWithTag(IdScannerTestTags.resultTag(IdSide.FRONT), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.RESTART).assertDoesNotExist()
    }

    @Test
    fun result_flagged_showsRow() {
        launch(
            IdScannerUiState(
                step = IdScannerStep.RESULT,
                selectedType = IdDocumentType.PASSPORT,
                results = listOf(result(IdSide.FRONT, ScanStatus.FLAGGED)),
            ),
        )
        rule.onNodeWithTag(IdScannerTestTags.resultTag(IdSide.FRONT), useUnmergedTree = true).assertIsDisplayed()
        // Flagged is not a failure, so no restart affordance.
        rule.onNodeWithTag(IdScannerTestTags.RESTART).assertDoesNotExist()
    }

    @Test
    fun result_failure_showsRestart() {
        launch(
            IdScannerUiState(
                step = IdScannerStep.RESULT,
                selectedType = IdDocumentType.PASSPORT,
                results = listOf(result(IdSide.FRONT, ScanStatus.REJECTED)),
            ),
        )
        rule.onNodeWithTag(IdScannerTestTags.resultTag(IdSide.FRONT), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(IdScannerTestTags.RESTART, useUnmergedTree = true).assertIsDisplayed()
    }

    private fun result(side: IdSide, status: ScanStatus) = ScanResult(
        scanId = "scan_${side.fileType}",
        side = side,
        status = status,
        mrzValid = true,
        reason = if (status == ScanStatus.REJECTED) "Document expired" else null,
        extraction = ExtractionSummary(null, null, null, null, null),
        imageUrl = null,
    )
}
