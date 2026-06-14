package com.testlogon.android.feature.kyc.facial

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.facial.model.FaceComparison
import com.testlogon.android.feature.kyc.facial.model.FaceResult
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.time.Instant

/**
 * AND-323 - Compose UI smoke tests for the stateless [FaceComparisonScreen]. An in-test reducer over a
 * remembered [FaceComparisonUiState] drives the screen; actions swap the state so the rendered surface can be
 * asserted (no VM / Hilt). useUnmergedTree for non-merging surfaces; assertDoesNotExist is used as a MEMBER on
 * the node.
 */
@RunWith(AndroidJUnit4::class)
class FaceComparisonScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: FaceComparisonUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                FaceComparisonScreen(
                    state = state,
                    onTakeSelfie = {},
                    onPickPhoto = {},
                    onRetake = {
                        state = state.copy(capturedFile = null, phase = FacePhase.CAPTURE)
                    },
                    onSubmit = { state = state.copy(phase = FacePhase.SUBMITTING, submitting = true) },
                    onRetryAfterFail = {
                        state = state.copy(phase = FacePhase.CAPTURE, capturedFile = null, result = null)
                    },
                    onDone = {},
                )
            }
        }
    }

    @Test
    fun capture_showsButtons_andAutoCaptureUnavailableNote() {
        launch(FaceComparisonUiState(phase = FacePhase.CAPTURE, autoCaptureUnavailable = true))
        rule.onNodeWithTag(FaceComparisonTestTags.TAKE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.PICK, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.UNAVAILABLE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun review_showsRetakeAndSubmit() {
        launch(FaceComparisonUiState(phase = FacePhase.REVIEW, capturedFile = File("selfie.jpg")))
        rule.onNodeWithTag(FaceComparisonTestTags.RETAKE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.SUBMIT, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun result_pass_showsResult_andDone_noRetry() {
        launch(
            FaceComparisonUiState(
                phase = FacePhase.RESULT,
                result = comparison(FaceResult.PASS, remaining = 2),
            ),
        )
        rule.onNodeWithTag(FaceComparisonTestTags.RESULT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.DONE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.RETRY).assertDoesNotExist()
    }

    @Test
    fun result_failWithRemaining_showsRetry() {
        launch(
            FaceComparisonUiState(
                phase = FacePhase.RESULT,
                result = comparison(FaceResult.FAIL, remaining = 1),
            ),
        )
        rule.onNodeWithTag(FaceComparisonTestTags.RESULT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.RETRY, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.DONE).assertDoesNotExist()
    }

    @Test
    fun result_failNoRemaining_noRetry_noDone() {
        launch(
            FaceComparisonUiState(
                phase = FacePhase.RESULT,
                result = comparison(FaceResult.FAIL, remaining = 0),
            ),
        )
        rule.onNodeWithTag(FaceComparisonTestTags.RESULT, useUnmergedTree = true).assertIsDisplayed()
        // No attempts left -> contact-support text, neither retry nor done affordance.
        rule.onNodeWithTag(FaceComparisonTestTags.RETRY).assertDoesNotExist()
        rule.onNodeWithTag(FaceComparisonTestTags.DONE).assertDoesNotExist()
    }

    @Test
    fun result_review_isNeutral_showsDone_noRetry() {
        launch(
            FaceComparisonUiState(
                phase = FacePhase.RESULT,
                result = comparison(FaceResult.REVIEW, remaining = 2),
            ),
        )
        rule.onNodeWithTag(FaceComparisonTestTags.RESULT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.DONE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(FaceComparisonTestTags.RETRY).assertDoesNotExist()
    }

    @Test
    fun history_isShownWhenPresent() {
        launch(
            FaceComparisonUiState(
                phase = FacePhase.CAPTURE,
                history = listOf(comparison(FaceResult.FAIL, remaining = 1)),
            ),
        )
        rule.onNodeWithTag(FaceComparisonTestTags.HISTORY, useUnmergedTree = true).assertIsDisplayed()
    }

    private fun comparison(result: FaceResult, remaining: Int) = FaceComparison(
        comparisonId = "cmp_1",
        confidenceScore = if (result == FaceResult.PASS) 92 else 40,
        result = result,
        antiSpoofPassed = result == FaceResult.PASS,
        antiSpoofPassedChecks = if (result == FaceResult.PASS) 3 else 1,
        antiSpoofTotalChecks = 3,
        attemptNumber = 3 - remaining,
        maxAttempts = 3,
        remainingAttempts = remaining,
        createdAt = Instant.ofEpochSecond(1_780_000_000L),
    )
}
