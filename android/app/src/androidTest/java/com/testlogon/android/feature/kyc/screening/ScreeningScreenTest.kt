package com.testlogon.android.feature.kyc.screening

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.screening.model.KycScreenResult
import com.testlogon.android.feature.kyc.screening.model.KycScreenType
import com.testlogon.android.feature.kyc.screening.model.KycScreeningResult
import com.testlogon.android.feature.kyc.screening.model.ScreeningStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-328 - Compose UI smoke tests for the stateless [ScreeningScreen]. An in-test reducer over a remembered
 * [ScreeningUiState] drives the screen (no VM / Hilt). useUnmergedTree for non-merging surfaces;
 * assertDoesNotExist is a MEMBER.
 */
@RunWith(AndroidJUnit4::class)
class ScreeningScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: ScreeningUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                ScreeningScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    // Retry swaps the error/stale surface to a fresh Content so the action is observable.
                    onRetry = {
                        state = ScreeningUiState.Content(
                            status = ScreeningStatus.CLEAR,
                            results = listOf(result(KycScreenResult.CLEAR, KycScreenType.SANCTIONS_OFAC)),
                        )
                    },
                )
            }
        }
    }

    @Test
    fun clear_rendersStatusCard() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.CLEAR,
                results = listOf(result(KycScreenResult.CLEAR, KycScreenType.SANCTIONS_OFAC)),
            ),
        )
        rule.onNodeWithTag(ScreeningTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun hit_rendersStatusCard() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.HIT,
                results = listOf(result(KycScreenResult.CONFIRMED_MATCH, KycScreenType.SANCTIONS_OFAC)),
            ),
        )
        rule.onNodeWithTag(ScreeningTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun review_rendersStatusCard() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.REVIEW,
                results = listOf(result(KycScreenResult.POTENTIAL_MATCH, KycScreenType.PEP_CHECK)),
            ),
        )
        rule.onNodeWithTag(ScreeningTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun notStarted_rendersStatusCard_andNoBreakdown() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.NOT_STARTED,
                results = emptyList(),
            ),
        )
        rule.onNodeWithTag(ScreeningTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(
            ScreeningTestTags.result(KycScreenType.SANCTIONS_OFAC),
            useUnmergedTree = true,
        ).assertDoesNotExist()
    }

    @Test
    fun content_rendersPerScreenBreakdown() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.REVIEW,
                results = listOf(
                    result(KycScreenResult.CLEAR, KycScreenType.SANCTIONS_OFAC),
                    result(KycScreenResult.POTENTIAL_MATCH, KycScreenType.PEP_CHECK),
                ),
            ),
        )
        rule.onNodeWithTag(
            ScreeningTestTags.result(KycScreenType.SANCTIONS_OFAC),
            useUnmergedTree = true,
        ).assertIsDisplayed()
        rule.onNodeWithTag(
            ScreeningTestTags.result(KycScreenType.PEP_CHECK),
            useUnmergedTree = true,
        ).assertIsDisplayed()
    }

    @Test
    fun staleContent_showsStaleBanner_andRetry() {
        launch(
            ScreeningUiState.Content(
                status = ScreeningStatus.CLEAR,
                results = listOf(result(KycScreenResult.CLEAR, KycScreenType.SANCTIONS_OFAC)),
                isStale = true,
                lastUpdated = Instant.ofEpochSecond(1_780_000_000L),
            ),
        )
        rule.onNodeWithTag(ScreeningTestTags.STALE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ScreeningTestTags.RETRY, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun error_showsRetry() {
        launch(ScreeningUiState.Error(message = "Couldn't load", retryable = true))
        rule.onNodeWithTag(ScreeningTestTags.RETRY, useUnmergedTree = true).assertIsDisplayed()
    }

    private fun result(res: KycScreenResult, type: KycScreenType) = KycScreeningResult(
        result = res,
        screenType = type,
        screenedAt = Instant.ofEpochSecond(1_780_000_000L),
        matchCount = null,
    )
}
