package com.testlogon.android.feature.kyc

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.model.Requirement
import com.testlogon.android.feature.kyc.model.Tier
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-320 — Compose UI smoke tests for the stateless [TierStatusScreen]. An in-test reducer over a
 * remembered [TierUiState] drives the screen; the actions just swap the state so the rendered surface can
 * be asserted (no VM / Hilt in the UI test).
 */
@RunWith(AndroidJUnit4::class)
class TierStatusScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: TierUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                TierStatusScreen(
                    state = state,
                    snackbarHostState = remember { SnackbarHostState() },
                    onBack = {},
                    onEvaluate = {
                        // Reduce: flip evaluating so the in-progress affordance is observable.
                        (state as? TierUiState.Content)?.let { state = it.copy(evaluating = true) }
                    },
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun content_showsCurrentTierCard_andRequirementRows() {
        launch(
            TierUiState.Content(
                current = Tier(1),
                updatedAt = null,
                target = Tier(2),
                requirements = listOf(
                    Requirement("email_verified", met = true),
                    Requirement("phone_verified", met = false),
                ),
                eligibleForTarget = false,
                history = emptyList(),
            ),
        )
        rule.onNodeWithTag(TierStatusTestTags.CURRENT).assertIsDisplayed()
        rule.onNodeWithTag(TierStatusTestTags.requirement("email_verified"), useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(TierStatusTestTags.requirement("phone_verified"), useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun content_belowMax_showsEvaluate_andNoMaxNotice() {
        launch(
            TierUiState.Content(
                current = Tier(2),
                updatedAt = null,
                target = Tier(3),
                requirements = listOf(Requirement("proof_of_address", met = false)),
                eligibleForTarget = false,
                history = emptyList(),
            ),
        )
        rule.onNodeWithTag(TierStatusTestTags.EVALUATE).assertIsDisplayed()
        rule.onNodeWithTag(TierStatusTestTags.MAX).assertDoesNotExist()
    }

    @Test
    fun maxTier_hidesEvaluate_showsTerminalMessage() {
        launch(
            TierUiState.Content(
                current = Tier(4),
                updatedAt = null,
                target = null,
                requirements = emptyList(),
                eligibleForTarget = false,
                history = emptyList(),
            ),
        )
        rule.onNodeWithTag(TierStatusTestTags.MAX).assertIsDisplayed()
        rule.onNodeWithTag(TierStatusTestTags.EVALUATE).assertDoesNotExist()
    }

    @Test
    fun eligible_showsEligibilityBanner() {
        launch(
            TierUiState.Content(
                current = Tier(1),
                updatedAt = null,
                target = Tier(2),
                requirements = listOf(Requirement("email_verified", met = true)),
                eligibleForTarget = true,
                history = emptyList(),
            ),
        )
        rule.onNodeWithTag(TierStatusTestTags.ELIGIBLE).assertIsDisplayed()
    }
}
