package com.testlogon.android.feature.boost

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.ads.BoostStatus
import com.testlogon.android.core.model.ads.ContentBoost
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-364 - Compose UI tests for the stateless [BoostScreen]. Drives an in-test reducer over
 * [BoostUiState] (USD -> cents / minutes -> seconds, mirroring the VM) so gating + status rendering are
 * exercised without Hilt. useUnmergedTree for nested controls; assertDoesNotExist is used as a MEMBER (a
 * chain call, not an import).
 */
@RunWith(AndroidJUnit4::class)
class BoostScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: BoostUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                BoostScreen(
                    state = state,
                    onBack = {},
                    onBudgetChanged = { text ->
                        (state as? BoostUiState.Form)?.let { form ->
                            val cents = parseUsd(text)
                            state = form.copy(
                                budgetText = text,
                                budgetCents = cents,
                                canSubmit = cents >= 1L && form.durationSeconds >= 1L,
                            )
                        }
                    },
                    onDurationChanged = { text ->
                        (state as? BoostUiState.Form)?.let { form ->
                            val seconds = (text.trim().toLongOrNull() ?: 0L).coerceAtLeast(0L) * 60L
                            state = form.copy(
                                durationMinutesText = text,
                                durationSeconds = seconds,
                                canSubmit = form.budgetCents >= 1L && seconds >= 1L,
                            )
                        }
                    },
                    onSubmit = {},
                    onCancel = {},
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    private fun parseUsd(text: String): Long {
        val cleaned = text.trim().removePrefix("$")
        if (cleaned.isEmpty()) return 0L
        val dollars = cleaned.toBigDecimalOrNull() ?: return 0L
        if (dollars.signum() < 0) return 0L
        return dollars.movePointRight(2).toLong()
    }

    private fun form(
        budget: String = "5.00",
        budgetCents: Long = 500L,
        minutes: String = "60",
        durationSeconds: Long = 3600L,
    ) = BoostUiState.Form(
        budgetText = budget,
        durationMinutesText = minutes,
        budgetCents = budgetCents,
        durationSeconds = durationSeconds,
        canSubmit = budgetCents >= 1L && durationSeconds >= 1L,
    )

    private fun status(statusEnum: BoostStatus, raw: String) = BoostUiState.Status(
        boost = ContentBoost(
            boostId = "bst_1",
            status = raw,
            statusEnum = statusEnum,
            budgetCents = 500L,
            spentCents = 100L,
            remainingCents = 400L,
            durationSeconds = 3600L,
            endsAt = 1700003600L,
        ),
        canCancel = statusEnum == BoostStatus.ACTIVE,
    )

    @Test
    fun form_renders_submitEnabledWhenValid() {
        launch(form())
        rule.onNodeWithTag(BoostTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.BUDGET, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.DURATION, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.SUBMIT).assertIsEnabled()
    }

    @Test
    fun submit_disabledWhenBudgetZero() {
        launch(form())
        rule.onNodeWithTag(BoostTestTags.BUDGET, useUnmergedTree = true).performTextReplacement("0")
        rule.onNodeWithTag(BoostTestTags.SUBMIT).assertIsNotEnabled()
    }

    @Test
    fun submit_disabledWhenDurationZero() {
        launch(form())
        rule.onNodeWithTag(BoostTestTags.DURATION, useUnmergedTree = true).performTextReplacement("0")
        rule.onNodeWithTag(BoostTestTags.SUBMIT).assertIsNotEnabled()
    }

    @Test
    fun status_active_showsValueAndCancel() {
        launch(status(BoostStatus.ACTIVE, "active"))
        rule.onNodeWithTag(BoostTestTags.STATUS).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.STATUS_VALUE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.CANCEL).assertIsDisplayed()
    }

    @Test
    fun status_completed_hidesCancel() {
        launch(status(BoostStatus.COMPLETED, "completed"))
        rule.onNodeWithTag(BoostTestTags.STATUS).assertIsDisplayed()
        rule.onNodeWithTag(BoostTestTags.CANCEL).assertDoesNotExist()
    }
}
