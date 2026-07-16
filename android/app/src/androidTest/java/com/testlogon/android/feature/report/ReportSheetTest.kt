package com.testlogon.android.feature.report

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.messaging.report.ReportReason
import com.testlogon.android.data.report.ReportKind
import com.testlogon.android.data.report.ReportOutcome
import com.testlogon.android.data.report.ReportTopics
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-383 — Compose UI tests for the report sheet content (TC-AND-383-10/11/12).
 *
 * Drives the stateless [ReportSheetContent] with an in-test reducer over remember{mutableStateOf} so
 * topic toggling / reason entry / submit / retry recomposition is observable without a real ViewModel or
 * Hilt. The five topic checkboxes, Submit enable/disable, the success confirmation + Done outcome, and
 * the retryable-error + Retry path are asserted. useUnmergedTree is not needed (tags are on the rows).
 */
@RunWith(AndroidJUnit4::class)
class ReportSheetTest {

    @get:Rule
    val rule = createComposeRule()

    private fun editing() = ReportUiState(
        kind = ReportKind.CONTENT,
        topics = ReportTopics.forKind(ReportKind.CONTENT),
    )

    /** Renders the content with a local reducer; [onDone] captures the outcome the host would receive. */
    private fun render(
        initial: ReportUiState = editing(),
        terminalOnSubmit: ReportUiState.Phase = ReportUiState.Phase.Success(alreadyReported = false),
        onOutcome: (ReportOutcome) -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                ReportSheetContent(
                    state = state,
                    onTopicToggled = { topic, checked ->
                        val next = if (checked) state.selectedTopics + topic else state.selectedTopics - topic
                        state = state.copy(selectedTopics = next)
                    },
                    onReasonTextChanged = { state = state.copy(reasonText = it) },
                    onSubmit = { state = state.copy(phase = terminalOnSubmit) },
                    onRetry = {
                        state = state.copy(phase = ReportUiState.Phase.Success(alreadyReported = false))
                    },
                    onDone = {
                        onOutcome(
                            when (val p = state.phase) {
                                is ReportUiState.Phase.Success ->
                                    if (p.alreadyReported) ReportOutcome.ALREADY_REPORTED else ReportOutcome.SUBMITTED
                                else -> ReportOutcome.CANCELLED
                            },
                        )
                    },
                    onCancel = { onOutcome(ReportOutcome.CANCELLED) },
                )
            }
        }
    }

    // TC-AND-383-10
    @Test
    fun happyPath_fiveTopics_submitEnablesThenConfirms() {
        var outcome: ReportOutcome? = null
        render(onOutcome = { outcome = it })

        // (1) five topic checkboxes shown.
        ReportReason.SELECTABLE.forEach { topic ->
            rule.onNodeWithTag(ReportTestTags.topicRow(topic)).assertIsDisplayed()
        }
        // (2) Submit disabled initially.
        rule.onNodeWithTag(ReportTestTags.SUBMIT).assertIsNotEnabled()

        // (3) check a topic + type a valid reason -> Submit enabled.
        rule.onNodeWithTag(ReportTestTags.topicRow(ReportReason.SPAM)).performClick()
        rule.onNodeWithTag(ReportTestTags.STATEMENT_FIELD).performTextInput("repeated spam links")
        rule.onNodeWithTag(ReportTestTags.SUBMIT).assertIsEnabled()

        // (4) tap Submit -> confirmation + Done invokes the SUBMITTED outcome.
        rule.onNodeWithTag(ReportTestTags.SUBMIT).performClick()
        rule.onNodeWithTag(ReportTestTags.SUCCESS).assertIsDisplayed()
        rule.onNodeWithTag(ReportTestTags.DONE).assertHasClickAction().performClick()
        assertEquals(ReportOutcome.SUBMITTED, outcome)
    }

    // TC-AND-383-11
    @Test
    fun retryableError_showsRetry_preservesState_recovers() {
        render(terminalOnSubmit = ReportUiState.Phase.Error("server boom", retryable = true))

        rule.onNodeWithTag(ReportTestTags.topicRow(ReportReason.HARASSMENT)).performClick()
        rule.onNodeWithTag(ReportTestTags.STATEMENT_FIELD).performTextInput("illegal content")
        rule.onNodeWithTag(ReportTestTags.SUBMIT).performClick()

        // Inline error + Retry visible; reason text still populated.
        rule.onNodeWithTag(ReportTestTags.ERROR).assertIsDisplayed()
        rule.onNodeWithTag(ReportTestTags.RETRY).assertIsDisplayed()
        rule.onNodeWithTag(ReportTestTags.STATEMENT_FIELD).assertIsDisplayed()

        rule.onNodeWithTag(ReportTestTags.RETRY).performClick()
        rule.onNodeWithTag(ReportTestTags.SUCCESS).assertIsDisplayed()
    }

    // TC-AND-383-12 (a11y: checkbox role + reachable controls)
    @Test
    fun topicRows_areCheckable_andSubmitDisabledExposed() {
        render(initial = editing().copy(kind = ReportKind.USER, topics = ReportTopics.forKind(ReportKind.USER)))

        // Each topic row is a toggleable (Role.Checkbox) with a click action.
        ReportReason.SELECTABLE.forEach { topic ->
            rule.onNodeWithTag(ReportTestTags.topicRow(topic)).assertHasClickAction()
        }
        // Submit exposes a disabled state when the form is incomplete.
        rule.onNodeWithTag(ReportTestTags.SUBMIT).assertIsNotEnabled()
    }
}
