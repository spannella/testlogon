package com.testlogon.android.feature.questionnaire.respond

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.model.questionnaire.RespondentSession
import com.testlogon.android.core.model.questionnaire.SessionStatus
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.questionnaire.render.QuestionFieldTestTags
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-349 - Compose UI tests for the stateless [RespondScreen] using an in-test reducer over
 * [RespondentSessionUiState]. Covers: Submit disabled until canSubmit; the submitting spinner; the
 * terminal Submitted confirmation + session id + Download PDF; an inline field error; and the error
 * retry surface. useUnmergedTree; assertDoesNotExist is a MEMBER.
 */
@RunWith(AndroidJUnit4::class)
class RespondScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val fields = listOf(
        QuestionnaireField.Text(
            questionId = "q1",
            sectionId = "s1",
            label = "Your name",
            required = true,
        ),
    )

    private fun session() = RespondentSession(
        sessionId = "rs_1",
        slug = "my-survey",
        questionnaireId = "q1",
        versionId = "v1",
        answers = emptyMap(),
        status = SessionStatus.IN_PROGRESS,
    )

    private fun render(
        initial: RespondentSessionUiState,
        onSubmit: () -> Unit = {},
        onDownloadPdf: () -> Unit = {},
        onRetry: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                var state by mutableStateOf(initial)
                RespondScreen(
                    state = state,
                    fields = fields,
                    onAnswerChanged = { _, _ -> },
                    onSubmit = onSubmit,
                    onDownloadPdf = onDownloadPdf,
                    onRetry = onRetry,
                    onReloadSchema = {},
                    onFirstErrorConsumed = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun submit_disabledUntilCanSubmit() {
        render(
            RespondentSessionUiState.Active(
                session = session(),
                answers = emptyMap(),
                canSubmit = false,
            ),
        )
        rule.onNodeWithTag(RespondTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(RespondTestTags.SUBMIT).assertIsNotEnabled()
    }

    @Test
    fun submit_enabledWhenCanSubmit_andClicks() {
        var submitted = false
        render(
            RespondentSessionUiState.Active(
                session = session(),
                answers = emptyMap(),
                canSubmit = true,
            ),
            onSubmit = { submitted = true },
        )
        rule.onNodeWithTag(RespondTestTags.SUBMIT).assertIsEnabled()
        rule.onNodeWithTag(RespondTestTags.SUBMIT).performClick()
        assertTrue(submitted)
    }

    @Test
    fun submitting_showsSpinner_andDisablesSubmit() {
        render(
            RespondentSessionUiState.Active(
                session = session(),
                answers = emptyMap(),
                canSubmit = true,
                submitting = true,
            ),
        )
        rule.onNodeWithTag(RespondTestTags.SUBMIT).assertIsNotEnabled()
        rule.onNodeWithTag(RespondTestTags.PROGRESS, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun submitted_showsConfirmation_sessionId_andDownloadPdf() {
        var downloaded = false
        render(
            RespondentSessionUiState.Submitted(
                sessionId = "rs_42",
                sessionStatus = SessionStatus.SUBMITTED,
            ),
            onDownloadPdf = { downloaded = true },
        )
        rule.onNodeWithTag(RespondTestTags.CONFIRMATION).assertIsDisplayed()
        rule.onNodeWithTag(RespondTestTags.SESSION_ID, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("rs_42", substring = true).assertIsDisplayed()
        rule.onNodeWithTag(RespondTestTags.DOWNLOAD_PDF).performClick()
        assertTrue(downloaded)
    }

    @Test
    fun activeBody_showsInlineFieldError() {
        render(
            RespondentSessionUiState.Active(
                session = session(),
                answers = emptyMap(),
                canSubmit = false,
                fieldErrors = mapOf("q1" to "This field is required"),
            ),
        )
        // The error text appears both as the field's supporting text (merged into the OutlinedTextField)
        // and as the dedicated error node; target the latter by its stable tag to avoid the ambiguity.
        rule.onNodeWithTag(QuestionFieldTestTags.error("q1"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun errorBody_retryInvokesCallback() {
        var retried = false
        render(
            RespondentSessionUiState.Error(
                com.testlogon.android.core.model.ApiError(
                    com.testlogon.android.core.model.ApiError.STATUS_NETWORK,
                    "Offline",
                ),
            ),
            onRetry = { retried = true },
        )
        rule.onNodeWithTag(RespondTestTags.ERROR_RETRY).performClick()
        assertEquals(true, retried)
    }
}
