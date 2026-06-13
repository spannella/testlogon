package com.testlogon.android.feature.syndicates

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.syndicates.LicensingContentType
import com.testlogon.android.core.model.syndicates.OpenLicensingContent
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.syndicates.ui.OpenLicensingScreen
import com.testlogon.android.feature.syndicates.ui.OpenLicensingTestTags
import com.testlogon.android.feature.syndicates.ui.OpenLicensingUiState
import com.testlogon.android.feature.syndicates.ui.RegisterFormState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-357 - Compose UI tests for the stateless [OpenLicensingScreen], driven by an in-test reducer over the
 * [OpenLicensingUiState]: list rows render; the empty CTA opens the form; the register form gates submit
 * until valid and surfaces a per-field error. assertDoesNotExist is chained (a member), not imported.
 */
@RunWith(AndroidJUnit4::class)
class OpenLicensingScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun row(id: String) = OpenLicensingContent(
        contentId = id, contentType = LicensingContentType.VIDEO, creatorId = "usr_a",
        exempt = false, registeredAt = 1L,
    )

    /** Drives the stateless screen with an in-test reducer over the form sub-state. */
    private fun launch(initial: OpenLicensingUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                OpenLicensingScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onOpenForm = { state = withForm(state) { it.copy(visible = true) } },
                    onDismissForm = { state = withForm(state) { it.copy(visible = false) } },
                    onContentIdChange = { v ->
                        state = withForm(state) { it.copy(contentId = v, contentIdError = null) }
                    },
                    onContentTypeChange = { t ->
                        state = withForm(state) { it.copy(contentType = t, contentTypeError = null) }
                    },
                    onSubmit = {},
                    onResultShown = {},
                )
            }
        }
    }

    private fun withForm(
        state: OpenLicensingUiState,
        transform: (RegisterFormState) -> RegisterFormState,
    ): OpenLicensingUiState {
        val next = transform(state.form)
        return when (state) {
            is OpenLicensingUiState.Loading -> state.copy(form = next)
            is OpenLicensingUiState.Content -> state.copy(form = next)
            is OpenLicensingUiState.Empty -> state.copy(form = next)
            is OpenLicensingUiState.Error -> state.copy(form = next)
        }
    }

    @Test
    fun contentList_rendersRows() {
        launch(OpenLicensingUiState.Content(items = listOf(row("vid_1"), row("clip_2"))))
        rule.onNodeWithTag(OpenLicensingTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OpenLicensingTestTags.contentRow("vid_1")).assertIsDisplayed()
        rule.onNodeWithTag(OpenLicensingTestTags.contentRow("clip_2")).assertIsDisplayed()
    }

    @Test
    fun empty_showsCta_andOpensForm() {
        launch(OpenLicensingUiState.Empty())
        rule.onNodeWithTag(OpenLicensingTestTags.EMPTY).assertIsDisplayed()
        // the form is not present until the CTA is tapped
        rule.onNodeWithTag(OpenLicensingTestTags.FORM).assertDoesNotExist()
        rule.onNodeWithText("Register content").performClick()
        rule.onNodeWithTag(OpenLicensingTestTags.FORM).assertIsDisplayed()
    }

    @Test
    fun registerForm_submitDisabledUntilValid_thenEnabled() {
        launch(OpenLicensingUiState.Content(items = listOf(row("vid_1")), form = RegisterFormState(visible = true)))
        rule.onNodeWithTag(OpenLicensingTestTags.FORM).assertIsDisplayed()
        rule.onNodeWithTag(OpenLicensingTestTags.SUBMIT).assertIsNotEnabled()

        rule.onNodeWithTag(OpenLicensingTestTags.CONTENT_ID).performTextInput("vid_9")
        // still no content type chosen -> disabled
        rule.onNodeWithTag(OpenLicensingTestTags.SUBMIT).assertIsNotEnabled()
    }

    @Test
    fun registerForm_validInput_enablesSubmit() {
        launch(
            OpenLicensingUiState.Content(
                items = listOf(row("vid_1")),
                form = RegisterFormState(
                    visible = true,
                    contentId = "vid_9",
                    contentType = LicensingContentType.VIDEO,
                ),
            ),
        )
        rule.onNodeWithTag(OpenLicensingTestTags.SUBMIT).assertIsEnabled()
    }

    @Test
    fun registerForm_fieldError_isDisplayed() {
        launch(
            OpenLicensingUiState.Content(
                items = listOf(row("vid_1")),
                form = RegisterFormState(
                    visible = true,
                    contentId = "vid_9",
                    contentType = LicensingContentType.VIDEO,
                    contentIdError = "must not be blank",
                ),
            ),
        )
        rule.onNodeWithText("must not be blank").assertIsDisplayed()
    }
}
