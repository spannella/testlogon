package com.testlogon.android.feature.signing.document

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.signing.document.model.DocumentRef
import com.testlogon.android.feature.signing.document.model.DocumentUiState
import com.testlogon.android.feature.signing.document.model.PageLayout
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-341 - Compose UI smoke tests for the stateless [DocumentViewerScreen], driven by FIXED UI states
 * (no VM / Hilt / real PdfRenderer; requestPage defaults to returning null so the placeholder path is
 * exercised). useUnmergedTree for non-merging surfaces; assertDoesNotExist is a MEMBER. An in-test
 * reducer (a mutableStateOf swap) verifies Retry drives a state change.
 */
@RunWith(AndroidJUnit4::class)
class DocumentViewerScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun ready(pageCount: Int = 2) = DocumentUiState.Ready(
        ref = DocumentRef(packetId = "pkt_1", displayName = "doc.pdf"),
        pageCount = pageCount,
        pages = (0 until pageCount).map { PageLayout(index = it, widthPts = 612f, heightPts = 792f) },
    )

    private fun launch(
        state: DocumentUiState,
        onRetry: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                DocumentViewerScreen(
                    state = state,
                    onBack = {},
                    onRetry = onRetry,
                )
            }
        }
    }

    @Test
    fun ready_showsPageItems_andLabels() {
        launch(ready(pageCount = 2))
        rule.onNodeWithTag(DocumentViewerTestTags.page(0), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(DocumentViewerTestTags.page(1), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun loading_showsSpinner() {
        launch(DocumentUiState.Loading)
        rule.onNodeWithTag(DocumentViewerTestTags.LOADING, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun error_showsRetry_whenRetryable() {
        launch(DocumentUiState.Error(message = "boom", retryable = true))
        rule.onNodeWithTag(DocumentViewerTestTags.RETRY, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun error_hidesRetry_whenNotRetryable() {
        launch(DocumentUiState.Error(message = "gone", retryable = false))
        rule.onNodeWithTag(DocumentViewerTestTags.RETRY, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun retry_firesThroughInTestReducer() {
        var retries = 0
        var state by mutableStateOf<DocumentUiState>(
            DocumentUiState.Error(message = "boom", retryable = true),
        )
        rule.setContent {
            TestLogonTheme {
                DocumentViewerScreen(
                    state = state,
                    onBack = {},
                    onRetry = {
                        retries++
                        state = DocumentUiState.Loading
                    },
                )
            }
        }
        rule.onNodeWithTag(DocumentViewerTestTags.RETRY, useUnmergedTree = true).performClick()
        rule.runOnIdle { assertEquals(1, retries) }
        // After the reducer swap to Loading, the retry button is gone and the spinner is shown.
        rule.onNodeWithTag(DocumentViewerTestTags.RETRY, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(DocumentViewerTestTags.LOADING, useUnmergedTree = true).assertIsDisplayed()
    }
}
