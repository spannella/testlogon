package com.testlogon.android.feature.files.download

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.files.download.CachedFile
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * AND-334 - Compose UI tests for the stateless download surface ([DownloadContent]). The body is rendered
 * directly (no ModalBottomSheet container) so reducer recomposition over a remember{mutableStateOf}
 * [FileDownloadUiState] is observable. useUnmergedTree is used for the per-control tags; assertDoesNotExist
 * is a member assertion (no import). The tags come from [DownloadTestTags].
 */
@RunWith(AndroidJUnit4::class)
class DownloadProgressTest {

    @get:Rule
    val rule = createComposeRule()

    private fun cached() = CachedFile(
        path = "/docs/report.bin",
        file = File("/tmp/report.bin"),
        mimeType = "application/pdf",
        displayName = "report.bin",
    )

    /**
     * Renders [DownloadContent] over a mutable [FileDownloadUiState]; [onCancel] flips the state to
     * Success so a cancel click's recomposition is observable. Each action callback records its name.
     */
    private fun content(
        initial: FileDownloadUiState,
        onAction: (String) -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                DownloadContent(
                    state = state,
                    fileName = "report.bin",
                    onCancel = {
                        state = FileDownloadUiState.Cancelled
                        onAction("cancel")
                    },
                    onOpen = { onAction("open") },
                    onSave = { onAction("save") },
                    onRetry = { onAction("retry") },
                )
            }
        }
    }

    @Test
    fun inProgress_showsProgress_andCancel_andNoOpenSave() {
        content(FileDownloadUiState.InProgress(fraction = 0.4f, bytesDownloaded = 4L, totalBytes = 10L))
        rule.onNodeWithTag(DownloadTestTags.PROGRESS, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DownloadTestTags.CANCEL, useUnmergedTree = true).assertExists()
        // the open / save affordances are Success-only.
        rule.onNodeWithTag(DownloadTestTags.OPEN, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(DownloadTestTags.SAVE, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun inProgress_indeterminate_stillShowsProgressBar() {
        // a null fraction (server omitted Content-Length) renders the indeterminate bar under the same tag.
        content(FileDownloadUiState.InProgress(fraction = null, bytesDownloaded = 0L, totalBytes = null))
        rule.onNodeWithTag(DownloadTestTags.PROGRESS, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DownloadTestTags.CANCEL, useUnmergedTree = true).assertExists()
    }

    @Test
    fun success_showsOpen_andSave_andNoProgressOrCancel() {
        content(FileDownloadUiState.Success(cached()))
        rule.onNodeWithTag(DownloadTestTags.OPEN, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DownloadTestTags.SAVE, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DownloadTestTags.PROGRESS, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(DownloadTestTags.CANCEL, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun cancel_click_invokesCallback_andRecomposesAwayFromProgress() {
        var clicked: String? = null
        content(FileDownloadUiState.InProgress(fraction = 0.2f, bytesDownloaded = 2L, totalBytes = 10L)) {
            clicked = it
        }
        rule.onNodeWithTag(DownloadTestTags.CANCEL, useUnmergedTree = true).performClick()
        rule.waitForIdle()
        assertEquals("cancel", clicked)
        // after cancel the surface no longer shows progress / cancel.
        rule.onNodeWithTag(DownloadTestTags.PROGRESS, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(DownloadTestTags.CANCEL, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun success_openAndSave_clicks_invokeCallbacks() {
        val clicks = mutableListOf<String>()
        content(FileDownloadUiState.Success(cached())) { clicks += it }
        rule.onNodeWithTag(DownloadTestTags.OPEN, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(DownloadTestTags.SAVE, useUnmergedTree = true).performClick()
        rule.waitForIdle()
        assertEquals(listOf("open", "save"), clicks)
    }

    @Test
    fun retryableError_showsRetry_andClickInvokesCallback() {
        var clicked: String? = null
        content(FileDownloadUiState.Error(message = "down", retryable = true)) { clicked = it }
        rule.onNodeWithTag(DownloadTestTags.RETRY, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DownloadTestTags.RETRY, useUnmergedTree = true).performClick()
        rule.waitForIdle()
        assertEquals("retry", clicked)
    }

    @Test
    fun nonRetryableError_hidesRetry() {
        content(FileDownloadUiState.Error(message = "forbidden", retryable = false))
        rule.onNodeWithTag(DownloadTestTags.RETRY, useUnmergedTree = true).assertDoesNotExist()
    }
}
