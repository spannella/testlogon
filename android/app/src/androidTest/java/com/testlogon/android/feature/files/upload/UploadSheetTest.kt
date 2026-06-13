package com.testlogon.android.feature.files.upload

import android.net.Uri
import androidx.compose.foundation.layout.Column
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-333 - Compose UI tests for the upload rows. The rows are rendered directly (the ModalBottomSheet
 * container is exercised via the same stateless [UploadRow]); an in-test reducer mutates a
 * remember{mutableStateOf} List<UploadJob> so cancel / retry recomposition is observable.
 * useUnmergedTree is used for the per-row tag; assertDoesNotExist is a member assertion.
 */
@RunWith(AndroidJUnit4::class)
class UploadSheetTest {

    @get:Rule
    val rule = createComposeRule()

    private fun job(
        id: String,
        name: String,
        state: UploadState,
        progress: Float = 0f,
    ) = UploadJob(
        id = id,
        sourceUri = Uri.EMPTY,
        displayName = name,
        mimeType = "application/octet-stream",
        sizeBytes = 100L,
        targetFolderPath = "/docs",
        state = state,
        progress = progress,
    )

    private fun rows(initial: List<UploadJob>, onAction: (String) -> Unit = {}) {
        rule.setContent {
            TestLogonTheme {
                var jobs by remember { mutableStateOf(initial) }
                Column {
                    jobs.forEach { j ->
                        UploadRow(
                            job = j,
                            onCancel = { id ->
                                jobs = jobs.map { if (it.id == id) it.copy(state = UploadState.CANCELLED) else it }
                                onAction(id)
                            },
                            onRetry = { id ->
                                jobs = jobs.map { if (it.id == id) it.copy(state = UploadState.UPLOADING) else it }
                                onAction(id)
                            },
                            onDismissJob = onAction,
                        )
                    }
                }
            }
        }
    }

    @Test
    fun row_rendersName_progress_andCancel_whileUploading() {
        rows(listOf(job("1", "photo.jpg", UploadState.UPLOADING, progress = 0.5f)))
        rule.onNodeWithTag(UploadTestTags.row("1"), useUnmergedTree = true).assertExists()
        rule.onNodeWithText("photo.jpg").assertIsDisplayed()
        rule.onNodeWithTag(UploadTestTags.PROGRESS, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(UploadTestTags.CANCEL, useUnmergedTree = true).assertExists()
        // no retry while in-flight.
        rule.onNodeWithTag(UploadTestTags.RETRY, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun row_showsRetry_whenFailed_andNoProgress() {
        rows(listOf(job("2", "doc.pdf", UploadState.FAILED)))
        rule.onNodeWithTag(UploadTestTags.RETRY, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(UploadTestTags.CANCEL, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(UploadTestTags.PROGRESS, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun cancel_click_invokesCallback_andRecomposes() {
        var clicked: String? = null
        rows(listOf(job("3", "clip.mp4", UploadState.UPLOADING, progress = 0.2f))) { clicked = it }
        rule.onNodeWithTag(UploadTestTags.CANCEL, useUnmergedTree = true).performClick()
        rule.waitForIdle()
        assertEquals("3", clicked)
        // after cancel the row no longer offers a cancel control.
        rule.onNodeWithTag(UploadTestTags.CANCEL, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun retry_click_invokesCallback() {
        var clicked: String? = null
        rows(listOf(job("4", "a.bin", UploadState.FAILED))) { clicked = it }
        rule.onNodeWithTag(UploadTestTags.RETRY, useUnmergedTree = true).performClick()
        rule.waitForIdle()
        assertEquals("4", clicked)
    }
}
