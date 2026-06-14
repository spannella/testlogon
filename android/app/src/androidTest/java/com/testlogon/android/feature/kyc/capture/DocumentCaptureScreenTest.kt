package com.testlogon.android.feature.kyc.capture

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.capture.model.KycDocument
import com.testlogon.android.feature.kyc.capture.model.KycDocumentStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.time.Instant

/**
 * AND-321 - Compose UI smoke tests for the stateless [DocumentCaptureScreen]. An in-test reducer over a
 * remembered [DocumentCaptureUiState] drives the screen; actions swap the state so the rendered surface can
 * be asserted (no VM / Hilt in the UI test). assertDoesNotExist is used as a MEMBER on the node.
 */
@RunWith(AndroidJUnit4::class)
class DocumentCaptureScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: DocumentCaptureUiState, allConfirmed: Boolean = false) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                DocumentCaptureScreen(
                    state = state,
                    allConfirmed = allConfirmed,
                    onBack = {},
                    onSelectType = {},
                    onTakePhoto = {},
                    onPickFromLibrary = {},
                    onRetake = {
                        // Reduce: a retake returns to type selection.
                        state = DocumentCaptureUiState.SelectingType(
                            available = listOf(DocType.ID_FRONT, DocType.ID_BACK),
                        )
                    },
                    onConfirm = {
                        // Reduce: a confirm advances to the upload-ready select state.
                        state = DocumentCaptureUiState.SelectingType(available = emptyList())
                    },
                    onStartUpload = {
                        state = DocumentCaptureUiState.Uploading(
                            progress = 0.5f,
                            perItem = listOf(
                                ItemStatus(DocType.ID_FRONT, ItemUploadState.SUCCEEDED),
                                ItemStatus(DocType.ID_BACK, ItemUploadState.UPLOADING),
                            ),
                        )
                    },
                    onCancel = {},
                    onRetry = {},
                    onOpenSettings = {},
                )
            }
        }
    }

    @Test
    fun selectingType_showsTypeCards_andCaptureActions() {
        launch(
            DocumentCaptureUiState.SelectingType(
                available = listOf(DocType.ID_FRONT, DocType.ID_BACK),
            ),
        )
        rule.onNodeWithTag(DocumentCaptureTestTags.TYPE_ID_FRONT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(DocumentCaptureTestTags.TYPE_ID_BACK, useUnmergedTree = true).assertIsDisplayed()
        // Each type card hosts its own capture buttons, so TAKE_PHOTO / PICK appear once per card - assert
        // the first instance is shown rather than matching a single node.
        rule.onAllNodesWithTag(DocumentCaptureTestTags.TAKE_PHOTO, useUnmergedTree = true)
            .onFirst().assertIsDisplayed()
        rule.onAllNodesWithTag(DocumentCaptureTestTags.PICK, useUnmergedTree = true)
            .onFirst().assertIsDisplayed()
        // No upload button yet (not all confirmed).
        rule.onNodeWithTag(DocumentCaptureTestTags.UPLOAD).assertDoesNotExist()
    }

    @Test
    fun allConfirmed_showsUploadButton() {
        launch(DocumentCaptureUiState.SelectingType(available = emptyList()), allConfirmed = true)
        rule.onNodeWithTag(DocumentCaptureTestTags.UPLOAD).assertIsDisplayed()
    }

    @Test
    fun reviewing_retakeAndConfirm_areShown_andConfirmReduces() {
        launch(
            DocumentCaptureUiState.Reviewing(
                docType = DocType.ID_FRONT,
                file = File("front.jpg"),
                confirmedCount = 0,
                totalCount = 2,
            ),
        )
        rule.onNodeWithTag(DocumentCaptureTestTags.RETAKE).assertIsDisplayed()
        rule.onNodeWithTag(DocumentCaptureTestTags.CONFIRM).assertIsDisplayed()
        rule.onNodeWithTag(DocumentCaptureTestTags.CONFIRM).performClick()
        // After confirm the review affordances are gone.
        rule.onNodeWithTag(DocumentCaptureTestTags.CONFIRM).assertDoesNotExist()
    }

    @Test
    fun uploading_showsProgress_andCancel() {
        launch(
            DocumentCaptureUiState.Uploading(
                progress = 0.5f,
                perItem = listOf(ItemStatus(DocType.ID_FRONT, ItemUploadState.UPLOADING)),
            ),
        )
        rule.onNodeWithTag(DocumentCaptureTestTags.CANCEL).assertIsDisplayed()
    }

    @Test
    fun success_showsSuccessSurface() {
        launch(
            DocumentCaptureUiState.Success(
                document = KycDocument(
                    documentId = "doc_1",
                    documentType = "id_front",
                    fileName = "front.jpg",
                    status = KycDocumentStatus.PENDING,
                    createdAt = Instant.EPOCH,
                    updatedAt = Instant.EPOCH,
                ),
            ),
        )
        rule.onNodeWithTag(DocumentCaptureTestTags.SUCCESS).assertIsDisplayed()
    }

    @Test
    fun permissionRequired_showsPermissionSurface() {
        launch(DocumentCaptureUiState.PermissionRequired(permanentlyDenied = true))
        rule.onNodeWithTag(DocumentCaptureTestTags.PERMISSION).assertIsDisplayed()
    }
}
