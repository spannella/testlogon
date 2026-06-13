package com.testlogon.android.feature.files.drive

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.files.drive.model.DriveFile
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-336 - Compose UI smoke tests for the stateless [DrivePickerScreen] using an in-test reducer over
 * the hoisted [DrivePickerUiState]. NotConnected shows Connect; Browsing shows files + folders + import;
 * a folder row navigates and breadcrumbs render. useUnmergedTree where the affordance is wrapped.
 */
@RunWith(AndroidJUnit4::class)
class DrivePickerTest {

    @get:Rule
    val rule = createComposeRule()

    private fun folder(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = true)
    private fun doc(id: String, name: String = id) = DriveFile(id = id, name = name, isFolder = false)

    @Test
    fun notConnected_showsConnectButton() {
        rule.setContent {
            TestLogonTheme {
                DrivePickerScreen(
                    state = DrivePickerUiState.NotConnected(),
                    snackbarHostState = remember { SnackbarHostState() },
                    onClose = {},
                    onConnect = {},
                    onRefreshStatus = {},
                    onOpenFolder = {},
                    onBreadcrumb = {},
                    onSearch = {},
                    onImport = {},
                    onDisconnect = {},
                )
            }
        }
        rule.onNodeWithTag(DriveTestTags.PICKER).assertIsDisplayed()
        rule.onNodeWithTag(DriveTestTags.CONNECT, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(DriveTestTags.REFRESH, useUnmergedTree = true).assertExists()
    }

    @Test
    fun browsing_showsFilesAndFolders_andImport() {
        rule.setContent {
            TestLogonTheme {
                DrivePickerScreen(
                    state = DrivePickerUiState.Browsing(
                        folderId = null,
                        breadcrumbs = listOf(DriveCrumb(id = null, name = "Drive")),
                        files = listOf(folder("fld_1", "Reports"), doc("file_1", "a.txt")),
                    ),
                    snackbarHostState = remember { SnackbarHostState() },
                    onClose = {},
                    onConnect = {},
                    onRefreshStatus = {},
                    onOpenFolder = {},
                    onBreadcrumb = {},
                    onSearch = {},
                    onImport = {},
                    onDisconnect = {},
                )
            }
        }
        rule.onNodeWithTag(DriveTestTags.file("fld_1"), useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DriveTestTags.file("file_1"), useUnmergedTree = true).assertExists()
        // File rows expose an import action; folder rows do not.
        rule.onNodeWithTag(DriveTestTags.import("file_1"), useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(DriveTestTags.breadcrumb(0), useUnmergedTree = true).assertExists()
    }

    @Test
    fun folderRow_click_invokesOnOpenFolder() {
        rule.setContent {
            TestLogonTheme {
                var state by remember {
                    mutableStateOf<DrivePickerUiState>(
                        DrivePickerUiState.Browsing(
                            breadcrumbs = listOf(DriveCrumb(id = null, name = "Drive")),
                            files = listOf(folder("fld_1", "Reports")),
                        ),
                    )
                }
                DrivePickerScreen(
                    state = state,
                    snackbarHostState = remember { SnackbarHostState() },
                    onClose = {},
                    onConnect = {},
                    onRefreshStatus = {},
                    // In-test reducer: opening a folder pushes a breadcrumb.
                    onOpenFolder = { f ->
                        val b = state as DrivePickerUiState.Browsing
                        state = b.copy(
                            folderId = f.id,
                            breadcrumbs = b.breadcrumbs + DriveCrumb(id = f.id, name = f.name),
                            files = emptyList(),
                        )
                    },
                    onBreadcrumb = {},
                    onSearch = {},
                    onImport = {},
                    onDisconnect = {},
                )
            }
        }
        rule.onNodeWithTag(DriveTestTags.file("fld_1"), useUnmergedTree = true).performClick()
        // The reducer pushed a second breadcrumb for the opened folder.
        rule.onNodeWithTag(DriveTestTags.breadcrumb(1), useUnmergedTree = true).assertExists()
    }

    @Test
    fun importAction_invokesOnImport() {
        var imported = false
        rule.setContent {
            TestLogonTheme {
                DrivePickerScreen(
                    state = DrivePickerUiState.Browsing(
                        breadcrumbs = listOf(DriveCrumb(id = null, name = "Drive")),
                        files = listOf(doc("file_1", "a.txt")),
                    ),
                    snackbarHostState = remember { SnackbarHostState() },
                    onClose = {},
                    onConnect = {},
                    onRefreshStatus = {},
                    onOpenFolder = {},
                    onBreadcrumb = {},
                    onSearch = {},
                    onImport = { imported = true },
                    onDisconnect = {},
                )
            }
        }
        rule.onNodeWithTag(DriveTestTags.import("file_1"), useUnmergedTree = true).performClick()
        assertTrue(imported)
    }
}
