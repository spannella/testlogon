package com.testlogon.android.feature.call.history

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.call.CallDirection
import com.testlogon.android.data.call.CallHistoryEntry
import com.testlogon.android.data.call.CallMode
import com.testlogon.android.data.call.CallStatus
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-303 — Compose UI tests for the stateless [CallHistoryScreen] / [CallHistoryDetailScreen]. Builds the
 * UiState by hand (no Hilt). Verifies row count, empty state, row tap -> onOpenDetail, and that the detail
 * "Call back" affordance is DISABLED (no conversation_id on a history record).
 */
@RunWith(AndroidJUnit4::class)
class CallHistoryScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun entry(id: String, status: CallStatus = CallStatus.COMPLETED) = CallHistoryEntry(
        callId = id,
        callerId = "caller_$id",
        calleeId = "callee_$id",
        mode = CallMode.AUDIO,
        direction = CallDirection.OUTGOING,
        status = status,
        durationSeconds = 42,
        createdAtEpochSeconds = 1000,
        rawStatus = status.name.lowercase(),
    )

    @Test
    fun rendersOneRowPerEntry() {
        rule.setContent {
            TestLogonTheme {
                CallHistoryScreen(
                    state = CallHistoryUiState(
                        entries = listOf(entry("a"), entry("b"), entry("c")),
                        loaded = true,
                    ),
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onLoadMore = {},
                    onRetryLoadMore = {},
                    onOpenDetail = {},
                    onDelete = {},
                )
            }
        }
        rule.onAllNodesWithTag(CallHistoryTestTags.ROW, useUnmergedTree = true).assertCountEquals(3)
    }

    @Test
    fun emptyState_shown_whenLoadedAndNoEntries() {
        rule.setContent {
            TestLogonTheme {
                CallHistoryScreen(
                    state = CallHistoryUiState(entries = emptyList(), loaded = true),
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onLoadMore = {},
                    onRetryLoadMore = {},
                    onOpenDetail = {},
                    onDelete = {},
                )
            }
        }
        rule.onNodeWithTag(CallHistoryTestTags.EMPTY, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun rowTap_invokesOnOpenDetail() {
        var opened: String? = null
        rule.setContent {
            TestLogonTheme {
                CallHistoryScreen(
                    state = CallHistoryUiState(entries = listOf(entry("a")), loaded = true),
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onLoadMore = {},
                    onRetryLoadMore = {},
                    onOpenDetail = { opened = it },
                    onDelete = {},
                )
            }
        }
        rule.onAllNodesWithTag(CallHistoryTestTags.ROW, useUnmergedTree = true).onFirst().performClick()
        assertEquals("a", opened)
    }

    @Test
    fun delete_invokesOnDeleteWithCallId() {
        var deleted: String? = null
        rule.setContent {
            TestLogonTheme {
                CallHistoryScreen(
                    state = CallHistoryUiState(entries = listOf(entry("a")), loaded = true),
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onLoadMore = {},
                    onRetryLoadMore = {},
                    onOpenDetail = {},
                    onDelete = { deleted = it },
                )
            }
        }
        rule.onAllNodesWithTag(CallHistoryTestTags.DELETE, useUnmergedTree = true).onFirst().performClick()
        assertEquals("a", deleted)
    }

    @Test
    fun detail_callBack_isDisabled() {
        rule.setContent {
            TestLogonTheme {
                CallHistoryDetailScreen(
                    state = CallHistoryDetailUiState(isLoading = false, entry = entry("a")),
                    onBack = {},
                    onRetry = {},
                    onDelete = {},
                )
            }
        }
        rule.onNodeWithTag(CallHistoryDetailTestTags.CALLBACK, useUnmergedTree = true)
            .assertIsNotEnabled()
    }

    @Test
    fun detail_deleteAction_invokesOnDelete() {
        var deleted = false
        rule.setContent {
            TestLogonTheme {
                CallHistoryDetailScreen(
                    state = CallHistoryDetailUiState(isLoading = false, entry = entry("a")),
                    onBack = {},
                    onRetry = {},
                    onDelete = { deleted = true },
                )
            }
        }
        rule.onNodeWithTag(CallHistoryDetailTestTags.DELETE, useUnmergedTree = true).performClick()
        assertEquals(true, deleted)
    }
}
