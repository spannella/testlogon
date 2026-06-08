package com.testlogon.android.feature.sessions

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.auth.SessionInfo
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-043 Compose UI test: current badge, no revoke on current row, confirm-then-remove. */
@RunWith(AndroidJUnit4::class)
class ActiveSessionsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun row(id: String, current: Boolean) = SessionRow(
        info = SessionInfo(id, current, 0L, 0L, "1.2.3.4", "ua-$id", false, null),
        isCurrent = current,
    )

    @Test
    fun currentRow_hasBadge_andNoRevoke_otherRow_revokesViaConfirm() {
        rule.setContent {
            TestLogonTheme {
                var state by mutableStateOf(
                    ActiveSessionsUiState(
                        rows = listOf(row("cur", true), row("a", false)),
                        loaded = true,
                    ),
                )
                ActiveSessionsScreen(
                    state = state,
                    onRetry = {},
                    onRevoke = { id -> state = state.copy(confirm = ConfirmTarget.RevokeOne(id)) },
                    onRevokeOthers = {},
                    onConfirm = {
                        val target = state.confirm as ConfirmTarget.RevokeOne
                        state = state.copy(
                            confirm = null,
                            rows = state.rows.filterNot { it.info.sessionId == target.sessionId },
                        )
                    },
                    onDismissConfirm = { state = state.copy(confirm = null) },
                    onBack = {},
                )
            }
        }

        rule.onNodeWithTag("session_current_badge_cur").assertIsDisplayed()
        rule.onNodeWithTag("session_revoke_cur").assertDoesNotExist()

        rule.onNodeWithTag("session_revoke_a").performClick()
        rule.onNodeWithTag("sessions_confirm_dialog").assertIsDisplayed()
        rule.onNodeWithTag("sessions_confirm").performClick()
        rule.onNodeWithTag("session_row_a").assertDoesNotExist()
    }
}
