package com.testlogon.android.feature.privacy.deletion

import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.privacy.DeletionStatus
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-386 - Compose UI tests for the stateless [AccountDeletionScreen] (TC-AND-386-11, 12, 13). The screen is
 * driven by an in-test mutable state so events mutate the rendered state; a recorded events list verifies the
 * destructive actions fire.
 */
@RunWith(AndroidJUnit4::class)
class AccountDeletionScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val events = mutableListOf<AccountDeletionEvent>()

    private fun launch(initial: AccountDeletionUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                AccountDeletionScreen(
                    state = state,
                    snackbarHostState = remember { SnackbarHostState() },
                    onBack = {},
                    onEvent = { ev ->
                        events += ev
                        state = reduce(state, ev)
                    },
                )
            }
        }
    }

    /** A minimal reducer mirroring the ViewModel gating, sufficient for the UI assertions. */
    private fun reduce(state: AccountDeletionUiState, ev: AccountDeletionEvent): AccountDeletionUiState {
        val ready = state as? AccountDeletionUiState.Ready ?: return state
        return when (ev) {
            AccountDeletionEvent.StartRequest -> ready.copy(confirmStep = ConfirmStep.Warning)
            AccountDeletionEvent.AdvanceFromWarning -> ready.copy(confirmStep = ConfirmStep.TypeToConfirm)
            is AccountDeletionEvent.TypedConfirmationChanged -> ready.copy(typedConfirmation = ev.text)
            is AccountDeletionEvent.PasswordChanged -> ready.copy(password = ev.text)
            AccountDeletionEvent.ShowFinalDialog ->
                if (ready.confirmUnlocked) ready.copy(confirmStep = ConfirmStep.FinalDialog) else ready
            AccountDeletionEvent.StartCancel -> ready.copy(confirmStep = ConfirmStep.CancelDialog)
            else -> ready
        }
    }

    // TC-AND-386-11: destructive button stays disabled through the gates with a wrong-case phrase + password.
    @Test
    fun deleteButton_disabledWithWrongCasePhrase() {
        launch(AccountDeletionUiState.Ready(status = DeletionStatus.Active))
        rule.onNodeWithTag(AccountDeletionTestTags.START).performClick()
        rule.onNodeWithTag(AccountDeletionTestTags.WARNING_CONTINUE).performClick()

        // Locked initially.
        rule.onNodeWithTag(AccountDeletionTestTags.SHOW_FINAL).assertIsNotEnabled()

        // Wrong-case phrase + a password is still locked (case-sensitive sentinel).
        rule.onNodeWithTag(AccountDeletionTestTags.CONFIRM_FIELD).performTextInput("delete my account")
        rule.onNodeWithTag(AccountDeletionTestTags.PASSWORD_FIELD).performTextInput("pw")
        rule.onNodeWithTag(AccountDeletionTestTags.SHOW_FINAL).assertIsNotEnabled()
    }

    // TC-AND-386-11 (exact-match unlock path, isolated).
    @Test
    fun deleteButton_enabledOnExactMatch_andFinalConfirmFires() {
        launch(
            AccountDeletionUiState.Ready(
                status = DeletionStatus.Active,
                confirmStep = ConfirmStep.TypeToConfirm,
                typedConfirmation = DELETE_SENTINEL,
                password = "pw",
            ),
        )
        rule.onNodeWithTag(AccountDeletionTestTags.SHOW_FINAL).assertIsEnabled()
        rule.onNodeWithTag(AccountDeletionTestTags.SHOW_FINAL).performClick()
        rule.onNodeWithTag(AccountDeletionTestTags.FINAL_DIALOG).assertIsDisplayed()
        rule.onNodeWithTag(AccountDeletionTestTags.FINAL_CONFIRM).performClick()
        assertTrue(events.contains(AccountDeletionEvent.ConfirmDelete))
    }

    // TC-AND-386-12: pending state shows the cancel CTA; cancel dialog confirm fires event.
    @Test
    fun pendingState_showsCancel_andConfirmFires() {
        launch(
            AccountDeletionUiState.Ready(
                status = DeletionStatus.Pending("del_x", 1_000L, 2_000L, 14, canCancel = true),
            ),
        )
        rule.onNodeWithTag(AccountDeletionTestTags.PENDING).assertIsDisplayed()
        rule.onNodeWithTag(AccountDeletionTestTags.CANCEL_CTA).performClick()
        rule.onNodeWithTag(AccountDeletionTestTags.CANCEL_DIALOG).assertIsDisplayed()
        rule.onNodeWithTag(AccountDeletionTestTags.CANCEL_CONFIRM).performClick()
        assertTrue(events.contains(AccountDeletionEvent.ConfirmCancel))
    }

    // TC-AND-386-12: canCancel == false hides the Cancel CTA.
    @Test
    fun pendingState_canCancelFalse_hidesCancel() {
        launch(
            AccountDeletionUiState.Ready(
                status = DeletionStatus.Pending("del_x", 1_000L, 2_000L, 14, canCancel = false),
            ),
        )
        rule.onNodeWithTag(AccountDeletionTestTags.PENDING).assertIsDisplayed()
        rule.onNodeWithTag(AccountDeletionTestTags.CANCEL_CTA).assertDoesNotExist()
    }

    // TC-AND-386-13: stale banner visible and the start (mutation) button disabled when offline.
    @Test
    fun staleState_showsBanner_andDisablesStart() {
        launch(AccountDeletionUiState.Ready(status = DeletionStatus.Active, isStale = true))
        rule.onNodeWithTag(AccountDeletionTestTags.STALE_BANNER).assertIsDisplayed()
        rule.onNodeWithTag(AccountDeletionTestTags.START).assertIsNotEnabled()
    }
}
