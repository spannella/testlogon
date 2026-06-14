package com.testlogon.android.feature.account.closure

import androidx.lifecycle.SavedStateHandle
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.AccountState
import com.testlogon.android.core.model.AccountStatus
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.account.AccountLifecycleRepository
import com.testlogon.android.data.account.ClosureStartResult
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-387 - Compose UI tests for the lifecycle screens (TC-AND-387-12). Drives a real
 * [AccountLifecycleViewModel] backed by an in-test fake repository through the Route composables (which
 * collect the StateFlow), so the typed-token gate and the closed terminal screen are exercised end to end.
 */
@RunWith(AndroidJUnit4::class)
class AccountLifecycleScreenTest {

    @get:Rule
    val rule = createComposeRule()

    /** A minimal synchronous fake; load() resolves immediately. */
    private class FakeRepo(
        private val statusState: AccountState = AccountState.ACTIVE,
        private val authRequired: Boolean = false,
    ) : AccountLifecycleRepository {
        override suspend fun status(): ApiResult<AccountStatus> =
            ApiResult.Success(AccountStatus(state = statusState, rawState = statusState.name.lowercase()))
        override suspend fun startClosure(): ApiResult<ClosureStartResult> =
            ApiResult.Success(ClosureStartResult(authRequired, "ch_re_19", listOf("password")))
        override suspend fun finalizeClosure(challengeId: String): ApiResult<AccountStatus> =
            ApiResult.Success(AccountStatus(AccountState.CLOSED, "closed"))
        override suspend fun suspend(reason: String?): ApiResult<AccountStatus> =
            ApiResult.Success(AccountStatus(AccountState.SUSPENDED, "suspended"))
        override suspend fun reactivate(reason: String?): ApiResult<AccountStatus> =
            ApiResult.Success(AccountStatus(AccountState.ACTIVE, "active"))
    }

    private fun vm(repo: AccountLifecycleRepository) =
        AccountLifecycleViewModel(repo, SavedStateHandle())

    // TC-12 / AC-3: the finalize confirm button stays disabled until the typed token is exactly CLOSE.
    @Test
    fun finalizeConfirm_disabledUntilExactCloseToken() {
        val viewModel = vm(FakeRepo(authRequired = false))
        rule.setContent {
            TestLogonTheme {
                AccountClosureRoute(onClosed = {}, onBack = {}, viewModel = viewModel)
            }
        }
        // Start the closure flow -> finalize confirm dialog (no re-auth in this fake).
        rule.onNodeWithTag(AccountLifecycleTestTags.PRIMARY).performClick()
        rule.waitForIdle()

        rule.onNodeWithTag(AccountLifecycleTestTags.FINALIZE_CONFIRM).assertIsNotEnabled()
        rule.onNodeWithTag(AccountLifecycleTestTags.TOKEN_FIELD).performTextInput("close")
        rule.onNodeWithTag(AccountLifecycleTestTags.FINALIZE_CONFIRM).assertIsNotEnabled()
        // Exact CLOSE via the field (replace lowercase first).
        rule.runOnIdle { viewModel.onTypedTokenChange(CLOSE_TOKEN) }
        rule.waitForIdle()
        rule.onNodeWithTag(AccountLifecycleTestTags.FINALIZE_CONFIRM).assertIsEnabled()
    }

    // TC-12 / AC-5: a CLOSED account renders the terminal screen with no destructive (PRIMARY) action.
    @Test
    fun closedAccount_showsTerminal_noActions() {
        val viewModel = vm(FakeRepo(statusState = AccountState.CLOSED))
        rule.setContent {
            TestLogonTheme {
                AccountClosureRoute(onClosed = {}, onBack = {}, viewModel = viewModel)
            }
        }
        rule.waitForIdle()
        rule.onNodeWithTag(AccountLifecycleTestTags.CLOSED_TERMINAL).assertIsDisplayed()
        // The destructive start action must not be offered on a closed account.
        rule.onNodeWithTag(AccountLifecycleTestTags.PRIMARY).assertDoesNotExist()
    }

    // TC-10 / AC-7: an offline status read shows the Retry affordance and no destructive action.
    @Test
    fun offlineStatus_showsRetry_noActions() {
        val offlineRepo = object : AccountLifecycleRepository {
            override suspend fun status(): ApiResult<AccountStatus> =
                ApiResult.NetworkError(RuntimeException("no net"), isTimeout = false)
            override suspend fun startClosure() = error("unused")
            override suspend fun finalizeClosure(challengeId: String) = error("unused")
            override suspend fun suspend(reason: String?) = error("unused")
            override suspend fun reactivate(reason: String?) = error("unused")
        }
        rule.setContent {
            TestLogonTheme {
                AccountClosureRoute(onClosed = {}, onBack = {}, viewModel = vm(offlineRepo))
            }
        }
        rule.waitForIdle()
        rule.onNodeWithTag(AccountLifecycleTestTags.RETRY).assertIsDisplayed()
        rule.onNodeWithTag(AccountLifecycleTestTags.PRIMARY).assertDoesNotExist()
    }
}
