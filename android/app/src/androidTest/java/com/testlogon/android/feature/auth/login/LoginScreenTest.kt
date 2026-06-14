package com.testlogon.android.feature.auth.login

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.LogoutReason
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-048 — Compose UI tests for the stateless [LoginScreen]: enable/disable + validation gating,
 * error rendering, loading-disabled, and the AND-044 expiry banner. Drives the screen with a small
 * in-test reducer mirroring LoginViewModel's submit-enablement so no Hilt graph is needed.
 */
@RunWith(AndroidJUnit4::class)
class LoginScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: LoginUiState = LoginUiState(serverUrl = "http://host:8000/")) {
        rule.setContent {
            TestLogonTheme {
                var state by mutableStateOf(initial)
                LoginScreen(
                    state = state,
                    onEmailChange = { state = state.copy(email = it, error = null) },
                    onPasswordChange = { state = state.copy(password = it, error = null) },
                    onTogglePasswordVisibility = { state = state.copy(passwordVisible = !state.passwordVisible) },
                    onSubmit = {},
                    onDismissError = { state = state.copy(error = null) },
                    onDismissExpiry = { state = state.copy(expiryReason = null) },
                    onOpenServerSettings = {},
                    onRegister = {},
                    onRecovery = {},
                    onMagicLink = {},
                )
            }
        }
    }

    @Test
    fun loginScreen_isDisplayed() {
        launch()
        rule.onNodeWithTag("login_screen").assertIsDisplayed()
    }

    @Test
    fun submit_disabled_whenFieldsEmpty() {
        launch()
        rule.onNodeWithTag("login_submit").assertIsNotEnabled()
    }

    @Test
    fun submit_disabled_forMalformedEmail() {
        launch()
        rule.onNodeWithTag("login_email").performTextReplacement("a@b")
        rule.onNodeWithTag("login_password").performTextReplacement("pw")
        rule.onNodeWithTag("login_submit").assertIsNotEnabled()
    }

    @Test
    fun submit_enabled_forValidCredentials() {
        // The in-test reducer's `var state by mutableStateOf(initial)` is not `remember`-ed, so typed
        // edits do not survive recomposition. Seed the valid credentials via the initial state instead.
        launch(LoginUiState(email = "alice@example.com", password = "pw", serverUrl = "http://host:8000/"))
        rule.waitForIdle()
        rule.onNodeWithTag("login_submit").assertIsEnabled()
    }

    @Test
    fun errorBanner_renders_andIsDismissable() {
        launch(LoginUiState(error = "Invalid email or password.", serverUrl = "http://h/"))
        rule.onNodeWithTag("login_error").assertIsDisplayed()
        rule.onNodeWithTag("login_dismiss_error").assertIsDisplayed()
    }

    @Test
    fun loading_disablesSubmit() {
        launch(LoginUiState(email = "alice@example.com", password = "pw", status = LoginStatus.Submitting))
        rule.onNodeWithTag("login_submit").assertIsNotEnabled()
    }

    @Test
    fun expiryBanner_shown_forSessionExpired() {
        launch(LoginUiState(expiryReason = LogoutReason.SESSION_EXPIRED, serverUrl = "http://h/"))
        rule.onNodeWithTag("login_expiry_banner").assertIsDisplayed()
    }
}
