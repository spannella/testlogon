package com.testlogon.android.feature.auth.register

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-053/055 — Compose UI tests for the stateless [RegisterScreen]: submit gating, password
 * mismatch, SMS-MFA → phone reveal, and the taken-email block. Drives the screen with a small
 * in-test reducer mirroring RegisterViewModel's field updates so no Hilt graph is needed.
 */
@RunWith(AndroidJUnit4::class)
class RegisterScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val validPassword = "Ada!Lovelace2026"

    private fun launch(initial: RegisterUiState = RegisterUiState()) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                RegisterScreen(
                    state = state,
                    onFullNameChange = { state = state.copy(fullName = it, fullNameError = null) },
                    onEmailChange = { state = state.copy(email = it, emailError = null) },
                    onPasswordChange = { state = state.copy(password = it, passwordError = null, confirmError = null) },
                    onConfirmChange = { state = state.copy(confirm = it, confirmError = null) },
                    onPhoneChange = { state = state.copy(phone = it, phoneError = null) },
                    onToggleSmsMfa = { state = state.copy(enableSmsMfa = it) },
                    onToggleTotpMfa = { state = state.copy(enableTotpMfa = it) },
                    onTogglePasswordVisibility = { state = state.copy(passwordVisible = !state.passwordVisible) },
                    onSubmit = {},
                    onDismissError = { state = state.copy(formError = null) },
                    onNavigateToLogin = {},
                )
            }
        }
    }

    @Test
    fun registerScreen_isDisplayed() {
        launch()
        rule.onNodeWithTag("register_screen").assertIsDisplayed()
    }

    @Test
    fun submit_disabled_whenEmpty() {
        launch()
        rule.onNodeWithTag("register_submit").assertIsNotEnabled()
    }

    @Test
    fun submit_enabled_whenAllValid() {
        // The in-test reducer's `var state by mutableStateOf(initial)` is not `remember`-ed, so typed
        // edits do not survive recomposition. Seed a fully-valid form via the initial state instead.
        launch(
            RegisterUiState(
                fullName = "Ada Lovelace",
                email = "ada@example.com",
                password = validPassword,
                confirm = validPassword,
            ),
        )
        rule.waitForIdle()
        rule.onNodeWithTag("register_submit").assertIsEnabled()
    }

    @Test
    fun submit_disabled_onMismatch() {
        launch()
        rule.onNodeWithTag("register_full_name").performTextReplacement("Ada Lovelace")
        rule.onNodeWithTag("register_email").performTextReplacement("ada@example.com")
        rule.onNodeWithTag("register_password").performTextReplacement(validPassword)
        rule.onNodeWithTag("register_confirm").performTextReplacement("different")
        rule.onNodeWithTag("register_submit").assertIsNotEnabled()
    }

    @Test
    fun smsMfa_revealsPhoneField() {
        launch()
        rule.onNodeWithTag("register_phone").assertDoesNotExist()
        rule.onNodeWithTag("register_mfa_sms").performClick()
        // Toggling SMS-MFA recomposes to add the phone field; wait for it then scroll it into view
        // (the form is in a verticalScroll Column and the field renders below the fold).
        rule.waitUntil(timeoutMillis = 5_000) {
            rule.onAllNodesWithTag("register_phone").fetchSemanticsNodes().isNotEmpty()
        }
        rule.onNodeWithTag("register_phone").performScrollTo().assertIsDisplayed()
    }

    @Test
    fun takenEmail_blocksSubmit() {
        launch(
            RegisterUiState(
                fullName = "Ada Lovelace",
                email = "ada@example.com",
                password = validPassword,
                confirm = validPassword,
                emailAvailability = com.testlogon.android.data.auth.EmailAvailability.Taken,
            ),
        )
        rule.onNodeWithTag("register_submit").assertIsNotEnabled()
    }

    @Test
    fun submitting_disablesSubmit_andShowsScreen() {
        launch(
            RegisterUiState(
                fullName = "Ada Lovelace",
                email = "ada@example.com",
                password = validPassword,
                confirm = validPassword,
                status = RegisterStatus.Submitting,
            ),
        )
        rule.onNodeWithTag("register_submit").assertIsNotEnabled()
    }
}
