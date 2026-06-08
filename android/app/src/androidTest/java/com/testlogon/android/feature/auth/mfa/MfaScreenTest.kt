package com.testlogon.android.feature.auth.mfa

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.auth.MfaFactor
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-049 — Compose UI tests for the stateless [MfaScreen]: TOTP + SMS factor rendering, the
 * wrong-code error path, and submit gating. Driven with explicit [MfaUiState] (no Hilt graph).
 */
@RunWith(AndroidJUnit4::class)
class MfaScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: MfaUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by mutableStateOf(initial)
                MfaScreen(
                    state = state,
                    onCodeChange = { state = state.copy(code = it, error = null) },
                    onRecoveryCodeChange = { state = state.copy(recoveryCode = it) },
                    onSubmit = {},
                    onResend = {},
                    onSwitchFactor = {},
                    onOpenRecovery = { state = state.copy(recoveryMode = true) },
                    onCloseRecovery = { state = state.copy(recoveryMode = false) },
                )
            }
        }
    }

    private fun totpState() = MfaUiState(
        challengeId = "chal_01HZX",
        remainingFactors = listOf(MfaFactor.Totp),
        activeFactor = MfaFactor.Totp,
    )

    private fun smsState() = MfaUiState(
        challengeId = "chal_01HZX",
        remainingFactors = listOf(MfaFactor.Sms),
        activeFactor = MfaFactor.Sms,
    )

    @Test
    fun totp_factor_rendersOtpField_andVerify() {
        launch(totpState())
        rule.onNodeWithTag("mfa_screen").assertIsDisplayed()
        rule.onNodeWithTag("mfa_otp").assertIsDisplayed()
        rule.onNodeWithTag("mfa_verify").assertIsDisplayed()
    }

    @Test
    fun totp_verify_disabledUntilFullCode() {
        launch(totpState())
        rule.onNodeWithTag("mfa_verify").assertIsNotEnabled()
    }

    @Test
    fun totp_verify_enabledWithFullCode() {
        launch(totpState().copy(code = "123456"))
        rule.onNodeWithTag("mfa_verify").assertIsEnabled()
    }

    @Test
    fun totp_wrongCode_showsInlineError() {
        launch(totpState().copy(error = "Invalid verification code"))
        rule.onNodeWithTag("mfa_error").assertIsDisplayed()
    }

    @Test
    fun sms_factor_rendersResendAffordance() {
        launch(smsState())
        rule.onNodeWithTag("mfa_otp").assertIsDisplayed()
        rule.onNodeWithTag("mfa_resend").assertIsDisplayed()
    }

    @Test
    fun sms_wrongCode_showsInlineError() {
        launch(smsState().copy(code = "654321", error = "Invalid verification code"))
        rule.onNodeWithTag("mfa_error").assertIsDisplayed()
    }
}
