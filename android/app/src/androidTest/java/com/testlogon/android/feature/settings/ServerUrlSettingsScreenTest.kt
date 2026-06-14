package com.testlogon.android.feature.settings

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performTextReplacement
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-041 Compose UI test driving the stateless screen with a small in-test reducer. */
@RunWith(AndroidJUnit4::class)
class ServerUrlSettingsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val default = "http://18.222.237.167:8000"

    private fun launch() {
        rule.setContent {
            TestLogonTheme {
                var state by remember {
                    mutableStateOf(
                        ServerUrlUiState(
                            input = default,
                            persistedUrl = default,
                            defaultUrl = default,
                        ),
                    )
                }
                ServerUrlSettingsScreen(
                    state = state,
                    onInputChange = { value ->
                        state = when (val v = BaseUrlValidator.validate(value)) {
                            is UrlValidation.Valid -> state.copy(
                                input = value,
                                error = null,
                                cleartextWarning = v.cleartext,
                                canSave = v.normalized != state.persistedUrl,
                            )
                            is UrlValidation.Invalid ->
                                state.copy(input = value, error = v.reason, canSave = false, cleartextWarning = false)
                        }
                    },
                    onSave = {
                        val v = BaseUrlValidator.validate(state.input) as UrlValidation.Valid
                        state = state.copy(persistedUrl = v.normalized, canSave = false, message = SettingsMessage.Saved)
                    },
                    onReset = { state = state.copy(input = default, canReset = false) },
                    onMessageShown = { state = state.copy(message = null) },
                    onNavigateBack = {},
                )
            }
        }
    }

    @Test
    fun invalidUrl_showsError_andDisablesSave() {
        launch()
        rule.onNodeWithTag("server_url_input").performTextReplacement("ftp://nope")
        rule.onNodeWithText("URL must start with http:// or https://").assertIsDisplayed()
        rule.onNodeWithTag("server_url_save").assertIsNotEnabled()
    }

    @Test
    fun validDifferentUrl_enablesSave() {
        launch()
        rule.onNodeWithTag("server_url_input").performTextReplacement("https://staging.example.com")
        rule.onNodeWithTag("server_url_save").assertIsEnabled()
    }

    @Test
    fun http_showsCleartextWarning() {
        launch()
        rule.onNodeWithTag("server_url_input").performTextReplacement("http://newhost:9000")
        rule.onNodeWithText("Connection is not encrypted (HTTP)").assertIsDisplayed()
    }
}
