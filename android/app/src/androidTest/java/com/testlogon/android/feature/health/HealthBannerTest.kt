package com.testlogon.android.feature.health

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-042 Compose UI test: banner shows when down, hides on recovery. */
@RunWith(AndroidJUnit4::class)
class HealthBannerTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun shows_whenVisible_hides_whenNot() {
        var visible by mutableStateOf(false)
        rule.setContent {
            TestLogonTheme {
                GlobalHealthBanner(state = HealthBannerUiState(visible = visible))
            }
        }

        rule.onNodeWithTag("health_banner").assertDoesNotExist()

        visible = true
        rule.waitForIdle()
        rule.onNodeWithTag("health_banner").assertIsDisplayed()

        visible = false
        rule.waitForIdle()
        rule.onNodeWithTag("health_banner").assertDoesNotExist()
    }
}
