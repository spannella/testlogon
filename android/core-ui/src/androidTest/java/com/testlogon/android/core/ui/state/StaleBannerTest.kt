package com.testlogon.android.core.ui.state

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-045 StaleBanner: nothing when fresh, reconnecting text when refreshing, offline + Retry when stale. */
@RunWith(AndroidJUnit4::class)
class StaleBannerTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun fresh_rendersNothing() {
        rule.setContent { TestLogonTheme { StaleBanner(stale = false, refreshing = false, onRetry = {}) } }
        rule.onNodeWithText("Reconnecting…").assertDoesNotExist()
        rule.onNodeWithText("Offline — showing last-known data").assertDoesNotExist()
    }

    @Test
    fun refreshing_showsReconnecting() {
        rule.setContent { TestLogonTheme { StaleBanner(stale = false, refreshing = true, onRetry = {}) } }
        rule.onNodeWithText("Reconnecting…").assertIsDisplayed()
    }

    @Test
    fun stale_showsOffline_andRetryInvokesCallback() {
        var retried = false
        rule.setContent { TestLogonTheme { StaleBanner(stale = true, refreshing = false, onRetry = { retried = true }) } }
        rule.onNodeWithText("Offline — showing last-known data").assertIsDisplayed()
        rule.onNodeWithText("Retry").performClick()
        assertTrue(retried)
    }
}
