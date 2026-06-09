package com.testlogon.android.core.ui.state

import androidx.compose.material3.Text
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.BackendStatus
import com.testlogon.android.core.model.Freshness
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-117 / AND-119 — Compose UI acceptance: host down + cached value → cached content renders with
 * the stale bar; retry works; reconnecting hides the (storm-guarded) retry; fresh hides the bar.
 *
 * String literals mirror res/values/strings.xml (same convention as StaleBannerTest, AND-045).
 */
@RunWith(AndroidJUnit4::class)
class StaleContentTest {

    @get:Rule
    val rule = createComposeRule()

    private val offlineSaved = "Offline — showing saved data."
    private val showingSaved = "Showing saved data."
    private val reconnecting = "Reconnecting…"
    private val retry = "Try again"

    @Test
    fun hostDown_cachedValue_showsContentAndStaleBar() {
        val freshness = Freshness(hasCachedValue = true, isStale = true, isRefreshing = false, lastRefreshFailed = true)
        rule.setContent {
            TestLogonTheme {
                ProvideBackendStatus(BackendStatus.Down) {
                    StaleContent(freshness = freshness, onRetry = {}) { Text("CONTENT") }
                }
            }
        }
        rule.onNodeWithText("CONTENT").assertIsDisplayed()
        rule.onNodeWithText(offlineSaved).assertIsDisplayed()
    }

    @Test
    fun retry_enabled_invokesCallback() {
        var retried = false
        val freshness = Freshness(hasCachedValue = true, isStale = true, isRefreshing = false, lastRefreshFailed = true)
        rule.setContent {
            TestLogonTheme {
                ProvideBackendStatus(BackendStatus.Down) {
                    StaleContent(freshness = freshness, onRetry = { retried = true }) { Text("CONTENT") }
                }
            }
        }
        rule.onNodeWithText(retry).assertIsDisplayed()
        rule.onNodeWithText(retry).assertIsEnabled()
        rule.onNodeWithText(retry).performClick()
        assertTrue(retried)
    }

    @Test
    fun reconnecting_hidesRetry() {
        val freshness = Freshness(hasCachedValue = true, isStale = false, isRefreshing = true, lastRefreshFailed = false)
        rule.setContent {
            TestLogonTheme {
                ProvideBackendStatus(BackendStatus.Down) {
                    StaleContent(freshness = freshness, onRetry = {}) { Text("CONTENT") }
                }
            }
        }
        rule.onNodeWithText(reconnecting).assertIsDisplayed()
        rule.onNodeWithText(retry).assertDoesNotExist()
    }

    @Test
    fun fresh_hidesBar_contentStays() {
        val fresh = Freshness(hasCachedValue = false, isStale = false, isRefreshing = false, lastRefreshFailed = false)
        rule.setContent {
            TestLogonTheme {
                ProvideBackendStatus(BackendStatus.Up) {
                    StaleContent(freshness = fresh, onRetry = {}) { Text("CONTENT") }
                }
            }
        }
        rule.onNodeWithText("CONTENT").assertIsDisplayed()
        rule.onNodeWithText(offlineSaved).assertDoesNotExist()
        rule.onNodeWithText(showingSaved).assertDoesNotExist()
    }
}
