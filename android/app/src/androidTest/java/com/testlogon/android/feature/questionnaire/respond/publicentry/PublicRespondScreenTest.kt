package com.testlogon.android.feature.questionnaire.respond.publicentry

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-395 (TC-AND-395-12/03) - Compose UI tests for the stateless [PublicRespondContent]. Covers the
 * loading shim, the NotFound copy, the Error + Retry surface (Retry re-invokes onRetry), and the
 * one-shot hand-off: a non-terminal Ready -> onSessionReady, a terminal Ready -> onSubmittedSession.
 */
@RunWith(AndroidJUnit4::class)
class PublicRespondScreenTest {

    @get:Rule
    val rule = createComposeRule()

    @Test
    fun loading_showsLoadingShim() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                PublicRespondContent(
                    state = PublicEntryState.Loading,
                    onSessionReady = {},
                    onSubmittedSession = {},
                    onRetry = {},
                )
            }
        }
        rule.onNodeWithTag(PublicRespondTestTags.LOADING).assertIsDisplayed()
    }

    @Test
    fun notFound_showsUnavailableCopy() {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                PublicRespondContent(
                    state = PublicEntryState.NotFound,
                    onSessionReady = {},
                    onSubmittedSession = {},
                    onRetry = {},
                )
            }
        }
        rule.onNodeWithTag(PublicRespondTestTags.NOT_FOUND).assertIsDisplayed()
        rule.onNodeWithText("Questionnaire unavailable").assertIsDisplayed()
    }

    @Test
    fun error_retry_invokesOnRetry() {
        var retries = 0
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                PublicRespondContent(
                    state = PublicEntryState.Error("Something went wrong"),
                    onSessionReady = {},
                    onSubmittedSession = {},
                    onRetry = { retries++ },
                )
            }
        }
        rule.onNodeWithTag(PublicRespondTestTags.ERROR).assertIsDisplayed()
        rule.onNodeWithText("Retry").performClick()
        assertEquals(1, retries)
    }

    @Test
    fun ready_nonTerminal_handsOffToRenderer() {
        var ready: String? = null
        var submitted: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                PublicRespondContent(
                    state = PublicEntryState.Ready("rs1", terminal = false),
                    onSessionReady = { ready = it },
                    onSubmittedSession = { submitted = it },
                    onRetry = {},
                )
            }
        }
        rule.waitForIdle()
        assertEquals("rs1", ready)
        assertTrue(submitted == null)
    }

    @Test
    fun ready_terminal_handsOffToConfirmation() {
        var ready: String? = null
        var submitted: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                PublicRespondContent(
                    state = PublicEntryState.Ready("rs9", terminal = true),
                    onSessionReady = { ready = it },
                    onSubmittedSession = { submitted = it },
                    onRetry = {},
                )
            }
        }
        rule.waitForIdle()
        assertEquals("rs9", submitted)
        assertTrue(ready == null)
    }
}
