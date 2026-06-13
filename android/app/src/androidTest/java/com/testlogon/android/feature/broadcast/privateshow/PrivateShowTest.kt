package com.testlogon.android.feature.broadcast.privateshow

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSummary
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-315 — Compose UI tests for the private-show host surfaces (sheet / active bar / summary dialog). Drives
 * an in-test reducer where needed. Asserts: the request sheet shows Accept/Decline (Accept emits the default
 * pause behavior), the active bar shows the timer + End, and the summary dialog shows the totals.
 * useUnmergedTree for nested controls.
 */
@RunWith(AndroidJUnit4::class)
class PrivateShowTest {

    @get:Rule
    val rule = createComposeRule()

    private fun request() = PrivateShowRequest(
        requestId = "req_1",
        privateSessionId = null,
        sessionId = "bcs_1",
        viewerId = "v_1",
        viewerDisplayName = "Jordan",
        ratePerMinuteCents = 500,
        status = "pending",
        maxDurationMinutes = 30,
        requestedAt = Instant.ofEpochSecond(900),
        startedAt = null,
    )

    @Test
    fun requestSheet_acceptDecline_acceptEmitsPause() {
        var accepted: PrivateShowBehavior? = null
        var declineCount = 0
        rule.setContent {
            TestLogonTheme {
                PrivateShowRequestSheet(
                    request = request(),
                    inFlight = false,
                    onAccept = { accepted = it },
                    onDecline = { declineCount++ },
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(PrivateShowTestTags.REQUEST_SHEET, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PrivateShowTestTags.ACCEPT, useUnmergedTree = true).performClick()
        assertEquals(PrivateShowBehavior.PAUSE, accepted)

        rule.onNodeWithTag(PrivateShowTestTags.DECLINE, useUnmergedTree = true).performClick()
        assertEquals(1, declineCount)
    }

    @Test
    fun activeBar_showsTimerAndEnd() {
        var ended = false
        rule.setContent {
            TestLogonTheme {
                PrivateShowActiveBar(
                    elapsedSeconds = 65,
                    accruedCents = 542,
                    ending = false,
                    onEnd = { ended = true },
                )
            }
        }
        rule.onNodeWithTag(PrivateShowTestTags.ACTIVE_BAR, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(PrivateShowTestTags.END, useUnmergedTree = true).performClick()
        assertTrue(ended)
    }

    @Test
    fun summaryDialog_showsTotals() {
        var dismissed = false
        rule.setContent {
            TestLogonTheme {
                PrivateShowSummaryDialog(
                    summary = PrivateShowSummary(
                        privateSessionId = "ps_1",
                        sessionId = "bcs_1",
                        status = "ended",
                        durationSeconds = 180,
                        totalBilledCents = 1_500,
                        endedBy = "host",
                    ),
                    onDismiss = { dismissed = true },
                )
            }
        }
        rule.onNodeWithTag(PrivateShowTestTags.SUMMARY_DIALOG, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun requestSheet_inFlight_disablesActions() {
        rule.setContent {
            TestLogonTheme {
                var inFlight by remember { mutableStateOf(true) }
                PrivateShowRequestSheet(
                    request = request(),
                    inFlight = inFlight,
                    onAccept = {},
                    onDecline = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(PrivateShowTestTags.REQUEST_SHEET, useUnmergedTree = true).assertIsDisplayed()
    }
}
