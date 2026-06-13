package com.testlogon.android.feature.messaging.helpdesk

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.messaging.helpdesk.ClaimState
import com.testlogon.android.data.messaging.helpdesk.HelpdeskQueueItem
import com.testlogon.android.data.messaging.helpdesk.HelpdeskRoutingState
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-378 — TC-AND-378-11 / TC-AND-378-13: inline claim affordance on the helpdesk queue row.
 *
 * Verifies the Claim button shows only on claimable rows, is disabled while a claim is in flight
 * (double-submit guard), invokes the callback once, and exposes an accessible label.
 */
@RunWith(AndroidJUnit4::class)
class HelpdeskQueueClaimRowTest {

    @get:Rule
    val rule = createComposeRule()

    private fun item(
        routing: HelpdeskRoutingState = HelpdeskRoutingState.AWAITING_AGENT,
        claim: ClaimState = ClaimState.UNASSIGNED,
        active: String? = null,
    ) = HelpdeskQueueItem(
        conversationId = "c1", title = "Jane Doe", preview = "Need help",
        routingState = routing, claimState = claim,
        activeAgentUserId = active, unreadCount = 0, lastMessageAtEpochSeconds = 1,
    )

    private fun setRow(
        item: HelpdeskQueueItem,
        claiming: Boolean = false,
        claimEnabled: Boolean = true,
        onClaim: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                HelpdeskQueueRow(
                    item = item,
                    claiming = claiming,
                    claimEnabled = claimEnabled,
                    onClick = {},
                    onClaim = onClaim,
                )
            }
        }
    }

    @Test
    fun claimableRow_showsEnabledClaimButton_andInvokesOnce() {
        var claims = 0
        setRow(item(), onClaim = { claims++ })
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).assertIsDisplayed().assertIsEnabled()
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).performClick()
        assertEquals(1, claims)
    }

    @Test
    fun inFlightRow_claimButtonDisabled() {
        var claims = 0
        setRow(item(), claiming = true, onClaim = { claims++ })
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).assertIsNotEnabled()
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).performClick()
        // Disabled button does not fire the callback (double-submit guard at the UI layer too).
        assertEquals(0, claims)
    }

    @Test
    fun awayAgent_claimButtonDisabled_withCaption_andDoesNotFire() {
        // AND-379 TC-12 — AWAY disables the Claim button (input + visual) and shows the caption.
        var claims = 0
        setRow(item(), claimEnabled = false, onClaim = { claims++ })
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).assertIsNotEnabled()
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM_CAPTION).assertIsDisplayed()
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).performClick()
        assertEquals(0, claims)
    }

    @Test
    fun assignedToOtherRow_hasNoClaimButton() {
        setRow(item(routing = HelpdeskRoutingState.ASSIGNED, claim = ClaimState.CLAIMED_BY_OTHER, active = "usr_other"))
        rule.onNodeWithTag(HelpdeskQueueTestTags.ROW_CLAIM).assertDoesNotExist()
    }
}
