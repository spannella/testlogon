package com.testlogon.android.feature.tickets

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.tickets.Ticket
import com.testlogon.android.core.model.tickets.TicketMessage
import com.testlogon.android.core.model.tickets.TicketSendState
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.tickets.ui.ComposerState
import com.testlogon.android.feature.tickets.ui.TicketThreadScreen
import com.testlogon.android.feature.tickets.ui.TicketThreadTestTags
import com.testlogon.android.feature.tickets.ui.TicketThreadUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-372 - Compose UI tests for the stateless [TicketThreadScreen]: message bubbles render oldest -> newest
 * (each with a stable ticket_msg_<idx> testTag, mine + other distinguished by sender_sub == currentSub via the
 * VM-resolved currentSub) and an Empty thread renders the empty surface. assertDoesNotExist is chained (a
 * member), not imported; the tree is used unmerged for the bubble testTags.
 */
@RunWith(AndroidJUnit4::class)
class TicketThreadScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun message(id: String, sender: String, body: String) = TicketMessage(
        messageId = id,
        senderSub = sender,
        body = body,
        createdAt = 100L,
    )

    private fun ticket(messages: List<TicketMessage>) = Ticket(
        ticketId = "t1",
        spaceId = "s1",
        subject = "Cannot log in",
        status = "open",
        messages = messages,
    )

    private fun launch(state: TicketThreadUiState) {
        rule.setContent {
            TestLogonTheme {
                TicketThreadScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun rendersBubbles_mineAndOther() {
        launch(
            TicketThreadUiState.Content(
                ticket = ticket(
                    listOf(
                        message("m1", sender = "me", body = "Help"),
                        message("m2", sender = "agent", body = "On it"),
                    ),
                ),
                currentSub = "me",
            ),
        )
        rule.onNodeWithTag(TicketThreadTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(TicketThreadTestTags.message(0), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(TicketThreadTestTags.message(1), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("Help", useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("On it", useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun emptyThread_showsEmptySurface_andNoBubbles() {
        launch(TicketThreadUiState.Empty)
        rule.onNodeWithTag(TicketThreadTestTags.EMPTY).assertIsDisplayed()
        rule.onNodeWithTag(TicketThreadTestTags.message(0), useUnmergedTree = true).assertDoesNotExist()
    }

    // ---- AND-373: reply composer ----

    private fun content(
        messages: List<TicketMessage>,
        composer: ComposerState,
    ) = TicketThreadUiState.Content(
        ticket = ticket(messages),
        currentSub = "me",
        composer = composer,
    )

    @Test
    fun composer_shown_whenCanPost() {
        launch(
            content(
                messages = listOf(message("m1", sender = "agent", body = "Hi")),
                composer = ComposerState(canPost = true),
            ),
        )
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_INPUT).assertIsDisplayed()
    }

    @Test
    fun composer_hidden_andCaptionShown_whenReadOnly() {
        launch(
            content(
                messages = listOf(message("m1", sender = "agent", body = "Hi")),
                composer = ComposerState(canPost = false),
            ),
        )
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_INPUT).assertDoesNotExist()
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_DISABLED_CAPTION).assertIsDisplayed()
    }

    @Test
    fun send_disabledWhenBlank_enabledOnNonBlankInput() {
        // In-test reducer: the composer draft updates as the user types.
        rule.setContent {
            var composer by mutableStateOf(ComposerState(canPost = true))
            TestLogonTheme {
                TicketThreadScreen(
                    state = TicketThreadUiState.Content(
                        ticket = ticket(listOf(message("m1", sender = "agent", body = "Hi"))),
                        currentSub = "me",
                        composer = composer,
                    ),
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                    onDraftChanged = { composer = composer.copy(draft = it) },
                    onSend = {},
                )
            }
        }
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_SEND).assertIsNotEnabled()
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_INPUT).performTextInput("Hello")
        rule.onNodeWithTag(TicketThreadTestTags.REPLY_SEND).assertIsEnabled()
    }

    @Test
    fun failedMessage_showsRetry() {
        val failed = TicketMessage(
            messageId = null,
            senderSub = "me",
            body = "oops",
            createdAt = 100L,
            sendState = TicketSendState.FAILED,
            clientId = "c1",
        )
        launch(
            content(
                messages = listOf(failed),
                composer = ComposerState(canPost = true),
            ),
        )
        rule.onNodeWithTag(TicketThreadTestTags.messageState("c1"), useUnmergedTree = true)
            .assertIsDisplayed()
    }
}
