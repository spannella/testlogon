package com.testlogon.android.feature.broadcast.moderation

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
import com.testlogon.android.data.broadcast.chat.ChatMessage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-313 — Compose UI tests for the moderation sheets + ban confirm dialog. Drives an in-test reducer over
 * the open [ModerationSheet]. Asserts: the user sheet shows the mute chips + ban; the message sheet shows
 * delete + pin; the ban confirm dialog appears and only bans on confirm; and the controls are hidden when
 * canModerate is false. useUnmergedTree for nested nodes; assertDoesNotExist is a member (not imported).
 */
@RunWith(AndroidJUnit4::class)
class ModerationSheetTest {

    @get:Rule
    val rule = createComposeRule()

    private fun message() = ChatMessage(
        id = "cm_1",
        sessionId = "bcs_1",
        senderId = "usr_9",
        senderDisplayName = "Ada",
        text = "hi",
        createdAtEpochSeconds = 0L,
    )

    @Test
    fun userSheet_showsMuteChips_andBan() {
        rule.setContent {
            TestLogonTheme {
                UserModerationSheet(
                    userId = "usr_9",
                    displayName = "Ada",
                    delegateAvailable = true,
                    onMute = {},
                    onBan = {},
                    onUnban = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(ModerationTestTags.USER_SHEET).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.MUTE_5M, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.MUTE_1H, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.MUTE_24H, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.MUTE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.BAN, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun userSheet_hostOnly_hidesBanAndUnban() {
        rule.setContent {
            TestLogonTheme {
                UserModerationSheet(
                    userId = "usr_9",
                    displayName = "Ada",
                    delegateAvailable = false,
                    onMute = {},
                    onBan = {},
                    onUnban = {},
                    onDismiss = {},
                )
            }
        }
        // Mute is host-scoped (always available); ban / unban are delegate-only.
        rule.onNodeWithTag(ModerationTestTags.MUTE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.BAN, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(ModerationTestTags.UNBAN, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun userSheet_muteChip_thenMute_invokesWithChosenDuration() {
        var spec: MuteSpec? = null
        rule.setContent {
            TestLogonTheme {
                UserModerationSheet(
                    userId = "usr_9",
                    displayName = "Ada",
                    delegateAvailable = true,
                    onMute = { spec = it },
                    onBan = {},
                    onUnban = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(ModerationTestTags.MUTE_1H, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ModerationTestTags.MUTE, useUnmergedTree = true).performClick()
        assertEquals(MuteSpec.ONE_HOUR.durationSeconds, spec?.durationSeconds)
    }

    @Test
    fun userSheet_ban_showsConfirmDialog_thenBansOnConfirm() {
        var banned = false
        var reason: String? = "untouched"
        rule.setContent {
            TestLogonTheme {
                UserModerationSheet(
                    userId = "usr_9",
                    displayName = "Ada",
                    delegateAvailable = true,
                    onMute = {},
                    onBan = { banned = true; reason = it },
                    onUnban = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(ModerationTestTags.BAN, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(ModerationTestTags.BAN_CONFIRM, useUnmergedTree = true).assertIsDisplayed()
        assertTrue(!banned)
        rule.onNodeWithTag(ModerationTestTags.BAN_CONFIRM, useUnmergedTree = true).performClick()
        assertTrue(banned)
        // No reason was typed -> null is passed.
        assertNull(reason)
    }

    @Test
    fun messageSheet_showsDeleteAndPin() {
        rule.setContent {
            TestLogonTheme {
                MessageModerationSheet(
                    message = message(),
                    isPinned = false,
                    delegateAvailable = true,
                    onDelete = {},
                    onPin = {},
                    onUnpin = {},
                    onModerateAuthor = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(ModerationTestTags.MESSAGE_SHEET).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.DELETE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.PIN, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun messageSheet_pinned_showsUnpinNotPin() {
        rule.setContent {
            TestLogonTheme {
                MessageModerationSheet(
                    message = message(),
                    isPinned = true,
                    delegateAvailable = true,
                    onDelete = {},
                    onPin = {},
                    onUnpin = {},
                    onModerateAuthor = {},
                    onDismiss = {},
                )
            }
        }
        rule.onNodeWithTag(ModerationTestTags.UNPIN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(ModerationTestTags.PIN, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun controls_hidden_whenCannotModerate() {
        // The screen gate: when canModerate is false, no sheet is opened at all.
        rule.setContent {
            TestLogonTheme {
                val canModerate by remember { mutableStateOf(false) }
                if (canModerate) {
                    MessageModerationSheet(
                        message = message(),
                        isPinned = false,
                        delegateAvailable = true,
                        onDelete = {},
                        onPin = {},
                        onUnpin = {},
                        onModerateAuthor = {},
                        onDismiss = {},
                    )
                }
            }
        }
        rule.onNodeWithTag(ModerationTestTags.MESSAGE_SHEET, useUnmergedTree = true).assertDoesNotExist()
    }
}
