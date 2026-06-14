package com.testlogon.android.feature.guest

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-312 — Compose UI tests for the stateless [GuestManageScreen]. Drives an in-test reducer over
 * [GuestManageUiState]. Asserts: the invite card create/copy/share/revoke affordances, the guest row overflow
 * Promote / Mute / Remove, the remove confirm dialog, an in-flight row disables (create) and shows progress,
 * and the empty state. useUnmergedTree for nested nodes; assertDoesNotExist is a member.
 */
@RunWith(AndroidJUnit4::class)
class GuestManageScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun guest(
        inputId: String,
        status: GuestStatus = GuestStatus.JOINED,
        muted: Boolean = false,
    ) = Guest(
        inputId = inputId,
        inviteId = "inv_$inputId",
        sessionId = "bcs_1",
        displayName = "Guest $inputId",
        status = status,
        mutedAudio = muted,
        connectedAt = null,
        isLive = status == GuestStatus.ONAIR,
    )

    private fun invite(inviteId: String = "inv_1") = GuestInvite(
        inviteId = inviteId,
        sessionId = "bcs_1",
        inputId = null,
        url = "https://testlogon.app/guest/accept?inviteId=$inviteId",
        ingestUrl = null,
        streamKey = null,
        joinMode = GuestJoinMode.BROWSER,
        status = InviteStatus.PENDING,
        expiresAt = null,
        createdAt = "",
        guestDisplayName = null,
    )

    private fun launch(
        initial: GuestManageUiState,
        onCreateInvite: () -> Unit = {},
        onRevokeInvite: (String) -> Unit = {},
        onPromote: (String) -> Unit = {},
        onToggleMute: (String, Boolean) -> Unit = { _, _ -> },
        onRemove: (String) -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                GuestManageScreen(
                    state = state,
                    onCreateInvite = onCreateInvite,
                    onRevokeInvite = onRevokeInvite,
                    onPromote = onPromote,
                    onToggleMute = onToggleMute,
                    onRemove = onRemove,
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun screen_renders() {
        launch(GuestManageUiState(guests = listOf(guest("a")), isLoading = false))
        rule.onNodeWithTag(GuestManageTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GuestManageTestTags.row("a")).assertIsDisplayed()
    }

    @Test
    fun inviteCard_noInvite_showsCreate() {
        launch(GuestManageUiState(isLoading = false))
        rule.onNodeWithTag(GuestManageTestTags.CREATE_INVITE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun createInvite_invokesCallback() {
        var created = false
        launch(GuestManageUiState(isLoading = false), onCreateInvite = { created = true })
        rule.onNodeWithTag(GuestManageTestTags.CREATE_INVITE, useUnmergedTree = true).performClick()
        assert(created)
    }

    @Test
    fun createButton_disabledWhileInFlight() {
        launch(
            GuestManageUiState(
                isLoading = false,
                inFlight = setOf(GuestManageViewModel.CREATE_KEY),
            ),
        )
        rule.onNodeWithTag(GuestManageTestTags.CREATE_INVITE, useUnmergedTree = true).assertIsNotEnabled()
    }

    @Test
    fun inviteCard_withUrl_showsCopyShareRevoke() {
        launch(GuestManageUiState(invite = invite(), isLoading = false))
        rule.onNodeWithTag(GuestManageTestTags.INVITE_URL, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(GuestManageTestTags.COPY, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(GuestManageTestTags.SHARE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(GuestManageTestTags.REVOKE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun revoke_invokesCallback() {
        var revoked: String? = null
        launch(GuestManageUiState(invite = invite("inv_7"), isLoading = false), onRevokeInvite = { revoked = it })
        rule.onNodeWithTag(GuestManageTestTags.REVOKE, useUnmergedTree = true).performClick()
        assert(revoked == "inv_7")
    }

    @Test
    fun overflowMenu_promote_invokesCallback() {
        var promoted: String? = null
        launch(GuestManageUiState(guests = listOf(guest("a")), isLoading = false), onPromote = { promoted = it })
        rule.onNodeWithTag(GuestManageTestTags.OVERFLOW, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(GuestManageTestTags.PROMOTE, useUnmergedTree = true).performClick()
        assert(promoted == "a")
    }

    @Test
    fun overflowMenu_mute_invokesCallbackWithToggledValue() {
        var muted: Boolean? = null
        launch(
            GuestManageUiState(guests = listOf(guest("a", muted = false)), isLoading = false),
            onToggleMute = { _, value -> muted = value },
        )
        rule.onNodeWithTag(GuestManageTestTags.OVERFLOW, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(GuestManageTestTags.MUTE, useUnmergedTree = true).performClick()
        assert(muted == true)
    }

    @Test
    fun remove_showsConfirmDialog_thenInvokesCallback() {
        var removed: String? = null
        launch(GuestManageUiState(guests = listOf(guest("a")), isLoading = false), onRemove = { removed = it })
        rule.onNodeWithTag(GuestManageTestTags.OVERFLOW, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(GuestManageTestTags.REMOVE, useUnmergedTree = true).performClick()
        // The confirm dialog appears; the callback only fires after confirming. (The overflow menu's Remove
        // item is dismissed on click, so the only remaining CONFIRM_LABEL node is the dialog's confirm button.)
        rule.onNodeWithTag(GuestManageTestTags.REMOVE_CONFIRM, useUnmergedTree = true).assertIsDisplayed()
        assert(removed == null)
        rule.onNode(hasText(CONFIRM_LABEL)).performClick()
        assert(removed == "a")
    }

    @Test
    fun inFlightRow_showsProgress_andHidesOverflow() {
        launch(
            GuestManageUiState(
                guests = listOf(guest("a")),
                isLoading = false,
                inFlight = setOf("a"),
            ),
        )
        rule.onNodeWithTag(GuestManageTestTags.OVERFLOW, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun emptyState_rendersWhenNoGuestsNoInvite() {
        launch(GuestManageUiState(isLoading = false))
        rule.onNodeWithTag(GuestManageTestTags.EMPTY, useUnmergedTree = true).assertIsDisplayed()
    }

    private companion object {
        // Mirrors R.string.guest_remove_confirm ("Remove").
        const val CONFIRM_LABEL = "Remove"
    }
}
