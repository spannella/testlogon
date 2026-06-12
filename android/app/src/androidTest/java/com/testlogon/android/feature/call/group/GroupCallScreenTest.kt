package com.testlogon.android.feature.call.group

import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.call.group.ConnQuality
import com.testlogon.android.data.call.group.GroupParticipant
import com.testlogon.android.data.call.group.ParticipantState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-299 — Compose UI tests for the stateless [GroupCallScreen] / [ParticipantGrid]. Renders with a
 * hand-built participant list (no Hilt).
 */
@RunWith(AndroidJUnit4::class)
class GroupCallScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun participant(
        userId: String,
        micMuted: Boolean = false,
        cameraOff: Boolean = false,
        joinedAt: Long = 0,
    ) = GroupParticipant(
        userId = userId,
        displayName = userId,
        isSelf = false,
        isHost = false,
        state = ParticipantState.Connected,
        micMuted = micMuted,
        cameraOff = cameraOff,
        quality = ConnQuality.Good,
        joinedAt = joinedAt,
    )

    private fun state(
        participants: List<GroupParticipant>,
        mediaUnavailable: Boolean = true,
        activeSpeakerUserId: String? = null,
    ) = GroupCallUiState(
        callId = "g1",
        phase = GroupCallPhase.Active,
        participants = participants,
        mediaUnavailable = mediaUnavailable,
        activeSpeakerUserId = activeSpeakerUserId,
    )

    private fun launch(initial: GroupCallUiState) {
        rule.setContent {
            TestLogonTheme {
                GroupCallScreen(state = initial, onAction = {})
            }
        }
    }

    @Test
    fun rendersOneTilePerParticipant() {
        val people = listOf(participant("a", joinedAt = 1), participant("b", joinedAt = 2), participant("c", joinedAt = 3))
        launch(state(people))
        rule.onAllNodesWithTag("participant_tile", useUnmergedTree = true).assertCountEquals(3)
    }

    @Test
    fun leaveControl_exposesContentDescription() {
        launch(state(listOf(participant("a"))))
        rule.onNodeWithContentDescription("Leave call", useUnmergedTree = true).assertIsEnabled()
    }

    @Test
    fun mediaUnavailableBanner_shows_whenFlagged() {
        launch(state(listOf(participant("a")), mediaUnavailable = true))
        rule.onNodeWithTag("groupcall_media_unavailable", useUnmergedTree = true).assertExists()
    }

    @Test
    fun mediaUnavailableBanner_hidden_whenNotFlagged() {
        launch(state(listOf(participant("a")), mediaUnavailable = false))
        rule.onNodeWithTag("groupcall_media_unavailable", useUnmergedTree = true).assertDoesNotExist()
    }
}
