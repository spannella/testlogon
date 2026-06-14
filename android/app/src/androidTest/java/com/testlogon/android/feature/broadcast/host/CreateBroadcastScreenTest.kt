package com.testlogon.android.feature.broadcast.host

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/** AND-307 — Compose UI tests for the stateless [CreateBroadcastScreen]. */
@RunWith(AndroidJUnit4::class)
class CreateBroadcastScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun scheduledSession() = BroadcastSession(
        id = "bcs_1",
        profileId = "prof_9",
        name = "Show",
        description = null,
        status = BroadcastSessionStatus.SCHEDULED,
        createdBy = "host",
        scheduledAt = Instant.ofEpochSecond(1749319200L),
        scheduleStatus = "scheduled",
        startedAt = null,
        stoppedAt = null,
        cancelledAt = null,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    /** Drives the stateless screen with an in-test reducer over [CreateBroadcastUiState]. */
    private fun launch(initial: CreateBroadcastUiState = CreateBroadcastUiState()) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                CreateBroadcastScreen(
                    state = state,
                    onTitleChange = { state = state.copy(title = it) },
                    onDescriptionChange = { state = state.copy(description = it) },
                    onToggleScheduleLater = { state = state.copy(scheduleForLater = it) },
                    onScheduledAtChange = { state = state.copy(scheduledAtEpochSeconds = it) },
                    onSubmit = {},
                    onCancelSchedule = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun submit_disabledWhenBlank_enabledWhenTitleFilled() {
        launch()
        rule.onNodeWithTag(CreateBroadcastTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(CreateBroadcastTestTags.SUBMIT).assertIsNotEnabled()

        rule.onNodeWithTag(CreateBroadcastTestTags.TITLE).performTextInput("My show")
        rule.onNodeWithTag(CreateBroadcastTestTags.SUBMIT).assertIsEnabled()
    }

    @Test
    fun scheduleToggle_revealsTimeInput() {
        launch()
        rule.onNodeWithTag(CreateBroadcastTestTags.SCHEDULED_AT).assertDoesNotExist()
        rule.onNodeWithTag(CreateBroadcastTestTags.SCHEDULE_TOGGLE).performClick()
        rule.onNodeWithTag(CreateBroadcastTestTags.SCHEDULED_AT).assertIsDisplayed()
    }

    @Test
    fun cancelSchedule_visibleWhenScheduledSessionExists() {
        launch(
            CreateBroadcastUiState(
                title = "Show",
                scheduleForLater = true,
                scheduledAtEpochSeconds = 1749319200L,
                createdSession = scheduledSession(),
            ),
        )
        rule.onNodeWithTag(CreateBroadcastTestTags.CANCEL_SCHEDULE).assertIsDisplayed()
    }
}
