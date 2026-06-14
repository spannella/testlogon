package com.testlogon.android.feature.broadcast.host

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertHasClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.broadcast.BroadcastSession
import com.testlogon.android.data.broadcast.BroadcastSessionStatus
import com.testlogon.android.data.broadcast.HealthLevel
import com.testlogon.android.data.broadcast.HostHealthReport
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-309 — Compose UI tests for the stateless [HostControlScreen]. An in-test reducer drives the
 * [HostControlUiState] so the surface is exercised end-to-end without Hilt/network. Uses useUnmergedTree for
 * nested nodes; assertDoesNotExist is a MEMBER call (not imported).
 */
@RunWith(AndroidJUnit4::class)
class HostControlScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun session(
        status: BroadcastSessionStatus,
        startedAt: Instant? = null,
    ) = BroadcastSession(
        id = "bcs_1",
        profileId = "prof_9",
        name = "Friday Night Live",
        description = null,
        status = status,
        createdBy = "host",
        scheduledAt = null,
        scheduleStatus = null,
        startedAt = startedAt,
        stoppedAt = null,
        cancelledAt = null,
        playbackUrl = null,
        thumbnailUrl = null,
        tipTotalCents = null,
        tipCount = null,
        createdAt = Instant.EPOCH,
        updatedAt = Instant.EPOCH,
    )

    private fun health() = HostHealthReport(
        sessionId = "bcs_1",
        connectionQuality = "healthy",
        level = HealthLevel.HEALTHY,
        ingestBitrateKbps = 4200,
        ingestFramerate = 30.0,
        droppedFrames = 0,
        droppedFramesPct = 0.0,
        outputErrors = 0,
        inputLossSeconds = 0.0,
        viewerCount = 100,
        updatedAt = Instant.ofEpochSecond(1749322800L),
    )

    private fun launch(initial: HostControlUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                HostControlScreen(
                    state = state,
                    onStart = { state = state.copy(inFlight = HostAction.START) },
                    onStop = { state = state.copy(showStopConfirm = true) },
                    onConfirmStop = { confirmed ->
                        state = state.copy(showStopConfirm = false, inFlight = if (confirmed) HostAction.STOP else null)
                    },
                    onResume = { state = state.copy(inFlight = HostAction.RESUME) },
                    onReschedule = { state = state.copy(inFlight = HostAction.RESCHEDULE) },
                    onRetryHealth = { state = state.copy(healthStale = false) },
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun screenRenders_withStatusChip() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.SCHEDULED), loading = false))
        rule.onNodeWithTag(HostControlTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(HostControlTestTags.STATUS_CHIP).assertIsDisplayed()
    }

    @Test
    fun start_enabledForScheduled() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.SCHEDULED), loading = false))
        rule.onNodeWithTag(HostControlTestTags.START).assertIsEnabled()
    }

    @Test
    fun start_enabledForReady() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.READY), loading = false))
        rule.onNodeWithTag(HostControlTestTags.START).assertIsEnabled()
    }

    @Test
    fun start_disabledForLive() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.LIVE), loading = false))
        rule.onNodeWithTag(HostControlTestTags.START).assertIsNotEnabled()
        // Stop is enabled while LIVE.
        rule.onNodeWithTag(HostControlTestTags.STOP).assertIsEnabled()
    }

    @Test
    fun inFlight_disablesWholeBar() {
        launch(
            HostControlUiState(
                session = session(BroadcastSessionStatus.SCHEDULED),
                inFlight = HostAction.START,
                loading = false,
            ),
        )
        rule.onNodeWithTag(HostControlTestTags.START).assertIsNotEnabled()
        rule.onNodeWithTag(HostControlTestTags.RESCHEDULE).assertIsNotEnabled()
    }

    @Test
    fun onStop_showsConfirmDialog() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.LIVE), loading = false))
        rule.onNodeWithTag(HostControlTestTags.STOP_CONFIRM).assertDoesNotExist()
        rule.onNodeWithTag(HostControlTestTags.STOP).performClick()
        rule.onNodeWithTag(HostControlTestTags.STOP_CONFIRM).assertIsDisplayed()
    }

    @Test
    fun staleBanner_visibleWhenHealthStale() {
        launch(
            HostControlUiState(
                session = session(BroadcastSessionStatus.LIVE),
                health = health(),
                healthStale = true,
                loading = false,
            ),
        )
        rule.onNodeWithTag(HostControlTestTags.STALE_BANNER, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun staleBanner_absentWhenFresh() {
        launch(
            HostControlUiState(
                session = session(BroadcastSessionStatus.LIVE),
                health = health(),
                healthStale = false,
                loading = false,
            ),
        )
        rule.onNodeWithTag(HostControlTestTags.STALE_BANNER, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun actionButtons_haveContentDescriptions() {
        launch(HostControlUiState(session = session(BroadcastSessionStatus.LIVE), loading = false))
        rule.onNodeWithContentDescription("Start broadcast", useUnmergedTree = true).assertExists()
        rule.onNodeWithContentDescription("Stop broadcast", useUnmergedTree = true)
            .assertHasClickAction()
    }
}
