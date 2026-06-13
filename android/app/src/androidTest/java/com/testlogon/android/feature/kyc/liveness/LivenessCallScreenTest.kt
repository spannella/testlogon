package com.testlogon.android.feature.kyc.liveness

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.kyc.liveness.model.LivenessCall
import com.testlogon.android.feature.kyc.liveness.model.LivenessCallStatus
import com.testlogon.android.feature.kyc.liveness.model.LivenessResult
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.time.Instant

/**
 * AND-324 - Compose UI smoke tests for the stateless [LivenessCallScreen]. An in-test reducer over a
 * remembered [LivenessUiState] drives the screen (no VM / Hilt). useUnmergedTree for non-merging
 * surfaces; assertDoesNotExist is used as a MEMBER on the node.
 */
@RunWith(AndroidJUnit4::class)
class LivenessCallScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun launch(initial: LivenessUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                LivenessCallScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    onSchedule = { _, _, _ ->
                        (state as? LivenessUiState.Ready)?.let { state = it.copy(scheduling = true) }
                    },
                    onCancel = {},
                    onJoin = {},
                )
            }
        }
    }

    @Test
    fun ready_showsScheduleForm_durationAndDateAndButton() {
        launch(LivenessUiState.Ready(calls = emptyList()))
        rule.onNodeWithTag(LivenessCallTestTags.SCREEN, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(LivenessCallTestTags.DATE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(LivenessCallTestTags.DURATION, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(LivenessCallTestTags.SCHEDULE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun callRow_showsStatusBadge() {
        val call = call("call_1", LivenessCallStatus.SCHEDULED)
        launch(LivenessUiState.Ready(calls = listOf(call)))
        rule.onNodeWithTag(LivenessCallTestTags.row("call_1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(LivenessCallTestTags.status("call_1"), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun join_shownOnlyWhenJoinUrlPresent() {
        val withUrl = call("call_1", LivenessCallStatus.IN_PROGRESS, joinUrl = "https://verify.example/join/abc")
        launch(LivenessUiState.Ready(calls = listOf(withUrl)))
        rule.onNodeWithTag(LivenessCallTestTags.JOIN, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun join_absentWhenNoJoinUrl() {
        val noUrl = call("call_1", LivenessCallStatus.SCHEDULED, joinUrl = null)
        launch(LivenessUiState.Ready(calls = listOf(noUrl)))
        rule.onNodeWithTag(LivenessCallTestTags.JOIN).assertDoesNotExist()
    }

    @Test
    fun cancel_shownOnlyWhenCancellable() {
        val cancellable = call("call_1", LivenessCallStatus.SCHEDULED)
        launch(LivenessUiState.Ready(calls = listOf(cancellable)))
        rule.onNodeWithTag(LivenessCallTestTags.CANCEL, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun cancel_absentWhenNotCancellable() {
        val done = call("call_1", LivenessCallStatus.PASSED, result = LivenessResult.PASSED)
        launch(LivenessUiState.Ready(calls = listOf(done)))
        rule.onNodeWithTag(LivenessCallTestTags.CANCEL).assertDoesNotExist()
    }

    private fun call(
        callId: String,
        status: LivenessCallStatus,
        joinUrl: String? = null,
        result: LivenessResult? = null,
    ) = LivenessCall(
        callId = callId,
        caseId = "kyc_1",
        status = status,
        scheduledAt = Instant.ofEpochSecond(1_780_000_000L),
        durationMinutes = 15,
        result = result,
        joinUrl = joinUrl,
    )
}
