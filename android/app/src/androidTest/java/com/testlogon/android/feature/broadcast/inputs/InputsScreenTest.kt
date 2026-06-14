package com.testlogon.android.feature.broadcast.inputs

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.broadcast.BroadcastInput
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-310 — Compose UI tests for the stateless [InputsScreen]. Drives an in-test reducer over
 * [InputsUiState]. Asserts: the program row's Switch is disabled (with deactivate-blocked semantics), a
 * non-live row has no "Make live", a pending row shows progress and is non-interactive, and the empty /
 * error states render. useUnmergedTree where row controls are nested; assertDoesNotExist is a member.
 */
@RunWith(AndroidJUnit4::class)
class InputsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun input(
        id: String,
        isLive: Boolean = false,
        isProgram: Boolean = false,
    ) = BroadcastInput(
        inputId = id,
        sessionId = "bcs_1",
        inputType = "guest",
        label = "Input $id",
        ingestUrl = null,
        streamKey = null,
        position = 0,
        isLive = isLive,
        isProgram = isProgram,
    )

    private fun row(
        id: String,
        isLive: Boolean = false,
        isProgram: Boolean = false,
    ): InputRow {
        val i = input(id, isLive, isProgram)
        return InputRow(
            input = i,
            canMakeLive = i.isLive && !isProgram,
            canDeactivate = !isProgram,
        )
    }

    private fun launch(initial: InputsUiState) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                InputsScreen(
                    state = state,
                    onToggleActive = { id, target ->
                        // Trivial in-test reducer: flip the toggled row's is_live.
                        val current = state
                        if (current is InputsUiState.Content) {
                            state = current.copy(
                                inputs = current.inputs.map {
                                    if (it.input.inputId == id) {
                                        it.copy(input = it.input.copy(isLive = target))
                                    } else {
                                        it
                                    }
                                },
                            )
                        }
                    },
                    onMakeLive = {},
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun screen_renders() {
        launch(InputsUiState.Content(inputs = listOf(row("a", isLive = true))))
        rule.onNodeWithTag(InputsTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(InputsTestTags.row("a")).assertIsDisplayed()
    }

    @Test
    fun programRow_switchDisabled_andBadgeShown() {
        launch(
            InputsUiState.Content(inputs = listOf(row("a", isLive = true, isProgram = true))),
        )
        rule.onNodeWithTag(InputsTestTags.TOGGLE, useUnmergedTree = true).assertIsNotEnabled()
        rule.onNodeWithTag(InputsTestTags.PROGRAM_BADGE, useUnmergedTree = true).assertIsDisplayed()
        // The program row cannot be made live again.
        rule.onNodeWithTag(InputsTestTags.MAKE_LIVE, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun nonLiveRow_hasNoMakeLive() {
        launch(InputsUiState.Content(inputs = listOf(row("a", isLive = false))))
        rule.onNodeWithTag(InputsTestTags.MAKE_LIVE, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun liveNonProgramRow_showsMakeLive() {
        launch(InputsUiState.Content(inputs = listOf(row("a", isLive = true, isProgram = false))))
        rule.onNodeWithTag(InputsTestTags.MAKE_LIVE, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun pendingRow_showsProgress_andHidesControls() {
        launch(
            InputsUiState.Content(
                inputs = listOf(row("a", isLive = true)),
                pendingIds = setOf("a"),
            ),
        )
        rule.onNodeWithTag(InputsTestTags.PENDING, useUnmergedTree = true).assertIsDisplayed()
        // Pending rows are non-interactive: no toggle / make-live affordances rendered.
        rule.onNodeWithTag(InputsTestTags.TOGGLE, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(InputsTestTags.MAKE_LIVE, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun emptyState_renders() {
        launch(InputsUiState.Empty())
        rule.onNodeWithTag(InputsTestTags.EMPTY, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun errorState_renders() {
        launch(InputsUiState.Error(message = "Couldn't load", retryable = true))
        rule.onNodeWithTag(InputsTestTags.ERROR, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun staleBanner_shownOnStaleContent() {
        launch(
            InputsUiState.Content(inputs = listOf(row("a")), isStale = true),
        )
        rule.onNodeWithTag(InputsTestTags.STALE_BANNER, useUnmergedTree = true).assertIsDisplayed()
    }
}
