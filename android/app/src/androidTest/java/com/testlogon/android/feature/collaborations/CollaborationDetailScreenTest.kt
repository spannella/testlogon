package com.testlogon.android.feature.collaborations

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.collaborations.CollabStatus
import com.testlogon.android.core.model.collaborations.Collaboration
import com.testlogon.android.core.model.collaborations.SplitDistribution
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.collaborations.ui.CollaborationDetailScreen
import com.testlogon.android.feature.collaborations.ui.CollaborationDetailUiState
import com.testlogon.android.feature.collaborations.ui.CollaborationsTestTags
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-358 - Compose UI tests for the stateless [CollaborationDetailScreen]: split rows + the total row render;
 * the non-blocking "does not total 100%" warning shows ONLY when the sum != 100; the SessionExpired surface
 * renders. assertDoesNotExist is chained (a member), not imported. useUnmergedTree where needed.
 */
@RunWith(AndroidJUnit4::class)
class CollaborationDetailScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun collab(split: Map<String, Int>) = Collaboration(
        id = "c1", title = "Track", status = "active", statusEnum = CollabStatus.ACTIVE,
        initiatorId = "usr_a", recipientId = "usr_b", split = split, createdAt = 1L,
    )

    private fun launch(
        state: CollaborationDetailUiState,
        viewerId: String? = "usr_a",
    ) {
        rule.setContent {
            TestLogonTheme {
                CollaborationDetailScreen(
                    state = state,
                    viewerId = viewerId,
                    onBack = {},
                    onRetry = {},
                    onAccept = {},
                    onReject = {},
                    onCounter = {},
                    onCancel = {},
                    onTerminate = {},
                )
            }
        }
    }

    @Test
    fun content_rendersSplitRows_andTotal_noWarningWhen100() {
        launch(
            CollaborationDetailUiState.Content(
                collab = collab(mapOf("usr_a" to 60, "usr_b" to 40)),
            ),
        )
        rule.onNodeWithTag(CollaborationsTestTags.DETAIL_SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.STATUS, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.splitRow("usr_a")).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.splitRow("usr_b")).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.SPLIT_TOTAL).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.SPLIT_WARNING).assertDoesNotExist()
    }

    @Test
    fun content_showsWarning_whenSplitNot100() {
        launch(
            CollaborationDetailUiState.Content(
                collab = collab(mapOf("usr_a" to 60, "usr_b" to 30)),
            ),
        )
        rule.onNodeWithTag(CollaborationsTestTags.SPLIT_TOTAL).assertIsDisplayed()
        rule.onNodeWithTag(CollaborationsTestTags.SPLIT_WARNING).assertIsDisplayed()
    }

    @Test
    fun content_rendersDistributions_whenPresent() {
        launch(
            CollaborationDetailUiState.Content(
                collab = collab(mapOf("usr_a" to 60, "usr_b" to 40)),
                distributions = listOf(
                    SplitDistribution(userId = "usr_a", percent = 60, amountCents = 6000),
                ),
            ),
        )
        rule.onNodeWithTag(CollaborationsTestTags.distribution(0)).assertIsDisplayed()
    }

    @Test
    fun sessionExpired_showsSignalSurface() {
        launch(CollaborationDetailUiState.SessionExpired)
        rule.onNodeWithTag(CollaborationsTestTags.SESSION_EXPIRED).assertIsDisplayed()
    }
}
