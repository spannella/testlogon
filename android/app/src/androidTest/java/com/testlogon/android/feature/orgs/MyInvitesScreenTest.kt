package com.testlogon.android.feature.orgs

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-354 - Compose UI smoke tests for the stateless [MyInvitesScreen], driven by an in-test reducer over
 * [MyInvitesUiState]: the list renders with accept/decline affordances; decline removes the row;
 * empty/error surfaces render the scaffold. useUnmergedTree for nested testTags.
 */
@RunWith(AndroidJUnit4::class)
class MyInvitesScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val invites = listOf(
        OrgInvite(inviteId = "inv_1", email = "a@x.com", role = OrgRole.MEMBER, orgName = "Acme"),
        OrgInvite(inviteId = "inv_2", email = "b@x.com", role = OrgRole.VIEWER, orgName = "Globex"),
    )

    private fun launch(initial: MyInvitesUiState) {
        rule.setContent {
            TestLogonTheme {
                // In-test reducer: decline / accept just drop the row locally.
                var state by remember { mutableStateOf(initial) }
                MyInvitesScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onAccept = { id ->
                        (state as? MyInvitesUiState.Content)?.let { c ->
                            state = c.copy(invites = c.invites.filterNot { it.inviteId == id })
                        }
                    },
                    onDecline = { id ->
                        (state as? MyInvitesUiState.Content)?.let { c ->
                            state = c.copy(invites = c.invites.filterNot { it.inviteId == id })
                        }
                    },
                    onNoticeShown = {},
                )
            }
        }
    }

    @Test
    fun rendersList_withAcceptAndDecline() {
        launch(MyInvitesUiState.Content(invites = invites))
        rule.onNodeWithTag(MyInvitesTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(MyInvitesTestTags.ROW_PREFIX + "inv_1", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(MyInvitesTestTags.ACCEPT_PREFIX + "inv_1", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(MyInvitesTestTags.DECLINE_PREFIX + "inv_1", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun decline_removesRow() {
        launch(MyInvitesUiState.Content(invites = invites))
        rule.onNodeWithTag(MyInvitesTestTags.DECLINE_PREFIX + "inv_1", useUnmergedTree = true)
            .performClick()
        rule.onNodeWithTag(MyInvitesTestTags.ROW_PREFIX + "inv_1", useUnmergedTree = true)
            .assertDoesNotExist()
        rule.onNodeWithTag(MyInvitesTestTags.ROW_PREFIX + "inv_2", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun emptyState_rendersScaffold() {
        launch(MyInvitesUiState.Empty)
        rule.onNodeWithTag(MyInvitesTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(MyInvitesTestTags.ROW_PREFIX + "inv_1", useUnmergedTree = true)
            .assertDoesNotExist()
    }

    @Test
    fun errorState_rendersScaffold() {
        launch(MyInvitesUiState.Error(ApiError(status = 500, message = "boom")))
        rule.onNodeWithTag(MyInvitesTestTags.SCREEN).assertIsDisplayed()
    }
}
