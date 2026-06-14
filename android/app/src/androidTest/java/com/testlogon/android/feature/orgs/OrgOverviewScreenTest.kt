package com.testlogon.android.feature.orgs

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.ApiError
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-354 - Compose UI smoke tests for the stateless [OrgOverviewScreen]: overview renders the org name +
 * the Members / My-Invites nav rows (which fire their callbacks); empty + error surfaces render the
 * scaffold. useUnmergedTree for nested testTags.
 */
@RunWith(AndroidJUnit4::class)
class OrgOverviewScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun content() = OrgOverviewUiState.Content(
        org = Org(orgId = "org_1", name = "Acme", callerRole = OrgRole.ADMIN),
        memberCount = 3,
        callerRole = OrgRole.ADMIN,
    )

    private fun launch(
        initial: OrgOverviewUiState,
        onOpenMembers: () -> Unit = {},
        onOpenInvites: () -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme {
                OrgOverviewScreen(
                    state = initial,
                    onBack = {},
                    onRetry = {},
                    onOpenMembers = onOpenMembers,
                    onOpenInvites = onOpenInvites,
                )
            }
        }
    }

    @Test
    fun content_rendersNameAndNavRows() {
        launch(content())
        rule.onNodeWithTag(OrgOverviewTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OrgOverviewTestTags.NAME, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(OrgOverviewTestTags.MEMBERS_NAV, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(OrgOverviewTestTags.INVITES_NAV, useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun navRows_fireCallbacks() {
        var members = 0
        var invites = 0
        launch(content(), onOpenMembers = { members++ }, onOpenInvites = { invites++ })
        rule.onNodeWithTag(OrgOverviewTestTags.MEMBERS_NAV, useUnmergedTree = true).performClick()
        rule.onNodeWithTag(OrgOverviewTestTags.INVITES_NAV, useUnmergedTree = true).performClick()
        assert(members == 1)
        assert(invites == 1)
    }

    @Test
    fun emptyState_rendersScaffold_noNavRows() {
        launch(OrgOverviewUiState.Empty)
        rule.onNodeWithTag(OrgOverviewTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OrgOverviewTestTags.MEMBERS_NAV, useUnmergedTree = true).assertDoesNotExist()
    }

    @Test
    fun errorState_rendersScaffold() {
        launch(OrgOverviewUiState.Error(ApiError(status = 500, message = "boom")))
        rule.onNodeWithTag(OrgOverviewTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OrgOverviewTestTags.NAME, useUnmergedTree = true).assertDoesNotExist()
    }
}
