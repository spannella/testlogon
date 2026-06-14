package com.testlogon.android.feature.orgs

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.orgs.Org
import com.testlogon.android.core.model.orgs.OrgInvite
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.model.orgs.OrgRole
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-353 - Compose UI smoke tests for the stateless [OrgMembersScreen], driven by an in-test reducer
 * over [OrgMembersUiState]: roster renders; a manager sees role/remove/invite affordances while a
 * non-manager gets a read-only roster; pending invites render. useUnmergedTree for nested testTags.
 */
@RunWith(AndroidJUnit4::class)
class OrgMembersScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val members = listOf(
        OrgMember(userSub = "usr_admin", role = OrgRole.ADMIN, status = "active"),
        OrgMember(userSub = "usr_member", role = OrgRole.MEMBER, status = "active"),
    )

    private val invites = listOf(
        OrgInvite(inviteId = "inv_1", email = "new@x.com", role = OrgRole.VIEWER),
    )

    private fun content(canManage: Boolean, callerRole: OrgRole) = OrgMembersUiState.Content(
        org = Org(orgId = "org_1", name = "Acme", callerRole = callerRole),
        members = members,
        pendingInvites = invites,
        callerRole = callerRole,
        canManage = canManage,
    )

    private fun launch(initial: OrgMembersUiState, callerUserSub: String? = "usr_admin") {
        rule.setContent {
            TestLogonTheme {
                // In-test reducer: changeRole / remove just mutate the local state.
                var state by remember { mutableStateOf(initial) }
                OrgMembersScreen(
                    state = state,
                    callerUserSub = callerUserSub,
                    onBack = {},
                    onRetry = {},
                    onChangeRole = { _, _ -> },
                    onRemove = { sub ->
                        (state as? OrgMembersUiState.Content)?.let { c ->
                            state = c.copy(members = c.members.filterNot { it.userSub == sub })
                        }
                    },
                    onInvite = {},
                    onNoticeShown = {},
                )
            }
        }
    }

    @Test
    fun rendersRoster_andScreen() {
        launch(content(canManage = true, callerRole = OrgRole.ADMIN))
        rule.onNodeWithTag(OrgMembersTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OrgMembersTestTags.MEMBER_ROW_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(OrgMembersTestTags.PENDING_INVITE_PREFIX + "inv_1", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun manager_seesRoleRemoveAndInvite() {
        launch(content(canManage = true, callerRole = OrgRole.ADMIN))
        rule.onNodeWithTag(OrgMembersTestTags.INVITE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(OrgMembersTestTags.ROLE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(OrgMembersTestTags.REMOVE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun nonManager_isReadOnly_noInviteOrControls() {
        launch(content(canManage = false, callerRole = OrgRole.MEMBER), callerUserSub = "usr_member")
        rule.onNodeWithTag(OrgMembersTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(OrgMembersTestTags.INVITE, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(OrgMembersTestTags.ROLE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertDoesNotExist()
        rule.onNodeWithTag(OrgMembersTestTags.REMOVE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertDoesNotExist()
    }

    @Test
    fun loadingState_rendersScreenScaffold() {
        launch(OrgMembersUiState.Loading)
        rule.onNodeWithTag(OrgMembersTestTags.SCREEN).assertIsDisplayed()
    }
}
