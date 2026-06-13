package com.testlogon.android.feature.groups

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.groups.GroupMember
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-355 - Compose UI smoke tests for the stateless [GroupMembersScreen], driven by an in-test reducer
 * over [GroupMembersUiState]: roster + pending section render; a manager sees role/remove/invite
 * affordances while a non-manager gets a read-only roster. useUnmergedTree for nested testTags.
 */
@RunWith(AndroidJUnit4::class)
class GroupMembersScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val members = listOf(
        GroupMember(userId = "usr_admin", role = GroupRole.ADMIN, status = "active", displayName = "Ann"),
        GroupMember(userId = "usr_member", role = GroupRole.MEMBER, status = "active", displayName = "Bob"),
    )

    private val pending = listOf(
        GroupMember(userId = "usr_new", role = GroupRole.MEMBER, status = "invited", displayName = "Cal"),
    )

    private fun content(canManage: Boolean, viewerRole: GroupRole) = GroupMembersUiState.Content(
        members = members,
        pending = pending,
        viewerRole = viewerRole,
        canManage = canManage,
    )

    private fun launch(initial: GroupMembersUiState) {
        rule.setContent {
            TestLogonTheme {
                // In-test reducer: remove just mutates the local state.
                var state by remember { mutableStateOf(initial) }
                GroupMembersScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onInvite = {},
                    onChangeRole = { _, _ -> },
                    onRemove = { id ->
                        (state as? GroupMembersUiState.Content)?.let { c ->
                            state = c.copy(members = c.members.filterNot { it.userId == id })
                        }
                    },
                    onNoticeShown = {},
                )
            }
        }
    }

    @Test
    fun rendersRoster_andPendingSection() {
        launch(content(canManage = true, viewerRole = GroupRole.ADMIN))
        rule.onNodeWithTag(GroupMembersTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GroupMembersTestTags.MEMBER_ROW_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(GroupMembersTestTags.PENDING_PREFIX + "usr_new", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun manager_seesRoleRemoveAndInvite() {
        launch(content(canManage = true, viewerRole = GroupRole.ADMIN))
        rule.onNodeWithTag(GroupMembersTestTags.INVITE, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(GroupMembersTestTags.ROLE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(GroupMembersTestTags.REMOVE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun nonManager_isReadOnly_noInviteOrControls() {
        launch(content(canManage = false, viewerRole = GroupRole.MEMBER))
        rule.onNodeWithTag(GroupMembersTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GroupMembersTestTags.INVITE, useUnmergedTree = true).assertDoesNotExist()
        rule.onNodeWithTag(GroupMembersTestTags.ROLE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertDoesNotExist()
        rule.onNodeWithTag(GroupMembersTestTags.REMOVE_PREFIX + "usr_member", useUnmergedTree = true)
            .assertDoesNotExist()
    }
}
