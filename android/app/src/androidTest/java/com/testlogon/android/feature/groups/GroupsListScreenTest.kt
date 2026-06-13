package com.testlogon.android.feature.groups

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.groups.Group
import com.testlogon.android.core.model.groups.GroupRole
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-355 - Compose UI smoke tests for the stateless [GroupsListScreen]: rows render with their group id
 * test tag; the empty surface renders. useUnmergedTree for nested testTags.
 */
@RunWith(AndroidJUnit4::class)
class GroupsListScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private val groups = listOf(
        Group(id = "grp_1", name = "Hikers", memberCount = 3, myRole = GroupRole.ADMIN),
        Group(id = "grp_2", name = "Readers", memberCount = 8, myRole = GroupRole.MEMBER),
    )

    private fun launch(state: GroupsListUiState) {
        rule.setContent {
            TestLogonTheme {
                GroupsListScreen(
                    state = state,
                    onBack = {},
                    onRetry = {},
                    onRefresh = {},
                    onOpenGroup = {},
                )
            }
        }
    }

    @Test
    fun rendersRows_andScreen() {
        launch(GroupsListUiState.Content(groups = groups))
        rule.onNodeWithTag(GroupsListTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GroupsListTestTags.ROW_PREFIX + "grp_1", useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(GroupsListTestTags.ROW_PREFIX + "grp_2", useUnmergedTree = true)
            .assertIsDisplayed()
    }

    @Test
    fun emptyState_rendersScreen_noRows() {
        launch(GroupsListUiState.Empty)
        rule.onNodeWithTag(GroupsListTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(GroupsListTestTags.ROW_PREFIX + "grp_1", useUnmergedTree = true)
            .assertDoesNotExist()
    }
}
