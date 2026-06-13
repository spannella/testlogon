package com.testlogon.android.feature.tickets

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.tickets.SpaceMember
import com.testlogon.android.core.model.tickets.TicketSpace
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.tickets.ui.SpacesListScreen
import com.testlogon.android.feature.tickets.ui.SpacesListTestTags
import com.testlogon.android.feature.tickets.ui.SpacesListUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-372 - Compose UI tests for the stateless [SpacesListScreen]: rows render with the member count (derived
 * from members.size), and an Empty state renders the empty surface. assertDoesNotExist is chained (a member),
 * not imported; the tree is used unmerged for the row testTags.
 */
@RunWith(AndroidJUnit4::class)
class SpacesListScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun space(id: String, members: Int) = TicketSpace(
        spaceId = id,
        name = "Space $id",
        visibility = "private",
        members = List(members) { SpaceMember(userSub = "u$it") },
        memberCount = members,
        updatedAt = 100L,
    )

    private fun launch(state: SpacesListUiState) {
        rule.setContent {
            TestLogonTheme {
                SpacesListScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                    onSpaceClick = {},
                )
            }
        }
    }

    @Test
    fun rendersRows_withMemberCount() {
        launch(SpacesListUiState.Content(spaces = listOf(space("s1", 3), space("s2", 1))))
        rule.onNodeWithTag(SpacesListTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(SpacesListTestTags.row("s1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(SpacesListTestTags.row("s2"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("3 members", useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun emptyState_showsEmptySurface_andNoRows() {
        launch(SpacesListUiState.Empty)
        rule.onNodeWithTag(SpacesListTestTags.EMPTY).assertIsDisplayed()
        rule.onNodeWithTag(SpacesListTestTags.row("s1"), useUnmergedTree = true).assertDoesNotExist()
    }
}
