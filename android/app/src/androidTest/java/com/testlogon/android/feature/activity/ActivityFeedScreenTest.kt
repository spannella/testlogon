package com.testlogon.android.feature.activity

import androidx.compose.runtime.remember
import androidx.compose.ui.test.assertCountEquals
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.paging.PagingData
import androidx.paging.compose.collectAsLazyPagingItems
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.activity.ActivityEvent
import com.testlogon.android.data.activity.ActivityEventType
import kotlinx.coroutines.flow.flowOf
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-096 — Compose UI smoke tests for the stateless [ActivityFeedScreen]. */
@RunWith(AndroidJUnit4::class)
class ActivityFeedScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun event(id: String, read: Boolean = false) = ActivityEvent(
        id = id,
        type = ActivityEventType.LOGIN_SUCCESS,
        rawType = "login_success",
        actorId = "usr_1",
        createdAtEpochSeconds = 1_749_132_202L,
        targetType = null,
        targetId = null,
        read = read,
        detail = null,
    )

    private fun launch(items: List<ActivityEvent>) {
        rule.setContent {
            TestLogonTheme {
                val paging = remember { flowOf(PagingData.from(items)) }
                ActivityFeedScreen(
                    items = paging.collectAsLazyPagingItems(),
                    onRefresh = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun rendersRows() {
        launch(listOf(event("a1", read = false), event("a2", read = true)))
        rule.onNodeWithTag(ActivityTestTags.SCREEN).assertIsDisplayed()
        rule.onAllNodesWithTag(ActivityTestTags.ROW).assertCountEquals(2)
    }

    @Test
    fun emptyState_rendersWhenNoItems() {
        launch(emptyList())
        rule.onNodeWithText("No activity yet").assertIsDisplayed()
    }
}
