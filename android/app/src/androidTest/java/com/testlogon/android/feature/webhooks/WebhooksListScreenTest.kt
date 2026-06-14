package com.testlogon.android.feature.webhooks

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.webhooks.Webhook
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.webhooks.ui.WebhooksListScreen
import com.testlogon.android.feature.webhooks.ui.WebhooksListTestTags
import com.testlogon.android.feature.webhooks.ui.WebhooksListUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-398 - Compose UI tests for the stateless [WebhooksListScreen] (the core acceptance "webhooks render"):
 * rows render with the URL + status; the Empty state shows the create CTA. assertDoesNotExist is chained (a
 * member), not imported; the tree is used unmerged for the row testTags.
 */
@RunWith(AndroidJUnit4::class)
class WebhooksListScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun webhook(id: String, url: String, enabled: Boolean) = Webhook(
        id = id,
        url = url,
        description = "",
        events = listOf("session.finalized", "mfa.verified"),
        enabled = enabled,
        secretSet = false,
        secret = null,
        createdAt = 1_747_072_651L,
    )

    private fun launch(state: WebhooksListUiState) {
        rule.setContent {
            TestLogonTheme {
                WebhooksListScreen(
                    state = state,
                    onBack = {},
                    onRefresh = {},
                    onRetry = {},
                    onCreate = {},
                    onWebhookClick = {},
                )
            }
        }
    }

    @Test
    fun rendersRows_withUrlAndStatus() {
        launch(
            WebhooksListUiState.Content(
                items = listOf(
                    webhook("wh_1", "https://a.test/h", enabled = true),
                    webhook("wh_2", "https://b.test/h", enabled = false),
                ),
            ),
        )
        rule.onNodeWithTag(WebhooksListTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(WebhooksListTestTags.row("wh_1"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(WebhooksListTestTags.row("wh_2"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("https://a.test/h", useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithText("Disabled", useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun emptyState_showsCreateCta_andNoRows() {
        launch(WebhooksListUiState.Empty)
        rule.onNodeWithTag(WebhooksListTestTags.EMPTY).assertIsDisplayed()
        rule.onNodeWithText("Create webhook").assertIsDisplayed()
        rule.onNodeWithTag(WebhooksListTestTags.row("wh_1"), useUnmergedTree = true).assertDoesNotExist()
    }
}
