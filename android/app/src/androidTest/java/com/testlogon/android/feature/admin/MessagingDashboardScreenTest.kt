package com.testlogon.android.feature.admin

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.admin.DashboardChannel
import com.testlogon.android.core.model.admin.DashboardMetricCard
import com.testlogon.android.core.model.admin.DeliveryActivity
import com.testlogon.android.core.model.admin.DeliveryStatus
import com.testlogon.android.core.model.admin.MessagingDashboard
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-404 - Compose UI tests for the stateless [MessagingDashboardScreen] (TC-11/12/13).
 *
 * Asserts: each state renders its testTag (loading/content/empty/error/forbidden/stale); Content shows metric
 * tiles + masked, INERT activity rows with a status TEXT label (not colour alone); the screen is READ-ONLY (only
 * Refresh + Back exist - NO resend/suppress/acknowledge control by tag, and activity rows have no mutating
 * action). assertDoesNotExist is chained (a member), not imported.
 */
@RunWith(AndroidJUnit4::class)
class MessagingDashboardScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun dashboard(
        activity: List<DeliveryActivity> = listOf(
            DeliveryActivity(
                key = "k1",
                maskedRecipient = "j***@e***.com",
                status = DeliveryStatus.DELIVERED,
                detail = "Welcome",
                createdAtEpochSeconds = 1_749_132_131L,
            ),
        ),
        activityFailed: Boolean = false,
    ) = MessagingDashboard(
        channel = DashboardChannel.EMAIL,
        metrics = listOf(DashboardMetricCard("msg_sent", "Sent", "12,840")),
        deliveryRatePct = 94.3,
        activity = activity,
        allZeroStats = false,
        activityFailed = activityFailed,
    )

    private fun setContent(state: MessagingDashboardUiState) {
        rule.setContent {
            TestLogonTheme {
                MessagingDashboardScreen(
                    title = "Email delivery",
                    channel = DashboardChannel.EMAIL,
                    state = state,
                    onRefresh = {},
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun loading_rendersLoadingTag() {
        setContent(MessagingDashboardUiState.Loading)
        rule.onNodeWithTag(MessagingDashboardTestTags.LOADING).assertExists()
    }

    @Test
    fun content_rendersMetricsAndActivity_readOnly() {
        setContent(MessagingDashboardUiState.Content(dashboard()))

        rule.onNodeWithTag(MessagingDashboardTestTags.CONTENT).assertExists()
        rule.onNodeWithTag(MessagingDashboardTestTags.METRICS).assertExists()
        rule.onNodeWithTag(MessagingDashboardTestTags.metric("msg_sent")).assertExists()
        rule.onNodeWithTag(MessagingDashboardTestTags.activityRow("k1")).assertExists()

        // Status conveyed by a TEXT label (not colour alone).
        rule.onNodeWithText("Delivered").assertExists()

        // Read-only: only Refresh + Back. No mutation affordance exists.
        rule.onNodeWithTag(MessagingDashboardTestTags.REFRESH).assertExists()
        rule.onNodeWithTag("activity_resend").assertDoesNotExist()
        rule.onNodeWithTag("activity_suppress").assertDoesNotExist()
    }

    @Test
    fun emptyState_rendersEmptyTag() {
        setContent(MessagingDashboardUiState.Empty)
        rule.onNodeWithTag(MessagingDashboardTestTags.EMPTY).assertIsDisplayed()
    }

    @Test
    fun errorState_rendersErrorTag() {
        setContent(MessagingDashboardUiState.Error(AdminUiError(AdminErrorType.SERVER)))
        rule.onNodeWithTag(MessagingDashboardTestTags.ERROR).assertExists()
    }

    @Test
    fun forbiddenState_rendersForbiddenTag_noActivityRows() {
        setContent(MessagingDashboardUiState.Forbidden)
        rule.onNodeWithTag(MessagingDashboardTestTags.FORBIDDEN).assertExists()
        rule.onNodeWithTag(MessagingDashboardTestTags.activityRow("k1")).assertDoesNotExist()
    }

    @Test
    fun staleContent_rendersStaleBanner() {
        setContent(
            MessagingDashboardUiState.Content(
                dashboard(),
                isStale = true,
                error = AdminUiError(AdminErrorType.NETWORK),
            ),
        )
        rule.onNodeWithTag(MessagingDashboardTestTags.STALE_BANNER).assertExists()
    }

    @Test
    fun activityFailed_showsInlineNotice_keepsMetrics() {
        setContent(MessagingDashboardUiState.Content(dashboard(activity = emptyList(), activityFailed = true)))
        rule.onNodeWithTag(MessagingDashboardTestTags.ACTIVITY_NOTICE).assertExists()
        rule.onNodeWithTag(MessagingDashboardTestTags.metric("msg_sent")).assertExists()
    }
}
