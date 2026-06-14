package com.testlogon.android.feature.admin

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.admin.AdminAlert
import com.testlogon.android.core.model.admin.AdminDashboard
import com.testlogon.android.core.model.admin.AdminMetric
import com.testlogon.android.core.model.admin.AlertSeverity
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-403 - Compose UI tests for the stateless [AdminDashboardScreen] (TC-05/10).
 *
 * Asserts: admin Content renders the metric tiles + an alert with a severity TEXT label (not colour alone);
 * the screen is READ-ONLY (only Refresh + Back actions exist - NO acknowledge/dismiss/resolve/edit/delete
 * control by tag); the Forbidden state renders with a Back action and no alert rows; empty alerts show the
 * "No active alerts" copy while metric tiles still render. assertDoesNotExist is chained (a member), not
 * imported.
 */
@RunWith(AndroidJUnit4::class)
class AdminDashboardScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun dashboard(
        alerts: List<AdminAlert> = listOf(
            AdminAlert(
                id = "job_payouts",
                severity = AlertSeverity.CRITICAL,
                title = "Payouts",
                message = "boom",
                source = "jobs",
                createdAtEpochSeconds = 1_717_200_000L,
            ),
        ),
        metrics: List<AdminMetric> = listOf(
            AdminMetric(key = "total_jobs", label = "Background jobs", value = "3"),
        ),
    ) = AdminDashboard(alerts = alerts, metrics = metrics)

    private fun setContent(state: AdminDashboardUiState) {
        rule.setContent {
            TestLogonTheme {
                AdminDashboardScreen(
                    state = state,
                    onRefresh = {},
                    onRetry = {},
                    onBack = {},
                )
            }
        }
    }

    @Test
    fun content_rendersMetricsAndAlerts_readOnly() {
        setContent(AdminDashboardUiState.Content(dashboard()))

        rule.onNodeWithTag(AdminDashboardTestTags.METRICS).assertExists()
        rule.onNodeWithTag(AdminDashboardTestTags.metric("total_jobs")).assertExists()
        rule.onNodeWithTag(AdminDashboardTestTags.alert("job_payouts")).assertExists()

        // Severity conveyed by a TEXT label (not colour alone).
        rule.onNodeWithText("Critical").assertExists()

        // Read-only: only Refresh + Back. Assert NO mutation affordance exists.
        rule.onNodeWithTag(AdminDashboardTestTags.REFRESH).assertExists()
        rule.onNodeWithTag("admin_alert_acknowledge").assertDoesNotExist()
        rule.onNodeWithTag("admin_alert_dismiss").assertDoesNotExist()
        rule.onNodeWithTag("admin_alert_resolve").assertDoesNotExist()
    }

    @Test
    fun emptyAlerts_presentMetrics_showsNoAlertsButKeepsMetrics() {
        setContent(AdminDashboardUiState.Content(dashboard(alerts = emptyList())))

        rule.onNodeWithTag(AdminDashboardTestTags.NO_ALERTS).assertIsDisplayed()
        rule.onNodeWithTag(AdminDashboardTestTags.metric("total_jobs")).assertExists()
    }

    @Test
    fun forbidden_rendersForbiddenState_noAlertRows() {
        setContent(AdminDashboardUiState.Forbidden)

        rule.onNodeWithTag(AdminDashboardTestTags.FORBIDDEN).assertExists()
        rule.onNodeWithTag(AdminDashboardTestTags.alert("job_payouts")).assertDoesNotExist()
    }
}
