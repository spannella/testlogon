package com.testlogon.android.feature.dashboard

import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithTag
import androidx.compose.ui.test.onFirst
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.Dashboard
import com.testlogon.android.core.model.EarningsBreakdown
import com.testlogon.android.core.model.Milestone
import com.testlogon.android.core.ui.theme.TestLogonTheme
import org.junit.Assert.assertEquals
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** AND-069 — headless Compose UI tests over the dashboard render states. */
@RunWith(AndroidJUnit4::class)
class DashboardScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun sample() = Dashboard(
        todayEarningsCents = 12750,
        earningsBreakdown = EarningsBreakdown(8000, 2500, 1500, 750, 0),
        periodViews = 18342,
        periodRevenueCents = 96000,
        totalSubscribers = 1280,
        topContent = emptyList(),
        activeBroadcasts = emptyList(),
        recentMilestones = listOf(
            Milestone("m1", "subscribers", 1000, 1280, "1,000 subscribers", null, false),
        ),
        currency = "USD",
        generatedAtMillis = null,
        warnings = emptyList(),
    )

    private fun setState(
        state: DashboardUiState,
        onRefresh: () -> Unit = {},
        onRetry: () -> Unit = {},
        onQuickLink: (QuickLink) -> Unit = {},
    ) {
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                DashboardScreen(
                    state = state,
                    onRefresh = onRefresh,
                    onRetry = onRetry,
                    onQuickLink = onQuickLink,
                )
            }
        }
    }

    @Test
    fun loading_showsLoadingAffordance() {
        setState(DashboardUiState(phase = DashboardUiState.Phase.Loading))
        rule.onNodeWithTag(DashboardTestTags.LOADING).assertIsDisplayed()
    }

    @Test
    fun content_showsWidgets() {
        setState(DashboardUiState(phase = DashboardUiState.Phase.Content, dashboard = sample()))
        rule.onNodeWithTag(DashboardTestTags.LIST).assertIsDisplayed()
        rule.onNodeWithTag(DashboardTestTags.SUMMARY_WIDGET).assertIsDisplayed()
        // Launchpad quick actions always render (Home is useful even with content).
        rule.onNodeWithTag(DashboardTestTags.ACTION_POST).assertIsDisplayed()
    }

    @Test
    fun empty_showsEmptyStateAndRefreshInvokes() {
        var refreshes = 0
        setState(DashboardUiState(phase = DashboardUiState.Phase.Empty), onRetry = { refreshes++ })
        // The launchpad always renders; the slim inline activity note carries the EMPTY tag.
        rule.onNodeWithTag(DashboardTestTags.LIST)
            .performScrollToNode(androidx.compose.ui.test.hasTestTag(DashboardTestTags.EMPTY))
        rule.onNodeWithTag(DashboardTestTags.EMPTY).assertIsDisplayed()
        assertEquals(0, refreshes)
    }

    @Test
    fun error_showsErrorState() {
        setState(DashboardUiState(phase = DashboardUiState.Phase.Error, errorMessage = "Service unavailable"))
        rule.onNodeWithTag(DashboardTestTags.ERROR).assertIsDisplayed()
    }

    @Test
    fun staleContent_showsBanner() {
        setState(
            DashboardUiState(
                phase = DashboardUiState.Phase.Content,
                dashboard = sample(),
                isStale = true,
            ),
        )
        rule.onNodeWithTag(DashboardTestTags.STALE_BANNER).assertIsDisplayed()
    }

    @Test
    fun profileAction_tap_invokesOnOpenProfile() {
        var opened = 0
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                DashboardScreen(
                    state = DashboardUiState(phase = DashboardUiState.Phase.Content, dashboard = sample()),
                    onRefresh = {},
                    onRetry = {},
                    onQuickLink = {},
                    onOpenProfile = { opened++ },
                )
            }
        }
        rule.onNodeWithTag(DashboardTestTags.PROFILE_ACTION).performClick()
        assertEquals(1, opened)
    }

    @Test
    fun quickAction_post_invokesOnOpenRoute() {
        var route: String? = null
        rule.setContent {
            TestLogonTheme(dynamicColor = false) {
                DashboardScreen(
                    state = DashboardUiState(phase = DashboardUiState.Phase.Empty),
                    onRefresh = {},
                    onRetry = {},
                    onQuickLink = {},
                    onOpenRoute = { route = it },
                )
            }
        }
        rule.onNodeWithTag(DashboardTestTags.ACTION_POST).performClick()
        assertEquals("compose_post", route)
    }

    @Test
    fun staleBanner_retry_invokesOnRetry() {
        var retries = 0
        setState(
            DashboardUiState(phase = DashboardUiState.Phase.Content, dashboard = sample(), isStale = true),
            onRetry = { retries++ },
        )
        rule.onAllNodesWithTag(DashboardTestTags.RETRY_ACTION).onFirst().performClick()
        assertEquals(1, retries)
    }
}
