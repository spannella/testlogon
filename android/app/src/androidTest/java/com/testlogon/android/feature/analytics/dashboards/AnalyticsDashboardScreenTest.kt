package com.testlogon.android.feature.analytics.dashboards

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.data.analytics.AnalyticsDashboard
import com.testlogon.android.data.analytics.AnalyticsOverview
import com.testlogon.android.data.analytics.AudienceRow
import com.testlogon.android.data.analytics.SubscribersPoint
import com.testlogon.android.data.analytics.TopContentRow
import com.testlogon.android.data.analytics.ViewsPoint
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-399 — Compose UI tests for the stateless [AnalyticsDashboardScreen]. Drives an in-test reducer
 * over the screen state (the range chip swaps the rendered range) so the KPI tiles, range chips,
 * charts, breakdown rows, stale banner, and the empty / error / loading surfaces are exercised without
 * Hilt. useUnmergedTree for nested controls.
 */
@RunWith(AndroidJUnit4::class)
class AnalyticsDashboardScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun dashboard() = AnalyticsDashboard(
        overview = AnalyticsOverview(
            periodViews = 184320L,
            periodRevenueCents = 942180L,
            periodNewSubscribers = 1372L,
            totalSubscribers = 51240L,
            currency = "USD",
        ),
        views = listOf(
            ViewsPoint("2026-05-09", 20580L, 6210L, 2110L, 318400L),
            ViewsPoint("2026-05-10", 20581L, 5980L, 2010L, 301100L),
        ),
        subscribers = listOf(
            SubscribersPoint("2026-05-09", 20580L, 120L, 30L, 90L, 50000L),
            SubscribersPoint("2026-05-10", 20581L, 110L, 20L, 90L, 50090L),
        ),
        topContent = listOf(
            TopContentRow("vid_77", "video", "Launch Recap", 41200L, 188200L, 0.0613),
        ),
        audienceCountries = listOf(AudienceRow("United States", 70110L, 38.0)),
        audienceDevices = listOf(AudienceRow("mobile", 51240L, 61.0)),
    )

    private fun content(state: AnalyticsDashboardUiState) {
        rule.setContent {
            TestLogonTheme {
                var s by remember { mutableStateOf(state) }
                AnalyticsDashboardScreen(
                    state = s,
                    onBack = {},
                    onRangeSelected = { option -> s = s.copy(range = option) },
                    onRefresh = {},
                    onRetry = { s = s.copy(phase = AnalyticsDashboardUiState.Phase.Content, dashboard = dashboard()) },
                )
            }
        }
    }

    @Test
    fun content_rendersTiles_charts_andBreakdownRows() {
        content(AnalyticsDashboardUiState(phase = AnalyticsDashboardUiState.Phase.Content, dashboard = dashboard()))
        rule.onNodeWithTag(AnalyticsDashboardTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.KPI_PREFIX + "views", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.KPI_PREFIX + "revenue", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.VIEWS_CHART, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.SUBS_CHART, useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.TOP_CONTENT_PREFIX + "0", useUnmergedTree = true).assertExists()
        rule.onNodeWithTag(
            AnalyticsDashboardTestTags.AUDIENCE_PREFIX + "country_0",
            useUnmergedTree = true,
        ).assertExists()
    }

    @Test
    fun loading_showsSkeletonSurface() {
        content(AnalyticsDashboardUiState(phase = AnalyticsDashboardUiState.Phase.Loading))
        rule.onNodeWithTag(AnalyticsDashboardTestTags.LOADING).assertIsDisplayed()
    }

    @Test
    fun empty_showsEmptyCopy() {
        content(AnalyticsDashboardUiState(phase = AnalyticsDashboardUiState.Phase.Empty, dashboard = null))
        rule.onNodeWithTag(AnalyticsDashboardTestTags.EMPTY, useUnmergedTree = true).assertExists()
    }

    @Test
    fun error_showsRetry_andRecovers() {
        content(
            AnalyticsDashboardUiState(
                phase = AnalyticsDashboardUiState.Phase.Error,
                dashboard = null,
                errorMessage = "boom",
            ),
        )
        rule.onNodeWithTag(AnalyticsDashboardTestTags.ERROR, useUnmergedTree = true).assertExists()
    }

    @Test
    fun stale_showsBanner() {
        content(
            AnalyticsDashboardUiState(
                phase = AnalyticsDashboardUiState.Phase.Content,
                dashboard = dashboard(),
                isStale = true,
            ),
        )
        rule.onNodeWithTag(AnalyticsDashboardTestTags.STALE_BANNER, useUnmergedTree = true).assertExists()
    }

    @Test
    fun rangeChip_selection_isClickable() {
        content(AnalyticsDashboardUiState(phase = AnalyticsDashboardUiState.Phase.Content, dashboard = dashboard()))
        rule.onNodeWithTag(AnalyticsDashboardTestTags.RANGE_PREFIX + "90", useUnmergedTree = true)
            .performClick()
        rule.onNodeWithTag(AnalyticsDashboardTestTags.RANGE_PREFIX + "90", useUnmergedTree = true)
            .assertExists()
    }
}
