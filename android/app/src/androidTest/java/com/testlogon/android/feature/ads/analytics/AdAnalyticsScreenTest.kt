package com.testlogon.android.feature.ads.analytics

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.hasTestTag
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollToNode
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.testlogon.android.core.model.ads.AdAnalyticsSummary
import com.testlogon.android.core.model.ads.AdBreakdownEntry
import com.testlogon.android.core.model.ads.AdTimeSeriesPoint
import com.testlogon.android.core.model.ads.DateRangePreset
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsScreen
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsTestTags
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsUiState
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AND-368 - Compose UI tests for the stateless [AdAnalyticsScreen]. Drives an in-test reducer over the screen
 * state (the range chip swaps the rendered preset) so the KPI tiles, range chips, charts, breakdown rows, and
 * the empty state are exercised without Hilt. useUnmergedTree for nested controls; assertDoesNotExist is used
 * as a MEMBER (a chain call, not an import).
 */
@RunWith(AndroidJUnit4::class)
class AdAnalyticsScreenTest {

    @get:Rule
    val rule = createComposeRule()

    private fun content(range: DateRangePreset = DateRangePreset.LAST_28) = AdAnalyticsUiState.Content(
        summary = AdAnalyticsSummary(
            impressions = 120000L,
            clicks = 3400L,
            spendCents = 250000L,
            ctrPct = 2.83,
            cpaCents = 7350L,
            effectiveCpmCents = 2083L,
            completionRatePct = 88.2,
            impressionsChangePct = 4.5,
        ),
        timeseries = listOf(
            AdTimeSeriesPoint(date = "2026-06-08", impressions = 1000L, clicks = 30L, spendCents = 2500L),
            AdTimeSeriesPoint(date = "2026-06-09", impressions = 1200L, clicks = 36L, spendCents = 3000L),
        ),
        breakdown = listOf(
            AdBreakdownEntry(key = "cmp_1", campaignName = "Spring", impressions = 80000L, clicks = 2400L, spendCents = 180000L, ctrPct = 3.0),
            AdBreakdownEntry(key = "cmp_2", impressions = 40000L, clicks = 1000L, spendCents = 70000L),
        ),
        range = range,
    )

    private fun launch(initial: AdAnalyticsUiState = content()) {
        rule.setContent {
            TestLogonTheme {
                var state by remember { mutableStateOf(initial) }
                AdAnalyticsScreen(
                    state = state,
                    onBack = {},
                    onRangeChanged = { preset ->
                        // In-test reducer: swap the rendered preset (mirrors the VM re-query selecting a range).
                        state = when (val s = state) {
                            is AdAnalyticsUiState.Content -> s.copy(range = preset)
                            is AdAnalyticsUiState.Empty -> s.copy(range = preset)
                            is AdAnalyticsUiState.Error -> s.copy(range = preset)
                            AdAnalyticsUiState.Loading -> s
                        }
                    },
                    onRefresh = {},
                    onRetry = {},
                )
            }
        }
    }

    @Test
    fun content_rendersKpiTiles_charts_andBreakdownRows() {
        launch()
        rule.onNodeWithTag(AdAnalyticsTestTags.SCREEN).assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.kpi("impressions"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.kpi("spend"), useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.kpi("ctr"), useUnmergedTree = true).assertIsDisplayed()
        // Charts + breakdown rows live further down the LazyColumn; off-screen lazy items are NOT composed,
        // so scroll the list to each before asserting it exists/is displayed (performScrollToNode for lazy).
        rule.onNodeWithTag(AdAnalyticsTestTags.LIST)
            .performScrollToNode(hasTestTag(AdAnalyticsTestTags.CHART_SPEND))
        rule.onNodeWithTag(AdAnalyticsTestTags.CHART_SPEND, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.LIST)
            .performScrollToNode(hasTestTag(AdAnalyticsTestTags.breakdownRow(0)))
        rule.onNodeWithTag(AdAnalyticsTestTags.breakdownRow(0), useUnmergedTree = true).assertIsDisplayed()
    }

    @Test
    fun rangeChips_areShown_andSelectable() {
        launch()
        rule.onNodeWithTag(AdAnalyticsTestTags.rangeChip(DateRangePreset.LAST_7), useUnmergedTree = true)
            .assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.rangeChip(DateRangePreset.LAST_90), useUnmergedTree = true)
            .assertIsDisplayed()
        // Selecting the 7-day chip keeps the screen rendered (reducer swaps the preset).
        rule.onNodeWithTag(AdAnalyticsTestTags.rangeChip(DateRangePreset.LAST_7), useUnmergedTree = true)
            .performClick()
        rule.onNodeWithTag(AdAnalyticsTestTags.SCREEN).assertIsDisplayed()
    }

    @Test
    fun empty_showsEmptyState_andNoKpiTiles() {
        launch(AdAnalyticsUiState.Empty(range = DateRangePreset.LAST_28))
        rule.onNodeWithTag(AdAnalyticsTestTags.EMPTY, useUnmergedTree = true).assertIsDisplayed()
        rule.onNodeWithTag(AdAnalyticsTestTags.kpi("impressions"), useUnmergedTree = true).assertDoesNotExist()
    }
}
