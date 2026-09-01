package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.marketingcampaigns.MarketingCampaignsRoute

/**
 * OFBiz Marketing CAMPAIGNS hub (web MKT: /ui/marketing campaigns + lists + segments, router
 * app/routers/marketing_campaigns.py). require_ui_session (usable by the test user). Reads degrade to
 * empty when the MARKETING_CAMPAIGNS_ENABLED flag is off; mutations surface a "not enabled" error.
 *
 * DISTINCT from [MarketingDashboardDest] (the /ui/agents/marketing content agent).
 */
data object MarketingCampaignsDest {
    const val ROUTE = "marketing/campaigns"
}

fun NavGraphBuilder.marketingCampaignsDestinations(navController: NavHostController) {
    composable(MarketingCampaignsDest.ROUTE) {
        MarketingCampaignsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
