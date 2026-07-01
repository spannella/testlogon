package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.marketing.MarketingCalendarRoute
import com.testlogon.android.feature.marketing.MarketingDashboardRoute
import com.testlogon.android.feature.marketing.MarketingEditorRoute
import com.testlogon.android.feature.marketing.MarketingEngagementRoute

/**
 * B4 web-parity — Marketing content agent routes (web /agents/marketing, /content/:contentId,
 * /calendar, /engagement). All backend `require_ui_session` (usable by the test user). Dashboard is the
 * hub entry; it links to calendar, engagement, and per-item editor.
 */
data object MarketingDashboardDest {
    const val ROUTE = "marketing"
}

data object MarketingEditorDest {
    const val ARG_CONTENT_ID = "contentId"
    const val ROUTE_BASE = "marketing/content"
    const val ROUTE = "$ROUTE_BASE/{$ARG_CONTENT_ID}"

    fun route(contentId: String): String = "$ROUTE_BASE/$contentId"
}

data object MarketingCalendarDest {
    const val ROUTE = "marketing/calendar"
}

data object MarketingEngagementDest {
    const val ROUTE = "marketing/engagement"
}

fun NavGraphBuilder.marketingDestinations(navController: NavHostController) {
    composable(MarketingDashboardDest.ROUTE) {
        MarketingDashboardRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            onOpenContent = { id -> navController.navigate(MarketingEditorDest.route(id)) },
            onOpenCalendar = { navController.navigate(MarketingCalendarDest.ROUTE) },
            onOpenEngagement = { navController.navigate(MarketingEngagementDest.ROUTE) },
        )
    }
    composable(
        route = MarketingEditorDest.ROUTE,
        arguments = listOf(navArgument(MarketingEditorDest.ARG_CONTENT_ID) { type = NavType.StringType }),
    ) {
        MarketingEditorRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
    composable(MarketingCalendarDest.ROUTE) {
        MarketingCalendarRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            onOpenContent = { id -> navController.navigate(MarketingEditorDest.route(id)) },
        )
    }
    composable(MarketingEngagementDest.ROUTE) {
        MarketingEngagementRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            onOpenContent = { id -> navController.navigate(MarketingEditorDest.route(id)) },
        )
    }
}
