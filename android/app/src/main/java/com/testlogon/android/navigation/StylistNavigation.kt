package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.stylist.StylistOverviewRoute
import com.testlogon.android.feature.stylist.StylistReviewRoute
import com.testlogon.android.feature.stylist.StylistRulesRoute

/**
 * B4 web-parity — Stylist / UI-design agent routes (web /agents/stylist, /agents/stylist/rules,
 * /agents/stylist/reviews/:reviewId). All backend `require_ui_session` (usable by the test user).
 * Overview is the hub entry; it links to Rules; a review-detail route is keyed by {reviewId}.
 */
data object StylistOverviewDest {
    const val ROUTE = "stylist"
}

data object StylistRulesDest {
    const val ROUTE = "stylist/rules"
}

data object StylistReviewDest {
    const val ARG_REVIEW_ID = "reviewId"
    const val ROUTE_BASE = "stylist/reviews"
    const val ROUTE = "$ROUTE_BASE/{$ARG_REVIEW_ID}"

    fun route(reviewId: String): String = "$ROUTE_BASE/$reviewId"
}

fun NavGraphBuilder.stylistDestinations(navController: NavHostController) {
    composable(StylistOverviewDest.ROUTE) {
        StylistOverviewRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
            onOpenRules = { navController.navigate(StylistRulesDest.ROUTE) },
        )
    }
    composable(StylistRulesDest.ROUTE) {
        StylistRulesRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
    composable(
        route = StylistReviewDest.ROUTE,
        arguments = listOf(navArgument(StylistReviewDest.ARG_REVIEW_ID) { type = NavType.StringType }),
    ) {
        StylistReviewRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
