package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.discounts.AffiliateDiscountsRoute

/** AND-267 — the affiliate-discounts list route (reached from the More hub / affiliates area). */
data object DiscountsDest {
    const val ROUTE = "discounts"
}

/** AND-267 — registers the affiliate-discounts destination in the authenticated graph. */
fun NavGraphBuilder.discountsDestination(navController: NavHostController) {
    composable(DiscountsDest.ROUTE) {
        AffiliateDiscountsRoute(onBack = { navController.popBackStack() })
    }
}
