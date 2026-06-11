package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.affiliates.AffiliatesRoute

/** AND-265 — the affiliates dashboard route (reached from the More hub / earnings). */
data object AffiliatesDest {
    const val ROUTE = "affiliates"
}

/** AND-265 — registers the affiliates destination in the authenticated graph. */
fun NavGraphBuilder.affiliatesDestination(navController: NavHostController) {
    composable(AffiliatesDest.ROUTE) {
        AffiliatesRoute(onBack = { navController.popBackStack() })
    }
}
