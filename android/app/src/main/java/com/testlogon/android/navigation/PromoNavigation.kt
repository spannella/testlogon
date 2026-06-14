package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.promo.PromoCodesRoute

/** AND-266 — the promo-codes list + create route (reached from the More hub / earnings). */
data object PromoDest {
    const val ROUTE = "promo"
}

/** AND-266 — registers the promo-codes destination in the authenticated graph. */
fun NavGraphBuilder.promoDestination(navController: NavHostController) {
    composable(PromoDest.ROUTE) {
        PromoCodesRoute(onBack = { navController.popBackStack() })
    }
}
