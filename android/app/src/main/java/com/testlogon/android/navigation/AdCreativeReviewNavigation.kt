package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adcreativereview.AdCreativeReviewRoute

/**
 * Web-parity admin AD CREATIVE-REVIEW queue, registered in the AUTHENTICATED graph. ADMIN-gated
 * (require_admin_or_root) - the ViewModel maps a backend 403 to the Forbidden state. Mirrors the web
 * /admin/ads/creatives/review page.
 */
data object AdCreativeReviewDest {
    const val ROUTE = "admin/ads/creatives/review"
}

fun NavGraphBuilder.adCreativeReviewDestination(navController: NavHostController) {
    composable(AdCreativeReviewDest.ROUTE) {
        AdCreativeReviewRoute(onBack = { navController.popBackStack() })
    }
}
