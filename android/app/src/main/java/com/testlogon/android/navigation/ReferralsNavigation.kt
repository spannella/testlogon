package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.referrals.ReferralsRoute

/** AND-264 — the referrals dashboard route (reached from the More hub / earnings). */
data object ReferralsDest {
    const val ROUTE = "referrals"
}

/** AND-264 — registers the referrals destination in the authenticated graph. */
fun NavGraphBuilder.referralsDestination(navController: NavHostController) {
    composable(ReferralsDest.ROUTE) {
        ReferralsRoute(
            onBack = { navController.popBackStack() },
            // SessionExpired routing is owned by the app shell's auth-gated router; pop back toward it.
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
