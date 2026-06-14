package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsRoute
import com.testlogon.android.feature.ads.analytics.ui.AdAnalyticsViewModel

/**
 * AND-368 - the READ-ONLY ad-analytics destination (`ad-analytics/{accountId}`). The VM reads {accountId}
 * from SavedStateHandle (the nav arg).
 *
 * STUB ENTRY: there is no ads-accounts discovery list in scope this wave, so the More-hub links to a known
 * sample account id ([SAMPLE_ACCOUNT_ID]) for manual testing - downstream this destination is reached from an
 * ads-accounts list. The plain (un-encoded) [STUB_ROUTE] is what the hub registers (mirrors AND-367's
 * AdsBillingDest stub entry).
 */
data object AdAnalyticsDest {
    const val ARG_ACCOUNT_ID = "accountId"
    const val ROUTE = "ad-analytics/{$ARG_ACCOUNT_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_ACCOUNT_ID = "acc_sample"

    /** Builds the concrete route for [accountId]. */
    fun build(accountId: String): String = "ad-analytics/${Uri.encode(accountId)}"

    /** The plain stub route the More-hub registers - the sample id needs no encoding. */
    const val STUB_ROUTE = "ad-analytics/$SAMPLE_ACCOUNT_ID"
}

/** AND-368 - navigates to the ad-analytics screen for [accountId] (the entry-point seam). */
fun NavHostController.navigateToAdAnalytics(accountId: String) {
    navigate(AdAnalyticsDest.build(accountId)) { launchSingleTop = true }
}

/** AND-368 - registers the `ad-analytics/{accountId}` destination. */
fun NavGraphBuilder.adAnalyticsDestination(navController: NavHostController) {
    composable(
        route = AdAnalyticsDest.ROUTE,
        arguments = listOf(
            navArgument(AdAnalyticsViewModel.ARG_ACCOUNT_ID) { type = NavType.StringType },
        ),
    ) {
        AdAnalyticsRoute(onBack = { navController.popBackStack() })
    }
}
