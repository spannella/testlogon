package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.syndicates.bundles.MyBundlesRoute

/**
 * My Bundles destination (web parity: /syndicates/my-bundles) - the caller's active syndicate bundle
 * subscriptions with a per-bundle cancel (access continues until period end).
 */
data object MyBundlesDest {
    const val ROUTE = "syndicates/my-bundles"
}

/** Registers the My Bundles destination in the authenticated graph. */
fun NavGraphBuilder.myBundlesDestinations(navController: NavHostController) {
    composable(route = MyBundlesDest.ROUTE) {
        MyBundlesRoute(onBack = { navController.popBackStack() })
    }
}
