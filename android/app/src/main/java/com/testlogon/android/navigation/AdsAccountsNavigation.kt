package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.ads.accounts.ui.AdsAccountsRoute

/**
 * ADV3-4 (B4) - the advertiser-accounts LIST destination (`ads-accounts`). No nav arg (the list is
 * caller-scoped). This is the "Advertise" hub landing surface (ADV3-5 / B5): it removes the single-account
 * ceiling by routing billing / campaigns / analytics with a REAL accountId picked from the list, and offers
 * "create ad account" as the entry into the create wizard.
 */
data object AdsAccountsDest {
    const val ROUTE = "ads-accounts"
}

/** ADV3-4 - navigates to the advertiser-accounts list. */
fun NavHostController.navigateToAdsAccounts() {
    navigate(AdsAccountsDest.ROUTE) { launchSingleTop = true }
}

/** ADV3-4 - registers the advertiser-accounts list destination + its downstream routing. */
fun NavGraphBuilder.adsAccountsDestination(navController: NavHostController) {
    composable(route = AdsAccountsDest.ROUTE) {
        AdsAccountsRoute(
            onBack = { navController.popBackStack() },
            onOpenCampaigns = { accountId -> navController.navigateToAdsCampaigns(accountId) },
            onOpenBilling = { accountId -> navController.navigateToAdsBilling(accountId) },
            onOpenAnalytics = { accountId -> navController.navigateToAdAnalytics(accountId) },
            onCreateAccount = { navController.navigateToCreateAdAccount() },
        )
    }
}
