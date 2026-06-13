package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.adsbilling.ui.AdsBillingRoute
import com.testlogon.android.feature.adsbilling.ui.AdsBillingViewModel

/**
 * AND-367 - the ads-account BILLING + DEPOSIT destination (`ads-billing/{accountId}`). The VM reads
 * {accountId} from SavedStateHandle (the nav arg).
 *
 * STUB ENTRY: there is no ads-accounts discovery list in scope this wave, so the More-hub links to a known
 * sample account id ([SAMPLE_ACCOUNT_ID]) purely for manual testing - downstream this destination is reached
 * from an ads-accounts list. The plain (un-encoded) [STUB_ROUTE] is what the hub registers.
 */
data object AdsBillingDest {
    const val ARG_ACCOUNT_ID = "accountId"
    const val ROUTE = "ads-billing/{$ARG_ACCOUNT_ID}"

    /** A known sample id the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_ACCOUNT_ID = "acc_sample"

    /** Builds the concrete route for [accountId]. */
    fun build(accountId: String): String = "ads-billing/${Uri.encode(accountId)}"

    /** The plain stub route the More-hub registers - the sample id needs no encoding. */
    const val STUB_ROUTE = "ads-billing/$SAMPLE_ACCOUNT_ID"
}

/** AND-367 - navigates to the ads-billing screen for [accountId] (the entry-point seam). */
fun NavHostController.navigateToAdsBilling(accountId: String) {
    navigate(AdsBillingDest.build(accountId)) { launchSingleTop = true }
}

/** AND-367 - registers the `ads-billing/{accountId}` destination. */
fun NavGraphBuilder.adsBillingDestination(navController: NavHostController) {
    composable(
        route = AdsBillingDest.ROUTE,
        arguments = listOf(
            navArgument(AdsBillingViewModel.ARG_ACCOUNT_ID) { type = NavType.StringType },
        ),
    ) {
        AdsBillingRoute(onBack = { navController.popBackStack() })
    }
}
