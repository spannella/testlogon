package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.taxreport.TaxReportRoute

/**
 * The read-only Tax Lots & Realized-Gains surface, reached from the More -> Wallet hub (near Reports).
 * Picks a cost-basis method (FIFO / LIFO / Average) + a year, assembles the account's fills from the
 * live exchange feed, runs the pure tax-lot engine client-side, and shows realized gains (per lot +
 * short/long split + totals), a by-symbol summary, open lots vs mark (unrealized), and a Share/Copy CSV
 * action. No money movement.
 */
data object TaxReportDest {
    const val ROUTE = "tax_report"
}

/** Registers the Tax Lots screen in the authenticated graph. Up / Back pops the back stack. */
fun NavGraphBuilder.taxReportDestination(navController: NavHostController) {
    composable(TaxReportDest.ROUTE) {
        TaxReportRoute(
            onBack = { navController.popBackStack() },
        )
    }
}
