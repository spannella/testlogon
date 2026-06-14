package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.taxdocs.TaxDocsRoute

/** AND-246 — the tax-documents list route (reached from billing / the More hub). */
data object TaxDocsDest {
    const val ROUTE = "billing/tax-documents"
}

/** AND-246 — registers the tax-documents list destination. PDFs open in a Custom Tab via the launcher. */
fun NavGraphBuilder.taxDocsDestination(navController: NavHostController) {
    composable(TaxDocsDest.ROUTE) {
        TaxDocsRoute(onBack = { navController.popBackStack() })
    }
}
