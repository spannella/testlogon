package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.taxforms.Form1099ListRoute

/** AND-247 — the 1099-NEC tax-forms list route (reached from the More hub / tax area). */
data object Form1099Dest {
    const val ROUTE = "billing/tax-forms/1099"
}

/** AND-247 — registers the 1099 forms list destination. PDFs open in a Custom Tab via the launcher. */
fun NavGraphBuilder.form1099Destination(navController: NavHostController) {
    composable(Form1099Dest.ROUTE) {
        Form1099ListRoute(onBack = { navController.popBackStack() })
    }
}
