package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.invoices.InvoiceDetailRoute
import com.testlogon.android.feature.invoices.InvoiceDetailViewModel
import com.testlogon.android.feature.invoices.InvoiceListRoute

/** AND-243 — the invoices list route (reached from billing / the More hub). */
data object InvoicesListDest {
    const val ROUTE = "invoices"
}

/** AND-243 — the invoice detail route; the arg is the STRING invoice_number (the path param). */
data object InvoiceDetailDest {
    const val ARG_INVOICE_NUMBER = InvoiceDetailViewModel.ARG_INVOICE_NUMBER
    const val ROUTE = "invoices/{$ARG_INVOICE_NUMBER}"

    fun build(invoiceNumber: String): String = "invoices/${Uri.encode(invoiceNumber)}"
}

/** AND-243 — registers the invoices list + detail destinations in the authenticated graph. */
fun NavGraphBuilder.invoicesDestinations(navController: NavHostController) {
    composable(InvoicesListDest.ROUTE) {
        InvoiceListRoute(
            onInvoiceClick = { invoiceNumber ->
                navController.navigate(InvoiceDetailDest.build(invoiceNumber)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
    composable(
        route = InvoiceDetailDest.ROUTE,
        arguments = listOf(
            navArgument(InvoiceDetailDest.ARG_INVOICE_NUMBER) { type = NavType.StringType },
        ),
    ) {
        InvoiceDetailRoute(onBack = { navController.popBackStack() })
    }
}
