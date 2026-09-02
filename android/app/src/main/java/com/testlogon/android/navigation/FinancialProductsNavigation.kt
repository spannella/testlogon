package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.financialproducts.FinancialProductsRoute

/**
 * CUS-004 Financial Products + Collections admin hub (router app/routers/financial_products.py, prefix
 * `/ui/financial-products`, all `require_admin_or_root`). Mirrors the web
 * `frontend/src/api/endpoints/bankCustomers.ts` (CUS-004 section): products list/create + collections
 * list/create.
 *
 * operator-only in the More catalog; self-gates via the client [AdminRoleProvider] pre-check + the
 * backend 403 -> Forbidden state. The whole router 404s unless the OBP + financial-products flags are on,
 * so reads degrade to empty; mutations surface a "not enabled" error.
 */
data object FinancialProductsDest {
    const val ROUTE = "admin/financial-products"
}

fun NavGraphBuilder.financialProductsDestinations(navController: NavHostController) {
    composable(FinancialProductsDest.ROUTE) {
        FinancialProductsRoute(
            onBack = { navController.popBackStack() },
            onSessionExpired = { navController.popBackStack() },
        )
    }
}
