package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.catalog.CatalogRoute
import com.testlogon.android.feature.catalog.ProductDetailPlaceholderRoute

/** AND-205 — the storefront catalog / category browse grid. */
data object CatalogDest {
    const val ROUTE = "catalog"
}

/**
 * AND-205 — product detail route `shop/{categoryId}/{itemId}` (web parity). AND-205 defines the
 * nav-arg contract and registers a minimal placeholder so item taps are never a dead end; AND-206 owns
 * the real product-detail screen (derived from the category-items list — there is no single-item GET).
 */
data object ProductDetailDest {
    const val ARG_CATEGORY_ID = "categoryId"
    const val ARG_ITEM_ID = "itemId"
    const val ROUTE = "shop/{$ARG_CATEGORY_ID}/{$ARG_ITEM_ID}"

    fun build(categoryId: String, itemId: String): String =
        "shop/${Uri.encode(categoryId)}/${Uri.encode(itemId)}"
}

/** AND-205 — registers the catalog browse grid; its cells open [ProductDetailDest]. */
fun NavGraphBuilder.catalogDestination(navController: NavHostController) {
    composable(CatalogDest.ROUTE) {
        CatalogRoute(
            onItemClick = { categoryId, itemId ->
                navController.navigate(ProductDetailDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-205 — registers a placeholder product-detail destination so the browse -> detail nav contract is
 * exercised end to end. AND-206 replaces [ProductDetailPlaceholderRoute] with the real screen.
 */
fun NavGraphBuilder.productDetailDestination(navController: NavHostController) {
    composable(
        route = ProductDetailDest.ROUTE,
        arguments = listOf(
            navArgument(ProductDetailDest.ARG_CATEGORY_ID) { type = NavType.StringType },
            navArgument(ProductDetailDest.ARG_ITEM_ID) { type = NavType.StringType },
        ),
    ) {
        ProductDetailPlaceholderRoute(onBack = { navController.popBackStack() })
    }
}
