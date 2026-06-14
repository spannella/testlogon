package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.catalog.CatalogRoute
import com.testlogon.android.feature.catalog.CatalogSearchRoute
import com.testlogon.android.feature.catalog.ProductDetailRoute

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

/** AND-207 — catalog full-text search route. */
data object CatalogSearchDest {
    const val ROUTE = "catalog/search"
}

/** AND-205 / AND-207 — registers the catalog browse grid; its cells open [ProductDetailDest]. */
fun NavGraphBuilder.catalogDestination(navController: NavHostController) {
    composable(CatalogDest.ROUTE) {
        CatalogRoute(
            onItemClick = { categoryId, itemId ->
                navController.navigate(ProductDetailDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
            onSearch = { navController.navigate(CatalogSearchDest.ROUTE) { launchSingleTop = true } },
            onCart = { navController.navigate(CartDest.ROUTE) { launchSingleTop = true } },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-207 — registers the catalog search destination; rows open [ProductDetailDest] with both ids
 * (web detail nav is keyed on category_id + item_id).
 */
fun NavGraphBuilder.catalogSearchDestination(navController: NavHostController) {
    composable(CatalogSearchDest.ROUTE) {
        CatalogSearchRoute(
            onItemClick = { categoryId, itemId ->
                navController.navigate(ProductDetailDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-206 — registers the real product-detail destination. The item is derived from the category-items
 * list (there is no single-item GET); categoryId/itemId arrive as nav args via SavedStateHandle.
 */
fun NavGraphBuilder.productDetailDestination(navController: NavHostController) {
    composable(
        route = ProductDetailDest.ROUTE,
        arguments = listOf(
            navArgument(ProductDetailDest.ARG_CATEGORY_ID) { type = NavType.StringType },
            navArgument(ProductDetailDest.ARG_ITEM_ID) { type = NavType.StringType },
        ),
    ) {
        ProductDetailRoute(onBack = { navController.popBackStack() })
    }
}
