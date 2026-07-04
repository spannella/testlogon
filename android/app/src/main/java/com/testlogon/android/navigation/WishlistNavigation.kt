package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.wishlist.WishlistRoute

/** ECOM — the user's saved catalog items (wishlist / favourites), reached from the SHOP hub. */
data object WishlistDest {
    const val ROUTE = "wishlist"
}

/**
 * ECOM — registers the Wishlist destination. Rows tap through to the product-detail route (keyed on the
 * saved category_id + item_id, exactly like the catalog grid).
 */
fun NavGraphBuilder.wishlistDestination(navController: NavHostController) {
    composable(WishlistDest.ROUTE) {
        WishlistRoute(
            onOpenItem = { categoryId, itemId ->
                navController.navigate(ProductDetailDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}
