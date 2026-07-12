package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.sellerstore.ListingEditorRoute
import com.testlogon.android.feature.sellerstore.SellerOrdersRoute
import com.testlogon.android.feature.sellerstore.SellerSalesRoute
import com.testlogon.android.feature.sellerstore.SellerStoreRoute

/** ECOM (seller store) — "My store / Manage listings" (SHOP hub, creator/operator-gated). */
data object SellerStoreDest {
    const val ROUTE = "seller/store"
}

/** ECOM (seller store) — orders-received (SHOP hub, creator/operator-gated). */
data object SellerOrdersDest {
    const val ROUTE = "seller/orders"
}

/**
 * ECOM-SELLER — the seller own "Sales / Orders received" (SHOP hub, NON-admin). Reachable for ANY
 * seller. The shop_item_sold alert deep-links here with a sale query arg to auto-open the sale detail.
 */
data object SellerSalesDest {
    const val ARG_SALE = "sale"
    const val BASE = "seller/sales"
    const val ROUTE = "seller/sales?sale={$ARG_SALE}"

    fun build(shipGroupId: String? = null): String =
        if (shipGroupId.isNullOrBlank()) BASE else BASE + "?sale=" + android.net.Uri.encode(shipGroupId)
}

/**
 * ECOM (seller store) — create/edit a listing. `itemId == NEW` (`_new`) creates; any other id edits the
 * existing item. Reached only from the store screen, so it is not a top-level More entry.
 */
data object ListingEditorDest {
    const val ARG_CATEGORY_ID = "categoryId"
    const val ARG_ITEM_ID = "itemId"
    const val NEW = "_new"
    const val ROUTE = "seller/store/{$ARG_CATEGORY_ID}/listing/{$ARG_ITEM_ID}"

    fun build(categoryId: String, itemId: String? = null): String =
        "seller/store/${Uri.encode(categoryId)}/listing/${Uri.encode(itemId ?: NEW)}"
}

/** Registers "My store": item rows open the listing editor; the add-item FAB opens it in create mode. */
fun NavGraphBuilder.sellerStoreDestination(navController: NavHostController) {
    composable(SellerStoreDest.ROUTE) {
        SellerStoreRoute(
            onEditItem = { categoryId, itemId ->
                navController.navigate(ListingEditorDest.build(categoryId, itemId)) { launchSingleTop = true }
            },
            onCreateItem = { categoryId ->
                navController.navigate(ListingEditorDest.build(categoryId, null)) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/** Registers the listing create/edit editor (nav args via SavedStateHandle). */
fun NavGraphBuilder.listingEditorDestination(navController: NavHostController) {
    composable(
        route = ListingEditorDest.ROUTE,
        arguments = listOf(
            navArgument(ListingEditorDest.ARG_CATEGORY_ID) { type = NavType.StringType },
            navArgument(ListingEditorDest.ARG_ITEM_ID) { type = NavType.StringType },
        ),
    ) {
        ListingEditorRoute(
            onDone = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
}

/** Registers orders-received. */
fun NavGraphBuilder.sellerOrdersDestination(navController: NavHostController) {
    composable(SellerOrdersDest.ROUTE) {
        SellerOrdersRoute(onBack = { navController.popBackStack() })
    }
}

/** Registers the seller-scoped "My sales" screen (non-admin); optional sale deep-link arg. */
fun NavGraphBuilder.sellerSalesDestination(navController: NavHostController) {
    composable(
        route = SellerSalesDest.ROUTE,
        arguments = listOf(
            navArgument(SellerSalesDest.ARG_SALE) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) { entry ->
        SellerSalesRoute(
            onBack = { navController.popBackStack() },
            initialSaleId = entry.arguments?.getString(SellerSalesDest.ARG_SALE),
        )
    }
}
