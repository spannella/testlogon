package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.cart.CartRoute
import com.testlogon.android.feature.checkout.CheckoutSessionViewModel
import com.testlogon.android.feature.checkout.OrderReviewRoute

/** AND-211 — the shopping cart screen. */
data object CartDest {
    const val ROUTE = "shop/cart"
}

/**
 * AND-213 — the order-review / checkout-session screen, reached from the cart. Carries the cart id and
 * the cart's authoritative total + currency as nav args (the checkout response carries no totals).
 */
data object OrderReviewDest {
    const val ARG_CART_ID = CheckoutSessionViewModel.ARG_CART_ID
    const val ARG_TOTAL_CENTS = CheckoutSessionViewModel.ARG_TOTAL_CENTS
    const val ARG_CURRENCY = CheckoutSessionViewModel.ARG_CURRENCY
    const val ROUTE = "shop/checkout/{$ARG_CART_ID}/{$ARG_TOTAL_CENTS}/{$ARG_CURRENCY}"

    fun build(cartId: String, totalCents: Long, currency: String): String =
        "shop/checkout/${Uri.encode(cartId)}/$totalCents/${Uri.encode(currency)}"
}

/** AND-211 — registers the cart screen; checkout routes to [OrderReviewDest], browse to the catalog. */
fun NavGraphBuilder.cartDestination(navController: NavHostController) {
    composable(CartDest.ROUTE) {
        CartRoute(
            onCheckout = { cartId, totalCents, currency ->
                // The cart screen owns the authoritative total; pass it so order-review can display it.
                navController.navigate(
                    OrderReviewDest.build(cartId, totalCents, currency),
                ) { launchSingleTop = true }
            },
            onBrowseCatalog = {
                navController.navigate(CatalogDest.ROUTE) { launchSingleTop = true }
            },
            onBack = { navController.popBackStack() },
        )
    }
}

/** AND-213 — registers the order-review destination (cart id + total + currency nav args). */
fun NavGraphBuilder.orderReviewDestination(navController: NavHostController) {
    composable(
        route = OrderReviewDest.ROUTE,
        arguments = listOf(
            navArgument(OrderReviewDest.ARG_CART_ID) { type = NavType.StringType },
            navArgument(OrderReviewDest.ARG_TOTAL_CENTS) { type = NavType.LongType },
            navArgument(OrderReviewDest.ARG_CURRENCY) { type = NavType.StringType },
        ),
    ) {
        OrderReviewRoute(onBack = { navController.popBackStack() })
    }
}
