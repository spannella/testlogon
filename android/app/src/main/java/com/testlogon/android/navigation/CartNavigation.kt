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
import com.testlogon.android.feature.checkout.address.AddressShippingRoute
import com.testlogon.android.feature.purchases.OrderDetailRoute
import com.testlogon.android.feature.tracking.TrackingViewModel

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

/**
 * AND-214 — the address step (saved-address list / add / select / set-primary). Shipping option/quote is
 * absent — no backend support. Reached from the order-review flow as the address-selection sub-screen.
 */
data object AddressShippingDest {
    const val ROUTE = "shop/address"
}

fun NavGraphBuilder.addressShippingDestination(navController: NavHostController) {
    composable(AddressShippingDest.ROUTE) {
        AddressShippingRoute(
            // The payment step (AND-216 payment) is not wired; Applied returns to the prior screen.
            onContinueToPayment = { navController.popBackStack() },
            onBack = { navController.popBackStack() },
        )
    }
}

/**
 * AND-215 / AND-220 — order (transaction) detail for a txn id. The AND-215 standalone tracking host was
 * replaced (per AND-220) by the real [OrderDetailRoute], which EMBEDS the AND-215
 * [com.testlogon.android.feature.tracking.TrackingSection]. The route/arg are kept so existing callers
 * (e.g. the AND-215 deep link) reach the full detail; the value is a txn_id.
 */
data object TrackingDest {
    const val ARG_TXN_ID = TrackingViewModel.ARG_TXN_ID
    const val ROUTE = "shop/tracking/{$ARG_TXN_ID}"

    fun build(txnId: String): String = "shop/tracking/${Uri.encode(txnId)}"
}

fun NavGraphBuilder.trackingDestination(navController: NavHostController) {
    composable(
        route = TrackingDest.ROUTE,
        arguments = listOf(navArgument(TrackingDest.ARG_TXN_ID) { type = NavType.StringType }),
    ) {
        OrderDetailRoute(onBack = { navController.popBackStack() })
    }
}
