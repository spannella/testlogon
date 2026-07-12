package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.delegationkeys.ui.DelegationKeysRoute

/**
 * Delegation-API keys destination (web parity: /delegation-api). A single screen with two tabs (My Keys /
 * Keys For My Account) + a create dialog (creator selector + permission subset + one-time secret). These are
 * the DELEGATED-access keys (a tool acting on a creator's behalf) - DISTINCT from the personal developer
 * keys under apiKeysDestinations (/ui/api_keys).
 */
data object DelegationKeysDest {
    const val ROUTE = "delegation_keys"
}

/** Registers the delegation-API keys destination in the authenticated graph. */
fun NavGraphBuilder.delegationKeysDestinations(navController: NavHostController) {
    composable(route = DelegationKeysDest.ROUTE) {
        DelegationKeysRoute(onBack = { navController.popBackStack() })
    }
}
