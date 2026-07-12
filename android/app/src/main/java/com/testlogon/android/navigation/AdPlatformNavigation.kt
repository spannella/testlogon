package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.adplatform.AdPlatformRoute

/**
 * Web-parity admin AD-PLATFORM console, registered in the AUTHENTICATED graph. Reads + moderate actions
 * are ADMIN-gated (require_admin_or_root); the kill-switch toggle is ROOT-only (surfaced read-only). The
 * ViewModel maps a backend 403 on load to the Forbidden state. Mirrors the web /admin/ad-platform page.
 */
data object AdPlatformDest {
    const val ROUTE = "admin/ad-platform"
}

fun NavGraphBuilder.adPlatformDestination(navController: NavHostController) {
    composable(AdPlatformDest.ROUTE) {
        AdPlatformRoute(onBack = { navController.popBackStack() })
    }
}
