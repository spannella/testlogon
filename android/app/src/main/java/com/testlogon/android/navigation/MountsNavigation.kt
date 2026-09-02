package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.files.mounts.MountsRoute

/**
 * FM-MOUNTS — the file-manager storage-mount management route (list / add / edit / test / remove S3
 * mounts). Reached from the file-manager entry point. This route lives in the files feature graph (NOT
 * the More catalog), so it does not touch MoreCatalog / RouteRegistry (mirrors the FE-170 TradingDocs
 * pattern). Degrades to an "unavailable" state when the backend surface is not enabled (404/403).
 */
data object MountsDest {
    const val ROUTE = "files/mounts"
}

/** FM-MOUNTS — registers the storage-mount management destination. */
fun NavGraphBuilder.mountsDestination(navController: NavHostController) {
    composable(MountsDest.ROUTE) {
        MountsRoute(onBack = { navController.popBackStack() })
    }
}
