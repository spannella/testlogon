package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.files.shared.SharedWithMeRoute
import com.testlogon.android.feature.files.usage.StorageUsageRoute

/**
 * FM-SHARE - the file-manager storage-usage + "shared with me" routes. Reached from the file-manager
 * top bar. These live in the files feature graph (NOT the More catalog), mirroring the FM-MOUNTS /
 * FE-170 TradingDocs pattern, so they do not touch MoreCatalog / RouteRegistry. Both surfaces
 * degrade-on-404/403 to an "unavailable" state.
 */
data object StorageUsageDest {
    const val ROUTE = "files/usage"
}

data object SharedWithMeDest {
    const val ROUTE = "files/shared-with-me"
}

/** FM-SHARE - registers the storage-usage destination. */
fun NavGraphBuilder.storageUsageDestination(navController: NavHostController) {
    composable(StorageUsageDest.ROUTE) {
        StorageUsageRoute(onBack = { navController.popBackStack() })
    }
}

/** FM-SHARE - registers the "shared with me" destination. Opening a shared item is a safe no-op for now. */
fun NavGraphBuilder.sharedWithMeDestination(navController: NavHostController) {
    composable(SharedWithMeDest.ROUTE) {
        SharedWithMeRoute(
            onBack = { navController.popBackStack() },
            // Open/preview of a shared node is deferred (mirrors FilesRoute.onOpenFile); safe no-op.
            onOpenShared = { _, _ -> },
        )
    }
}
