package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.files.ui.FilesRoute

/** AND-332 - the read-only file-manager browse surface (path-based folder navigation + search + sort). */
data object FilesDest {
    const val ROUTE = "files"
}

/**
 * AND-332 - registers the file-manager browse screen in the authenticated graph. Up / back at the root
 * pops the back stack. Opening a file currently routes to a no-op handoff: the file preview / open
 * surface is a later ticket (AND-333+), so [FilesRoute.onOpenFile] carries the path but lands nowhere
 * harmful for now.
 */
fun NavGraphBuilder.filesDestination(navController: NavHostController) {
    composable(FilesDest.ROUTE) {
        FilesRoute(
            onBack = { navController.popBackStack() },
            // Preview / open is AND-333+; keep the path-carrying callback wired but a safe no-op.
            onOpenFile = { },
            // AND-335 - the share affordance opens the owner ShareSheet keyed by the file path.
            onShareFile = { path ->
                navController.navigate(ShareSheetDest.build(path)) { launchSingleTop = true }
            },
            // AND-336 - the import-from-Drive affordance opens the backend-mediated picker, carrying the
            // folder on screen as the import target.
            onImportFromDrive = { targetFolderPath ->
                navController.navigate(DriveImportDest.build(targetFolderPath)) { launchSingleTop = true }
            },
        )
    }
}
