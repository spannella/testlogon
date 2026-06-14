package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.files.drive.DrivePickerRoute
import com.testlogon.android.feature.files.drive.DrivePickerViewModel

/**
 * AND-336 - the BACKEND-MEDIATED Google Drive import picker (authenticated-only).
 *
 * The optional TestLogon target folder the import lands in is carried as a single encoded path segment
 * named exactly [DrivePickerViewModel.KEY_TARGET] so the VM reads it straight from its SavedStateHandle.
 * An empty segment means "no specific target" (the backend uses its default / root). The auth_url is
 * opened externally via the plain ACTION_VIEW idiom and the picker re-checks status on return - there is
 * NO deep-link / manifest change (the backend completes OAuth server-side).
 */
data object DriveImportDest {
    const val ARG_TARGET = DrivePickerViewModel.KEY_TARGET
    const val ROUTE = "drive/import/{$ARG_TARGET}"

    /** Builds the route for an optional [targetFolderPath] (null / blank -> a placeholder empty segment). */
    fun build(targetFolderPath: String? = null): String {
        val encoded = Uri.encode(targetFolderPath?.takeIf { it.isNotBlank() } ?: NONE)
        return "drive/import/$encoded"
    }

    /** Placeholder used when no target folder is supplied (an empty path segment is not routable). */
    const val NONE = " "
}

/** AND-336 - registers the Drive import picker in the authenticated graph. */
fun NavGraphBuilder.driveImportDestination(navController: NavHostController) {
    composable(
        route = DriveImportDest.ROUTE,
        arguments = listOf(
            navArgument(DriveImportDest.ARG_TARGET) {
                type = NavType.StringType
                defaultValue = DriveImportDest.NONE
            },
        ),
    ) {
        DrivePickerRoute(onDone = { navController.popBackStack() })
    }
}
