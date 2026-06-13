package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavController
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.dmca.DmcaRoute
import com.testlogon.android.feature.dmca.DmcaViewModel

/**
 * AND-384 - the DMCA submit destination.
 *
 * Two entry points (FR-1): the standalone form (Settings -> Privacy & Safety; no args) and a pre-targeted
 * form launched from a content / profile overflow menu (prefills + locks the content reference). All three
 * args are OPTIONAL query params so the same route serves both; the VM reads them from SavedStateHandle.
 */
data object DmcaDest {
    const val ARG_CONTENT_TYPE = DmcaViewModel.ARG_CONTENT_TYPE
    const val ARG_CONTENT_ID = DmcaViewModel.ARG_CONTENT_ID
    const val ARG_URL = DmcaViewModel.ARG_URL

    const val ROUTE =
        "dmca?$ARG_CONTENT_TYPE={$ARG_CONTENT_TYPE}&$ARG_CONTENT_ID={$ARG_CONTENT_ID}&$ARG_URL={$ARG_URL}"

    /** The plain standalone route (no pre-target) - what the Settings entry registers. */
    const val STANDALONE_ROUTE = "dmca"

    /** Builds a concrete pre-targeted route; null args are omitted so they fall back to the VM defaults. */
    fun build(
        contentType: String? = null,
        contentId: String? = null,
        url: String? = null,
    ): String {
        val params = buildList {
            contentType?.takeIf { it.isNotBlank() }?.let { add("$ARG_CONTENT_TYPE=${Uri.encode(it)}") }
            contentId?.takeIf { it.isNotBlank() }?.let { add("$ARG_CONTENT_ID=${Uri.encode(it)}") }
            url?.takeIf { it.isNotBlank() }?.let { add("$ARG_URL=${Uri.encode(it)}") }
        }
        return if (params.isEmpty()) STANDALONE_ROUTE else "dmca?${params.joinToString("&")}"
    }
}

/**
 * AND-384 - the shared navigation seam used by every entry point (Settings standalone + content/profile
 * overflow). Content call sites pass the resolved content reference to prefill + lock the form.
 */
fun NavController.navigateToDmca(
    contentType: String? = null,
    contentId: String? = null,
    url: String? = null,
) {
    navigate(DmcaDest.build(contentType, contentId, url)) { launchSingleTop = true }
}

/** AND-384 - registers the `dmca?...` destination with three optional, nullable string args. */
fun NavGraphBuilder.dmcaDestination(navController: NavHostController) {
    composable(
        route = DmcaDest.ROUTE,
        arguments = listOf(
            navArgument(DmcaDest.ARG_CONTENT_TYPE) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
            navArgument(DmcaDest.ARG_CONTENT_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
            navArgument(DmcaDest.ARG_URL) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        DmcaRoute(onBack = { navController.popBackStack() })
    }
}
