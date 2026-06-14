package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.seo.data.ResourceType
import com.testlogon.android.feature.seo.ui.SeoRoute
import com.testlogon.android.feature.seo.ui.SeoViewModel

/**
 * AND-400 - the READ-ONLY public SEO inspector destination (`seo/{resourceType}/{id}` with an optional
 * `?secondaryId=` arg for events). The VM reads resourceType / id / secondaryId from SavedStateHandle.
 *
 * STUB ENTRY: there is no per-resource detail surface wiring this screen in scope this wave, so the
 * More-hub links to a known sample resource ([STUB_ROUTE]) for manual testing - downstream this is
 * reached from a resource's detail screen (mirrors AND-368 AdAnalyticsDest's stub entry).
 */
data object SeoDest {
    const val ARG_RESOURCE_TYPE = SeoViewModel.ARG_RESOURCE_TYPE
    const val ARG_ID = SeoViewModel.ARG_ID
    const val ARG_SECONDARY_ID = SeoViewModel.ARG_SECONDARY_ID

    const val ROUTE = "seo/{$ARG_RESOURCE_TYPE}/{$ARG_ID}?$ARG_SECONDARY_ID={$ARG_SECONDARY_ID}"

    /** A known sample resource the More-hub stub entry opens (manual testing only). */
    const val SAMPLE_ID = "sample"

    /** Builds the concrete route for a resource (events pass [secondaryId]). */
    fun build(type: ResourceType, id: String, secondaryId: String? = null): String {
        val base = "seo/${type.wire}/${Uri.encode(id)}"
        return if (secondaryId.isNullOrBlank()) base else "$base?$ARG_SECONDARY_ID=${Uri.encode(secondaryId)}"
    }

    /**
     * The plain stub route the More-hub registers - a known sample PROFILE resource (plain constant,
     * no Uri.encode, so the JVM MoreCatalog integrity test stays Android-free; the literal matches
     * ResourceType.PROFILE.wire = "profile").
     */
    const val STUB_ROUTE = "seo/profile/$SAMPLE_ID"
}

/** AND-400 - navigates to the SEO inspector for a resource (the entry-point seam). */
fun NavHostController.navigateToSeo(type: ResourceType, id: String, secondaryId: String? = null) {
    navigate(SeoDest.build(type, id, secondaryId)) { launchSingleTop = true }
}

/** AND-400 - registers the `seo/{resourceType}/{id}` destination. */
fun NavGraphBuilder.seoDestination(navController: NavHostController) {
    composable(
        route = SeoDest.ROUTE,
        arguments = listOf(
            navArgument(SeoDest.ARG_RESOURCE_TYPE) { type = NavType.StringType },
            navArgument(SeoDest.ARG_ID) { type = NavType.StringType },
            navArgument(SeoDest.ARG_SECONDARY_ID) {
                type = NavType.StringType
                nullable = true
                defaultValue = null
            },
        ),
    ) {
        SeoRoute(onBack = { navController.popBackStack() })
    }
}
