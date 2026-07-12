package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.videos.upload.VideoUploadRoute

/** Publish-a-video (VOD upload) screen. Reached from the gallery upload FAB. */
data object VideoUploadDest {
    const val ROUTE = "video_upload"
}

/** #5 — SavedStateHandle keys the upload screen writes back so the gallery shows a pending tile. */
object VideoUploadResult {
    const val UPLOADED_ID = "uploaded_video_id"
    const val UPLOADED_TITLE = "uploaded_video_title"
}

fun NavGraphBuilder.videoUploadDestination(navController: NavHostController) {
    composable(VideoUploadDest.ROUTE) {
        VideoUploadRoute(
            onBack = { navController.popBackStack() },
            // #5 — report the new video to the PREVIOUS back-stack entry (the gallery) so it can
            // render an immediate pending tile + refresh, then pop.
            onUploaded = { videoId, title ->
                navController.previousBackStackEntry?.savedStateHandle?.let { handle ->
                    handle[VideoUploadResult.UPLOADED_ID] = videoId
                    handle[VideoUploadResult.UPLOADED_TITLE] = title
                }
            },
        )
    }
}
