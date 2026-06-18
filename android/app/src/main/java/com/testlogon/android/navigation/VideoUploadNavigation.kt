package com.testlogon.android.navigation

import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.compose.composable
import com.testlogon.android.feature.videos.upload.VideoUploadRoute

/** Publish-a-video (VOD upload) screen. Reached from the gallery upload FAB. */
data object VideoUploadDest {
    const val ROUTE = "video_upload"
}

fun NavGraphBuilder.videoUploadDestination(navController: NavHostController) {
    composable(VideoUploadDest.ROUTE) {
        VideoUploadRoute(onBack = { navController.popBackStack() })
    }
}
