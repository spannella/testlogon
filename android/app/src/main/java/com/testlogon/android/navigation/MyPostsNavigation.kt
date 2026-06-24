package com.testlogon.android.navigation

import android.net.Uri
import androidx.navigation.NavGraphBuilder
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.testlogon.android.feature.feed.own.EditPostRoute
import com.testlogon.android.feature.feed.own.MyPostsRoute

/** FD1 -- "Your posts" management surface (own posts list + edit/delete). */
data object MyPostsDest {
    const val ROUTE = "my_posts"
    /** #4 — result key set on the My Posts entry after an edit returns, so the list force-refreshes. */
    const val RESULT_EDITED = "my_posts_edited"
}

/** FD1 -- edit an owned post. */
data object EditPostDest {
    const val ROUTE = "edit_post/{postId}"
    const val ARG_POST_ID = "postId"
    fun build(postId: String): String = "edit_post/${Uri.encode(postId)}"
}

fun NavGraphBuilder.myPostsDestination(navController: NavHostController) {
    composable(MyPostsDest.ROUTE) { backStackEntry ->
        // #4 — observe the edit result set on THIS entry's SavedStateHandle (set by the Edit screen on
        // pop). When present we force an immediate refresh and clear the flag so a later return doesn't
        // re-trigger it.
        val savedStateHandle = backStackEntry.savedStateHandle
        val editedResult = savedStateHandle.getStateFlow(MyPostsDest.RESULT_EDITED, false)
        MyPostsRoute(
            onBack = { navController.popBackStack() },
            onComposePost = { navController.navigate(ComposePostDest.ROUTE) },
            onEditPost = { postId -> navController.navigate(EditPostDest.build(postId)) },
            onPostClick = { postId -> navController.navigate(PostDetailDest.build(postId)) },
            refreshSignal = editedResult,
            onRefreshSignalConsumed = { savedStateHandle[MyPostsDest.RESULT_EDITED] = false },
        )
    }
    composable(
        route = EditPostDest.ROUTE,
        arguments = listOf(navArgument(EditPostDest.ARG_POST_ID) { type = NavType.StringType }),
    ) { backStackEntry ->
        val postId = backStackEntry.arguments?.getString(EditPostDest.ARG_POST_ID).orEmpty()
        EditPostRoute(
            postId = postId,
            onBack = {
                // #4 — signal the previous entry (My Posts, when edit was opened from there) to refresh
                // so the edited post's new text / photos / visibility / lock show up immediately. Harmless
                // when the previous entry is the shell (the main feed refreshes via its own ON_RESUME).
                navController.previousBackStackEntry
                    ?.savedStateHandle?.set(MyPostsDest.RESULT_EDITED, true)
                navController.popBackStack()
            },
        )
    }
}
