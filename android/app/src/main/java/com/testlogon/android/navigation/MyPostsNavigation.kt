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
}

/** FD1 -- edit an owned post. */
data object EditPostDest {
    const val ROUTE = "edit_post/{postId}"
    const val ARG_POST_ID = "postId"
    fun build(postId: String): String = "edit_post/${Uri.encode(postId)}"
}

fun NavGraphBuilder.myPostsDestination(navController: NavHostController) {
    composable(MyPostsDest.ROUTE) {
        MyPostsRoute(
            onBack = { navController.popBackStack() },
            onComposePost = { navController.navigate(ComposePostDest.ROUTE) },
            onEditPost = { postId -> navController.navigate(EditPostDest.build(postId)) },
            onPostClick = { postId -> navController.navigate(PostDetailDest.build(postId)) },
        )
    }
    composable(
        route = EditPostDest.ROUTE,
        arguments = listOf(navArgument(EditPostDest.ARG_POST_ID) { type = NavType.StringType }),
    ) { backStackEntry ->
        val postId = backStackEntry.arguments?.getString(EditPostDest.ARG_POST_ID).orEmpty()
        EditPostRoute(
            postId = postId,
            onBack = { navController.popBackStack() },
        )
    }
}
