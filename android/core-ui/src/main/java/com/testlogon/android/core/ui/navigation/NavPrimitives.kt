package com.testlogon.android.core.ui.navigation

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.tween
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally

/**
 * Shared, feature-agnostic navigation primitives (AND-022). Lives in core-ui so feature modules
 * may reference them without depending on `:app`.
 *
 * SECURITY: sensitive values (passwords, OTP codes, challenge ids, session/CSRF tokens) must NEVER
 * be encoded into route arguments — route args can be persisted to the saved-state Bundle on
 * process death. Pass such values via injected ViewModels / session state instead.
 */

/** Marker for routes that are valid NavHost destinations. */
sealed interface NavRoute

/** Marker for routes eligible to be a top-level (back-stack root) destination. */
sealed interface TopLevelRoute : NavRoute

/** App-wide navigation transition policy: horizontal slide + fade, 300ms. */
object TLTransitions {
    private const val DURATION = 300

    fun enter(): EnterTransition =
        slideInHorizontally(tween(DURATION)) { it / 4 } + fadeIn(tween(DURATION))

    fun exit(): ExitTransition =
        slideOutHorizontally(tween(DURATION)) { -it / 4 } + fadeOut(tween(DURATION))

    fun popEnter(): EnterTransition =
        slideInHorizontally(tween(DURATION)) { -it / 4 } + fadeIn(tween(DURATION))

    fun popExit(): ExitTransition =
        slideOutHorizontally(tween(DURATION)) { it / 4 } + fadeOut(tween(DURATION))
}
