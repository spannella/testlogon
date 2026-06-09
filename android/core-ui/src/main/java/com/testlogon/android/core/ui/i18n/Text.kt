package com.testlogon.android.core.ui.i18n

import android.content.Context
import androidx.annotation.PluralsRes
import androidx.annotation.StringRes
import androidx.compose.runtime.Composable
import androidx.compose.runtime.ReadOnlyComposable
import androidx.compose.ui.platform.LocalContext

/**
 * AND-111 — Compose-side string accessors.
 *
 * These live in :core-ui (not a feature module) so shared keys owned by :core-ui (its R.string)
 * are reachable by every feature despite non-transitive R classes: features call [text] /
 * [quantityText] instead of touching another module's generated R.
 *
 * Resolution happens against LocalContext, so text re-resolves automatically on a configuration /
 * locale change (the basis for the no-restart locale switch in AND-114). ViewModels must NOT resolve
 * strings — they carry @StringRes ids or a [UiText]; the composable resolves.
 */
@Composable
@ReadOnlyComposable
fun text(@StringRes id: Int, vararg formatArgs: Any): String =
    LocalContext.current.resources.getString(id, *formatArgs)

/** Quantity-aware resolver backed by Android <plurals>; selects the CLDR quantity for [count]. */
@Composable
@ReadOnlyComposable
fun quantityText(@PluralsRes id: Int, count: Int, vararg formatArgs: Any): String =
    LocalContext.current.resources.getQuantityString(id, count, *formatArgs)

/**
 * Non-Compose resolver for call sites that legitimately hold a [Context] (Services, notification
 * builders). ViewModels are intentionally excluded — they have no Context and must defer resolution.
 */
object Strings {
    fun get(ctx: Context, @StringRes id: Int, vararg args: Any): String = ctx.getString(id, *args)

    fun quantity(ctx: Context, @PluralsRes id: Int, count: Int, vararg args: Any): String =
        ctx.resources.getQuantityString(id, count, *args)
}
