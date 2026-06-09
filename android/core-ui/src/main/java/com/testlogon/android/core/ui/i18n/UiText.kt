package com.testlogon.android.core.ui.i18n

import androidx.annotation.StringRes
import androidx.compose.runtime.Composable

/**
 * AND-111 — locale-agnostic text holder so a ViewModel's UiState can carry user-facing copy without
 * resolving it (no Context in ViewModels) and without leaking a resolved String that would go stale
 * on a locale change.
 *
 * - [Res] references a string resource (+ optional positional args); resolved in the composable.
 * - [Raw] carries server-passthrough text only (e.g. a normalized FastAPI error detail). It is
 *   rendered as plain text, never interpreted as markup.
 */
sealed interface UiText {
    data class Res(@StringRes val id: Int, val args: List<Any> = emptyList()) : UiText

    data class Raw(val value: String) : UiText
}

/** Resolves a [UiText] at the composable layer against the current configuration/locale. */
@Composable
fun UiText.asString(): String = when (this) {
    is UiText.Res -> text(id, *args.toTypedArray())
    is UiText.Raw -> value
}
