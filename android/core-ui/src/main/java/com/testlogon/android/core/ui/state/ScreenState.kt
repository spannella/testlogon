package com.testlogon.android.core.ui.state

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import com.testlogon.android.core.ui.R

/**
 * Local screen-state mapping type (kept in core-ui so it has no core-network dependency).
 * Feature ViewModels map their own `UiState<T>` to this at the screen boundary.
 */
sealed interface ScreenState<out T> {
    data object Loading : ScreenState<Nothing>
    data class Content<T>(val value: T) : ScreenState<T>
    data object Empty : ScreenState<Nothing>
    data class Error(val message: String, val offline: Boolean = false) : ScreenState<Nothing>
}

/**
 * Renders the correct full-screen state for [state] (loading / empty / error / offline) or the
 * [content] for a [ScreenState.Content]. [onRetry] is routed to the Error / Offline surfaces.
 */
@Composable
fun <T> ScreenStateContainer(
    state: ScreenState<T>,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    emptyTitle: String = stringResource(R.string.state_empty_title),
    content: @Composable (T) -> Unit,
) {
    Box(modifier.fillMaxSize()) {
        when (state) {
            ScreenState.Loading -> LoadingState()
            ScreenState.Empty -> EmptyState(title = emptyTitle)
            is ScreenState.Error ->
                if (state.offline) {
                    OfflineBanner(onRetry = onRetry)
                } else {
                    ErrorState(message = state.message, onRetry = onRetry)
                }
            is ScreenState.Content -> content(state.value)
        }
    }
}
