package com.testlogon.android.core.ui.state

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CloudOff
import androidx.compose.material.icons.outlined.Schedule
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.runtime.ProvidableCompositionLocal
import androidx.compose.runtime.compositionLocalOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.model.BackendStatus
import com.testlogon.android.core.model.Freshness
import com.testlogon.android.core.ui.R

/**
 * AND-117 — backend health provided once at the app scaffold root (collected via
 * `collectAsStateWithLifecycle` by the host) so per-screen code does not re-collect the health flow.
 * Defaults to [BackendStatus.Unknown].
 */
val LocalBackendStatus: ProvidableCompositionLocal<BackendStatus> =
    compositionLocalOf { BackendStatus.Unknown }

/** Convenience provider so a host can seed [LocalBackendStatus] for a subtree. */
@Composable
fun ProvideBackendStatus(status: BackendStatus, content: @Composable () -> Unit) {
    CompositionLocalProvider(LocalBackendStatus provides status, content = content)
}

/**
 * AND-117 — derives [StaleState] from cache [freshness] and the ambient [backend] health.
 * Cheap, synchronous, recomputed only when inputs change.
 */
@Composable
fun rememberStaleState(
    freshness: Freshness,
    backend: BackendStatus = LocalBackendStatus.current,
): StaleState = remember(freshness, backend) { deriveStaleState(freshness, backend) }

/**
 * AND-117 — thin, non-blocking inset bar shown above content when data is cache-served and
 * stale/refresh-failed/reconnecting. Stateless w.r.t. [state]; animates in/out (FR-5).
 *
 * Severity → Material 3 roles. State is conveyed by icon + text (never colour alone) and announced
 * via a polite live region. The retry button is hidden in Reconnecting mode and disabled while a
 * refresh is in flight (FR-3 retry-storm guard).
 */
@Composable
fun StaleBar(
    state: StaleState,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    AnimatedVisibility(
        visible = state.showBar,
        enter = expandVertically() + fadeIn(),
        exit = shrinkVertically() + fadeOut(),
        modifier = modifier,
    ) {
        val message = if (state.messageRes != 0) stringResource(state.messageRes) else ""
        val colors = colorsFor(state.mode)
        Surface(
            color = colors.first,
            contentColor = colors.second,
            modifier = Modifier
                .fillMaxWidth()
                .semantics {
                    liveRegion = LiveRegionMode.Polite
                    contentDescription = message
                },
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            ) {
                when (state.mode) {
                    StaleState.Mode.Reconnecting ->
                        CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                    StaleState.Mode.RefreshFailed ->
                        Icon(Icons.Filled.CloudOff, contentDescription = null, modifier = Modifier.size(18.dp))
                    StaleState.Mode.Stale ->
                        Icon(Icons.Outlined.Schedule, contentDescription = null, modifier = Modifier.size(18.dp))
                    StaleState.Mode.None -> Unit
                }
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier
                        .padding(start = 8.dp)
                        .weight(1f),
                )
                if (state.mode != StaleState.Mode.Reconnecting) {
                    TextButton(onClick = onRetry, enabled = state.retryEnabled) {
                        Text(stringResource(R.string.stale_retry))
                    }
                }
            }
        }
    }
}

/**
 * AND-117 — wraps per-screen [content] with a [StaleBar] derived from [freshness]. Features pass a
 * single [Freshness] (distilled from their SWR `Resource`) plus a retry lambda; no feature
 * re-implements freshness logic.
 */
@Composable
fun StaleContent(
    freshness: Freshness,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    val state = rememberStaleState(freshness)
    Column(modifier) {
        StaleBar(state = state, onRetry = onRetry, modifier = Modifier.fillMaxWidth())
        content()
    }
}

@Composable
private fun colorsFor(mode: StaleState.Mode): Pair<androidx.compose.ui.graphics.Color, androidx.compose.ui.graphics.Color> {
    val scheme = MaterialTheme.colorScheme
    return when (mode) {
        StaleState.Mode.RefreshFailed -> scheme.errorContainer to scheme.onErrorContainer
        StaleState.Mode.Reconnecting -> scheme.secondaryContainer to scheme.onSecondaryContainer
        StaleState.Mode.Stale -> scheme.surfaceVariant to scheme.onSurfaceVariant
        StaleState.Mode.None -> scheme.surface to scheme.onSurface
    }
}
