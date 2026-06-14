package com.testlogon.android.feature.dashboard.states

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.theme.TestLogonTheme
import com.testlogon.android.feature.dashboard.DashboardTestTags

/**
 * AND-069 — empty/error/offline state composables for the dashboard.
 *
 * All are stateless and preview-able (copy from string resources, handlers hoisted), each carrying a
 * stable [DashboardTestTags] tag on its root and action. They delegate spacing/typography to the
 * shared core-ui [EmptyState]/[ErrorState] primitives.
 */
@Composable
fun DashboardEmptyState(
    onRefresh: () -> Unit,
    modifier: Modifier = Modifier,
) {
    EmptyState(
        title = stringResource(R.string.dashboard_empty_title),
        body = stringResource(R.string.dashboard_empty_body),
        actionLabel = stringResource(R.string.dashboard_action_refresh),
        onAction = onRefresh,
        modifier = modifier.testTag(DashboardTestTags.EMPTY),
    )
}

@Composable
fun DashboardErrorState(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val safeMessage = message.ifBlank { stringResource(R.string.dashboard_error_generic) }
    ErrorState(
        message = safeMessage,
        onRetry = onRetry,
        modifier = modifier.testTag(DashboardTestTags.ERROR),
    )
}

@Composable
fun DashboardOfflineState(
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    staleAsOf: String? = null,
) {
    val body = staleAsOf?.let { stringResource(R.string.dashboard_offline_stale_as_of, it) }
        ?: stringResource(R.string.dashboard_offline_body)
    EmptyState(
        title = stringResource(R.string.dashboard_offline_title),
        body = body,
        imageVector = Icons.Outlined.CloudOff,
        actionLabel = stringResource(R.string.dashboard_action_retry),
        onAction = onRetry,
        modifier = modifier.testTag(DashboardTestTags.OFFLINE),
    )
}

/** Non-blocking banner shown above cached content while stale (offline/refresh failed). */
@Composable
fun DashboardStaleBanner(
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    refreshing: Boolean = false,
) {
    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        modifier = modifier
            .fillMaxWidth()
            .testTag(DashboardTestTags.STALE_BANNER)
            .semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.CloudOff, contentDescription = null, modifier = Modifier.size(18.dp))
                Text(
                    text = stringResource(R.string.dashboard_offline_body),
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            TlButton(
                text = stringResource(R.string.dashboard_action_retry),
                onClick = onRetry,
                variant = TlButtonVariant.Text,
                enabled = !refreshing,
                modifier = Modifier.testTag(DashboardTestTags.RETRY_ACTION),
            )
        }
    }
}

@Preview
@Composable
private fun DashboardStatesPreview() {
    TestLogonTheme(dynamicColor = false) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            DashboardStaleBanner(onRetry = {})
            DashboardEmptyState(onRefresh = {})
        }
    }
}
