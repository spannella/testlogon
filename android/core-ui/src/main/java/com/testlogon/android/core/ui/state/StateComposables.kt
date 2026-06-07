package com.testlogon.android.core.ui.state

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.CloudOff
import androidx.compose.material.icons.outlined.ErrorOutline
import androidx.compose.material.icons.outlined.Inbox
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.R
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.theme.TestLogonTheme

/** Centered (full-screen) or inline progress indicator. Stateless. */
@Composable
fun LoadingState(
    modifier: Modifier = Modifier,
    message: String? = null,
    fullScreen: Boolean = true,
) {
    val loadingCd = stringResource(R.string.state_loading)
    val container = if (fullScreen) {
        modifier.fillMaxSize()
    } else {
        modifier.fillMaxWidth().padding(16.dp)
    }
    Box(
        modifier = container.semantics { liveRegion = LiveRegionMode.Polite },
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            CircularProgressIndicator(modifier = Modifier.semantics { contentDescription = loadingCd })
            Text(message ?: loadingCd, style = MaterialTheme.typography.bodyMedium)
        }
    }
}

/** Empty (zero-results) surface with an optional primary action. Stateless. */
@Composable
fun EmptyState(
    title: String,
    modifier: Modifier = Modifier,
    body: String? = null,
    imageVector: ImageVector = Icons.Outlined.Inbox,
    actionLabel: String? = null,
    onAction: (() -> Unit)? = null,
) {
    CenteredMessage(
        modifier = modifier,
        icon = imageVector,
        iconDescription = title,
        title = title,
        body = body,
        actionLabel = actionLabel,
        onAction = onAction,
    )
}

/** Error surface with a Retry button. [message] must already be a sanitized, human-readable string. */
@Composable
fun ErrorState(
    message: String,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
    title: String = stringResource(R.string.state_error_title),
    retryLabel: String = stringResource(R.string.action_retry),
    imageVector: ImageVector = Icons.Outlined.ErrorOutline,
) {
    CenteredMessage(
        modifier = modifier.semantics { liveRegion = LiveRegionMode.Polite },
        icon = imageVector,
        iconDescription = title,
        title = title,
        body = message,
        actionLabel = retryLabel,
        onAction = onRetry,
    )
}

/** Slim inline banner signalling no connectivity. Does not replace content. */
@Composable
fun OfflineBanner(
    modifier: Modifier = Modifier,
    message: String = stringResource(R.string.state_offline_message),
    onRetry: (() -> Unit)? = null,
) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = modifier
            .fillMaxWidth()
            .semantics { liveRegion = LiveRegionMode.Polite },
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.CloudOff, contentDescription = null, modifier = Modifier.size(20.dp))
                Text(
                    text = message,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            if (onRetry != null) {
                TextButton(onClick = onRetry) { Text(stringResource(R.string.action_retry)) }
            }
        }
    }
}

/** Shared centered icon + title + body + optional action layout. */
@Composable
private fun CenteredMessage(
    icon: ImageVector,
    iconDescription: String,
    title: String,
    body: String?,
    actionLabel: String?,
    onAction: (() -> Unit)?,
    modifier: Modifier = Modifier,
) {
    Box(
        modifier = modifier.fillMaxSize().padding(24.dp),
        contentAlignment = Alignment.Center,
    ) {
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = icon,
                contentDescription = iconDescription,
                modifier = Modifier.size(48.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(title, style = MaterialTheme.typography.titleMedium, textAlign = TextAlign.Center)
            if (body != null) {
                Text(
                    text = body,
                    style = MaterialTheme.typography.bodyMedium,
                    textAlign = TextAlign.Center,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            if (actionLabel != null && onAction != null) {
                TlButton(text = actionLabel, onClick = onAction)
            }
        }
    }
}

@Preview
@Composable
private fun StatePreviews() {
    TestLogonTheme(dynamicColor = false) {
        Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
            OfflineBanner(onRetry = {})
            EmptyState(title = "Nothing here", body = "Pull to refresh", actionLabel = "Refresh", onAction = {})
        }
    }
}
