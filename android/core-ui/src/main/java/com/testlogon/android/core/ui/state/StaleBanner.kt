package com.testlogon.android.core.ui.state

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.History
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp

/**
 * AND-045 — stale/reconnecting indicator for auth-area reads.
 *
 * Renders nothing when fresh and not refreshing. While [refreshing] it shows a reconnecting
 * affordance; when [stale] (cached data shown while the host is down) it shows an offline message
 * with a Retry action. State is conveyed by icon + text (not colour alone) and announced via a
 * polite live region.
 */
@Composable
fun StaleBanner(
    stale: Boolean,
    refreshing: Boolean,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    if (!stale && !refreshing) return

    Surface(
        color = MaterialTheme.colorScheme.tertiaryContainer,
        contentColor = MaterialTheme.colorScheme.onTertiaryContainer,
        modifier = modifier
            .fillMaxWidth()
            .semantics {
                liveRegion = LiveRegionMode.Polite
                stateDescription = if (refreshing) "reconnecting" else "offline, showing saved data"
            },
    ) {
        Column(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                if (refreshing) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
                } else {
                    Icon(Icons.Outlined.History, contentDescription = null, modifier = Modifier.size(18.dp))
                }
                Text(
                    text = if (refreshing) {
                        "Reconnecting…"
                    } else {
                        "Offline — showing last-known data"
                    },
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            if (stale && !refreshing) {
                TextButton(onClick = onRetry) { Text("Retry") }
            }
        }
    }
}
