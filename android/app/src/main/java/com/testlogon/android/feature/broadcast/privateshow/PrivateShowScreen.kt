@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.privateshow

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.PrivateShowRequest
import com.testlogon.android.data.broadcast.PrivateShowSummary

/** AND-315 — stable testTags for the private-show host surfaces. */
object PrivateShowTestTags {
    const val REQUEST_SHEET = "private_request_sheet"
    const val ACCEPT = "private_accept"
    const val DECLINE = "private_decline"
    const val ACTIVE_BAR = "private_active_bar"
    const val END = "private_end"
    const val SUMMARY_DIALOG = "private_summary_dialog"
}

/**
 * AND-315 — the request -> accept/decline bottom sheet shown while a viewer is requesting a private show.
 * Shows the requester, the viewer-set rate (read-only), optional max duration, and a behavior chooser
 * (pause / end / continue; default pause). Accept emits the chosen behavior; both actions are disabled while
 * an action is in flight.
 */
@Composable
fun PrivateShowRequestSheet(
    request: PrivateShowRequest,
    inFlight: Boolean,
    onAccept: (PrivateShowBehavior) -> Unit,
    onDecline: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(PrivateShowTestTags.REQUEST_SHEET),
    ) {
        var behavior by remember { mutableStateOf(PrivateShowBehavior.PAUSE) }
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 24.dp, vertical = 16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.private_show_request_title),
                style = MaterialTheme.typography.titleLarge,
            )
            val requester = request.viewerDisplayName?.takeIf { it.isNotBlank() }
                ?: stringResource(R.string.private_show_anonymous_viewer)
            Text(
                text = stringResource(R.string.private_show_request_from, requester),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = stringResource(
                    R.string.private_show_rate,
                    formatCents(request.ratePerMinuteCents),
                ),
                style = MaterialTheme.typography.bodyMedium,
            )
            request.maxDurationMinutes?.let { minutes ->
                Text(
                    text = stringResource(R.string.private_show_max_duration, minutes),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }

            Text(
                text = stringResource(R.string.private_show_behavior_label),
                style = MaterialTheme.typography.titleSmall,
            )
            BehaviorChooser(selected = behavior, onSelect = { behavior = it })

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                val declineCd = stringResource(R.string.private_show_decline_cd)
                OutlinedButton(
                    onClick = onDecline,
                    enabled = !inFlight,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag(PrivateShowTestTags.DECLINE)
                        .semantics { contentDescription = declineCd },
                ) {
                    Text(stringResource(R.string.private_show_decline))
                }
                val acceptCd = stringResource(R.string.private_show_accept_cd)
                Button(
                    onClick = { onAccept(behavior) },
                    enabled = !inFlight,
                    modifier = Modifier
                        .weight(1f)
                        .heightIn(min = 48.dp)
                        .testTag(PrivateShowTestTags.ACCEPT)
                        .semantics { contentDescription = acceptCd },
                ) {
                    if (inFlight) {
                        CircularProgressIndicator(modifier = Modifier.heightIn(min = 20.dp))
                    } else {
                        Text(stringResource(R.string.private_show_accept))
                    }
                }
            }
        }
    }
}

@Composable
private fun BehaviorChooser(
    selected: PrivateShowBehavior,
    onSelect: (PrivateShowBehavior) -> Unit,
) {
    Column {
        PrivateShowBehavior.entries.forEach { option ->
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .selectable(selected = option == selected, onClick = { onSelect(option) }),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                RadioButton(selected = option == selected, onClick = { onSelect(option) })
                Text(stringResource(behaviorLabel(option)))
            }
        }
    }
}

/**
 * AND-315 — the active-show status bar: a live-ticking elapsed timer + running (client-estimate) cost + End.
 * The metrics are a polite live region for screen readers.
 */
@Composable
fun PrivateShowActiveBar(
    elapsedSeconds: Long,
    accruedCents: Long,
    ending: Boolean,
    onEnd: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        modifier = modifier
            .fillMaxWidth()
            .testTag(PrivateShowTestTags.ACTIVE_BAR),
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .semantics { liveRegion = LiveRegionMode.Polite },
                verticalArrangement = Arrangement.spacedBy(2.dp),
            ) {
                Text(
                    text = stringResource(R.string.private_show_active_title),
                    style = MaterialTheme.typography.titleSmall,
                )
                Text(
                    text = stringResource(R.string.private_show_elapsed, formatElapsed(elapsedSeconds)),
                    style = MaterialTheme.typography.bodyMedium,
                )
                Text(
                    text = stringResource(R.string.private_show_running_cost, formatCents(accruedCents)),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            val endCd = stringResource(R.string.private_show_end_cd)
            Button(
                onClick = onEnd,
                enabled = !ending,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(PrivateShowTestTags.END)
                    .semantics { contentDescription = endCd },
            ) {
                if (ending) {
                    CircularProgressIndicator(modifier = Modifier.heightIn(min = 20.dp))
                } else {
                    Text(stringResource(R.string.private_show_end))
                }
            }
        }
    }
}

/** AND-315 — the end summary dialog: duration + authoritative total billed (server summary). */
@Composable
fun PrivateShowSummaryDialog(
    summary: PrivateShowSummary,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(PrivateShowTestTags.SUMMARY_DIALOG),
        onDismissRequest = onDismiss,
        title = { Text(stringResource(R.string.private_show_summary_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    stringResource(
                        R.string.private_show_summary_duration,
                        formatElapsed(summary.durationSeconds.toLong()),
                    ),
                )
                Text(
                    stringResource(
                        R.string.private_show_summary_total,
                        formatCents(summary.totalBilledCents),
                    ),
                )
            }
        },
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text(stringResource(R.string.private_show_summary_dismiss))
            }
        },
    )
}

internal fun behaviorLabel(behavior: PrivateShowBehavior): Int = when (behavior) {
    PrivateShowBehavior.PAUSE -> R.string.private_show_behavior_pause
    PrivateShowBehavior.END -> R.string.private_show_behavior_end
    PrivateShowBehavior.CONTINUE -> R.string.private_show_behavior_continue
}
