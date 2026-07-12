@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.PauseCircle
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Sync
import androidx.compose.material.icons.filled.ThumbUp
import androidx.compose.material.icons.filled.Undo
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.payouts.PayoutStatus

/**
 * AND-260 — shared color-coded status chip with an icon + localized label, mirroring the AssistChip
 * convention used by the invoices/refunds screens. Never relies on color alone (each status has a
 * distinct icon + label); exposes a "Status: <label>" contentDescription for TalkBack.
 */
@Composable
fun PayoutStatusChip(status: PayoutStatus, modifier: Modifier = Modifier) {
    val label = stringResource(payoutStatusLabelRes(status))
    val cd = stringResource(R.string.payout_status_cd, label)
    val icon = statusIcon(status)
    val tint = statusColor(status)
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(label, style = MaterialTheme.typography.labelMedium) },
        leadingIcon = {
            Icon(icon, contentDescription = null, modifier = Modifier.size(AssistChipDefaults.IconSize), tint = tint)
        },
        colors = AssistChipDefaults.assistChipColors(
            disabledLabelColor = MaterialTheme.colorScheme.onSurface,
            disabledLeadingIconContentColor = tint,
        ),
        modifier = modifier.clearAndSetSemantics { contentDescription = cd },
    )
}

private fun statusIcon(status: PayoutStatus): ImageVector = when (status) {
    PayoutStatus.REQUESTED -> Icons.Filled.Schedule
    PayoutStatus.APPROVED -> Icons.Filled.ThumbUp
    PayoutStatus.PROCESSING -> Icons.Filled.Sync
    PayoutStatus.PAID, PayoutStatus.COMPLETED -> Icons.Filled.CheckCircle
    PayoutStatus.FAILED -> Icons.Filled.ErrorOutline
    PayoutStatus.RETURNED -> Icons.Filled.Undo
    PayoutStatus.HELD -> Icons.Filled.PauseCircle
    PayoutStatus.REJECTED -> Icons.Filled.Cancel
    PayoutStatus.CANCELLED -> Icons.Filled.Cancel
    PayoutStatus.UNKNOWN -> Icons.Filled.HelpOutline
}

@Composable
private fun statusColor(status: PayoutStatus): Color = when (status) {
    PayoutStatus.PAID, PayoutStatus.COMPLETED, PayoutStatus.APPROVED -> MaterialTheme.colorScheme.primary
    PayoutStatus.REQUESTED, PayoutStatus.PROCESSING, PayoutStatus.HELD -> MaterialTheme.colorScheme.tertiary
    PayoutStatus.FAILED, PayoutStatus.RETURNED, PayoutStatus.REJECTED -> MaterialTheme.colorScheme.error
    PayoutStatus.CANCELLED, PayoutStatus.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
}
