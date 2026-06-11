@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.payouts

import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Cancel
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material.icons.filled.ErrorOutline
import androidx.compose.material.icons.filled.HelpOutline
import androidx.compose.material.icons.filled.Schedule
import androidx.compose.material.icons.filled.Sync
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
import com.testlogon.android.data.payouts.PayoutBatchStatus

/**
 * AND-261 — color-coded bulk-batch status chip (icon + localized label), mirroring [PayoutStatusChip].
 * Never relies on color alone; exposes a "Status: <label>" contentDescription for TalkBack.
 */
@Composable
fun PayoutBatchStatusChip(status: PayoutBatchStatus, modifier: Modifier = Modifier) {
    val label = stringResource(payoutBatchStatusLabelRes(status))
    val cd = stringResource(R.string.payout_status_cd, label)
    val icon = batchStatusIcon(status)
    val tint = batchStatusColor(status)
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

private fun batchStatusIcon(status: PayoutBatchStatus): ImageVector = when (status) {
    PayoutBatchStatus.DRAFT, PayoutBatchStatus.PENDING -> Icons.Filled.Schedule
    PayoutBatchStatus.PROCESSING -> Icons.Filled.Sync
    PayoutBatchStatus.COMPLETED -> Icons.Filled.CheckCircle
    PayoutBatchStatus.PARTIALLY_FAILED -> Icons.Filled.ErrorOutline
    PayoutBatchStatus.FAILED -> Icons.Filled.Cancel
    PayoutBatchStatus.CANCELED -> Icons.Filled.Cancel
    PayoutBatchStatus.UNKNOWN -> Icons.Filled.HelpOutline
}

@Composable
private fun batchStatusColor(status: PayoutBatchStatus): Color = when (status) {
    PayoutBatchStatus.COMPLETED -> MaterialTheme.colorScheme.primary
    PayoutBatchStatus.PENDING, PayoutBatchStatus.PROCESSING, PayoutBatchStatus.DRAFT ->
        MaterialTheme.colorScheme.tertiary
    PayoutBatchStatus.PARTIALLY_FAILED, PayoutBatchStatus.FAILED -> MaterialTheme.colorScheme.error
    PayoutBatchStatus.CANCELED, PayoutBatchStatus.UNKNOWN -> MaterialTheme.colorScheme.onSurfaceVariant
}
