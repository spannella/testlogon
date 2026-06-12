package com.testlogon.android.feature.call.billing

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-301 — pre-start confirm for a PAID 1:1 call. A LOCAL affordance (there is no server /authorize
 * endpoint): it shows the per-minute rate and the wallet balance when known, and gates Start.
 *
 * The wallet-balance check is the FLAGGED [com.testlogon.android.data.messaging.BillingAuthorizer] seam
 * (AND-031) which returns NotConfigured, so [balanceRemainingCents] is typically null -> a "balance check
 * unavailable" note is shown and Start is STILL allowed (do NOT block start on an unknown balance). Start
 * is disabled only when the balance IS known AND is below the per-minute rate. AlertDialog is stable M3.
 */
@Composable
fun PaidCallConfirmDialog(
    rateCentsPerMinute: Int,
    balanceRemainingCents: Int?,
    onConfirm: () -> Unit,
    onCancel: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val rateLabel = stringResource(
        R.string.billing_rate_per_min,
        BillingCalculator.formatCents(rateCentsPerMinute),
    )
    // Allow start unless the balance is known AND insufficient to cover one minute. Unknown balance
    // (FLAGGED seam) -> allowed.
    val startEnabled = balanceRemainingCents == null || balanceRemainingCents >= rateCentsPerMinute

    AlertDialog(
        modifier = modifier.testTag("paid_call_confirm"),
        onDismissRequest = onCancel,
        title = { Text(stringResource(R.string.billing_paid_call_title)) },
        text = {
            Column(modifier = Modifier.heightIn(min = 0.dp)) {
                Text(
                    text = rateLabel,
                    style = MaterialTheme.typography.bodyLarge,
                    modifier = Modifier.semantics { liveRegion = LiveRegionMode.Polite },
                )
                Spacer(Modifier.height(8.dp))
                if (balanceRemainingCents != null) {
                    Text(
                        text = stringResource(
                            R.string.billing_balance_remaining,
                            BillingCalculator.formatCents(balanceRemainingCents),
                        ),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.testTag("paid_call_balance"),
                    )
                } else {
                    Text(
                        text = stringResource(R.string.billing_balance_unavailable),
                        style = MaterialTheme.typography.bodyMedium,
                        modifier = Modifier.testTag("paid_call_balance_unavailable"),
                    )
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = onConfirm,
                enabled = startEnabled,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag("paid_call_start"),
            ) { Text(stringResource(R.string.billing_start_paid_call)) }
        },
        dismissButton = {
            TextButton(
                onClick = onCancel,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag("paid_call_cancel"),
            ) { Text(stringResource(R.string.billing_cancel)) }
        },
    )
}
