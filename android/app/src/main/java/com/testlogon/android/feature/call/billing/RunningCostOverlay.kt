package com.testlogon.android.feature.call.billing

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
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

/**
 * AND-301 — running-cost overlay for a PAID 1:1 call, rendered in the in-call top overlay area. Shows the
 * authoritative cost (heartbeat) or the local estimate (labelled "(est.)" via [isEstimate]) and a warning
 * chip when [condition] is a low-balance / max-duration warning. A polite liveRegion announces cost changes.
 */
@Composable
fun RunningCostOverlay(
    runningCostCents: Int,
    isEstimate: Boolean,
    condition: BillingCondition,
    modifier: Modifier = Modifier,
) {
    val costText = BillingCalculator.formatCents(runningCostCents)
    val estimateSuffix = if (isEstimate) " (" + stringResource(R.string.billing_estimate_suffix) + ")" else ""
    val costCd = stringResource(R.string.billing_running_cost_cd, costText)

    Column(
        modifier = modifier
            .testTag("running_cost")
            .semantics {
                liveRegion = LiveRegionMode.Polite
                contentDescription = costCd
            },
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = costText + estimateSuffix,
            style = MaterialTheme.typography.titleMedium,
        )
        val warning = conditionLabel(condition)
        if (warning != null) {
            Spacer(Modifier.height(4.dp))
            WarningChip(text = warning)
        }
    }
}

/**
 * AND-301 — final-cost summary shown on a paid call's Ended state. [finalCostCents] is authoritative from
 * the billing read, or the last running value when [finalIsEstimate] (labelled "estimated").
 */
@Composable
fun FinalCostSummary(
    finalCostCents: Int,
    finalIsEstimate: Boolean,
    modifier: Modifier = Modifier,
) {
    val total = stringResource(R.string.billing_final_cost, BillingCalculator.formatCents(finalCostCents))
    val text = if (finalIsEstimate) {
        total + " (" + stringResource(R.string.billing_estimate_suffix) + ")"
    } else {
        total
    }
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        modifier = modifier
            .testTag("final_cost")
            .semantics { liveRegion = LiveRegionMode.Polite },
    )
}

@Composable
private fun WarningChip(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        modifier = Modifier.testTag("running_cost_warning"),
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onErrorContainer,
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
        )
    }
}

@Composable
private fun conditionLabel(condition: BillingCondition): String? = when (condition) {
    BillingCondition.LowBalance, BillingCondition.BalanceDepleted ->
        stringResource(R.string.billing_low_balance)
    BillingCondition.MaxDurationWarning, BillingCondition.MaxDurationReached ->
        stringResource(R.string.billing_max_duration)
    BillingCondition.HeartbeatTimeout, BillingCondition.None -> null
}
