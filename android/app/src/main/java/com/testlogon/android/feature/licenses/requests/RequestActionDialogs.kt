package com.testlogon.android.feature.licenses.requests

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.licenses.FullLicenseRequest

/** Deny a received request with an optional reason. */
@Composable
fun DenyDialog(
    contentId: String,
    onDismiss: () -> Unit,
    onConfirm: (String) -> Unit,
) {
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("license_requests_deny_dialog"),
        title = { Text("Deny Request") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Optionally provide a reason for denying this request ($contentId).")
                OutlinedTextField(
                    value = reason,
                    onValueChange = { if (it.length <= 500) reason = it },
                    label = { Text("Reason (optional)") },
                    modifier = Modifier.fillMaxWidth().testTag("license_requests_deny_reason"),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(reason) },
                modifier = Modifier.testTag("license_requests_deny_confirm"),
            ) { Text("Deny Request") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

/** Propose counter terms for a received request. */
@Composable
fun CounterOfferDialog(
    target: FullLicenseRequest,
    onDismiss: () -> Unit,
    onConfirm: (profitPct: Double, revenuePct: Double, fixedCents: Long) -> Unit,
) {
    var profit by remember { mutableStateOf((target.proposedTerms?.profitSharePct ?: 0.0).cleanString()) }
    var revenue by remember { mutableStateOf((target.proposedTerms?.revenueSharePct ?: 0.0).cleanString()) }
    var fixed by remember { mutableStateOf((target.proposedTerms?.fixedCostCents ?: 0L).toString()) }

    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("license_requests_counter_dialog"),
        title = { Text("Counter-Offer") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                Text("Propose different terms for ${target.contentId}.")
                OutlinedTextField(
                    value = profit,
                    onValueChange = { profit = it.filter { c -> c.isDigit() || c == '.' } },
                    label = { Text("Profit Share %") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("license_requests_counter_profit"),
                )
                OutlinedTextField(
                    value = revenue,
                    onValueChange = { revenue = it.filter { c -> c.isDigit() || c == '.' } },
                    label = { Text("Revenue Share %") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    modifier = Modifier.fillMaxWidth().testTag("license_requests_counter_revenue"),
                )
                OutlinedTextField(
                    value = fixed,
                    onValueChange = { fixed = it.filter { c -> c.isDigit() } },
                    label = { Text("Fixed Cost (cents)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth().testTag("license_requests_counter_fixed"),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onConfirm(
                        profit.toDoubleOrNull() ?: 0.0,
                        revenue.toDoubleOrNull() ?: 0.0,
                        fixed.toLongOrNull() ?: 0L,
                    )
                },
                modifier = Modifier.testTag("license_requests_counter_confirm"),
            ) { Text("Send Counter-Offer") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

private fun Double.cleanString(): String =
    if (this == this.toLong().toDouble()) this.toLong().toString() else this.toString()
