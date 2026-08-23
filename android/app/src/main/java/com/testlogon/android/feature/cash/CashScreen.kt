@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.cash

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/**
 * The FIAT (USD) "Cash" screen — deposit / withdraw the USD wallet balance used for trading, margin &
 * fees, wired to the SAME real /ui/billing/wallet endpoints the web app uses. Deposit is gated behind a
 * payment-method pick + a money-safety confirm; Withdraw is capped at the balance behind a confirm.
 */
@Composable
fun CashRoute(
    onBack: () -> Unit,
    viewModel: CashViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    var showDepositConfirm by remember { mutableStateOf(false) }
    var showWithdrawConfirm by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Cash") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            // ---- Balance ----
            Card(modifier = Modifier.fillMaxWidth().testTag("cash_balance_card")) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("USD cash balance", style = MaterialTheme.typography.labelLarge)
                    if (state.loading) {
                        Spacer(Modifier.height(8.dp))
                        CircularProgressIndicator(modifier = Modifier.height(22.dp), strokeWidth = 2.dp)
                    } else if (state.walletUnavailable) {
                        Text(
                            "Unavailable",
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(
                            "Your cash wallet isn't available on this account yet.",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        Text(
                            CashMath.formatCentsUsd(state.balanceCents),
                            style = MaterialTheme.typography.headlineMedium,
                            fontWeight = FontWeight.Bold,
                            modifier = Modifier.testTag("cash_balance_value"),
                        )
                    }
                    Text(
                        "Usable for trading, margin & fees.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            state.successMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("cash_success"))
            }
            state.errorMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("cash_error"))
            }

            Spacer(Modifier.height(20.dp))

            // ---- Deposit ----
            Text("Deposit", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.depositText,
                onValueChange = viewModel::onDepositText,
                label = { Text("Amount (USD)") },
                prefix = { Text("$") },
                singleLine = true,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                supportingText = { Text("Minimum ${CashMath.formatCentsUsd(CashMath.MIN_CENTS)}.") },
                modifier = Modifier.fillMaxWidth().testTag("cash_deposit_amount"),
            )
            Spacer(Modifier.height(8.dp))
            if (state.hasPaymentMethod) {
                Text("Pay with", style = MaterialTheme.typography.labelLarge)
                Column {
                    state.paymentMethods.forEach { pm ->
                        Row(
                            verticalAlignment = Alignment.CenterVertically,
                            modifier = Modifier
                                .fillMaxWidth()
                                .selectable(
                                    selected = pm.id == state.selectedPaymentMethodId,
                                    onClick = { viewModel.onSelectPaymentMethod(pm.id) },
                                )
                                .padding(vertical = 4.dp)
                                .testTag("cash_pm_${pm.id}"),
                        ) {
                            RadioButton(
                                selected = pm.id == state.selectedPaymentMethodId,
                                onClick = { viewModel.onSelectPaymentMethod(pm.id) },
                            )
                            Spacer(Modifier.height(0.dp))
                            Text(
                                pm.label + if (pm.isDefault) "  (default)" else "",
                                style = MaterialTheme.typography.bodyMedium,
                            )
                        }
                    }
                }
            } else {
                Text(
                    "No payment method on file. Add one on the web billing page to fund a deposit.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.testTag("cash_no_pm"),
                )
            }
            Spacer(Modifier.height(12.dp))
            Button(
                onClick = { showDepositConfirm = true },
                enabled = state.canDeposit,
                modifier = Modifier.fillMaxWidth().testTag("cash_deposit_submit"),
            ) { Text("Deposit") }

            Spacer(Modifier.height(24.dp))
            Divider()
            Spacer(Modifier.height(20.dp))

            // ---- Withdraw ----
            Text("Withdraw", style = MaterialTheme.typography.titleMedium)
            Spacer(Modifier.height(8.dp))
            OutlinedTextField(
                value = state.withdrawText,
                onValueChange = viewModel::onWithdrawText,
                label = { Text("Amount (USD)") },
                prefix = { Text("$") },
                singleLine = true,
                enabled = !state.walletUnavailable,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                supportingText = { Text("Up to your ${CashMath.formatCentsUsd(state.balanceCents)} balance.") },
                modifier = Modifier.fillMaxWidth().testTag("cash_withdraw_amount"),
            )
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp), modifier = Modifier.fillMaxWidth()) {
                OutlinedButton(
                    onClick = viewModel::onWithdrawMax,
                    enabled = !state.walletUnavailable && state.balanceCents >= CashMath.MIN_CENTS,
                    modifier = Modifier.testTag("cash_withdraw_max"),
                ) { Text("Max") }
                Button(
                    onClick = { showWithdrawConfirm = true },
                    enabled = state.canWithdraw,
                    modifier = Modifier.fillMaxWidth().testTag("cash_withdraw_submit"),
                ) {
                    if (state.submitting) {
                        CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp)
                    } else {
                        Text("Withdraw")
                    }
                }
            }
        }
    }

    if (showDepositConfirm) {
        val pmLabel = state.paymentMethods.firstOrNull { it.id == state.selectedPaymentMethodId }?.label ?: "—"
        AlertDialog(
            onDismissRequest = { showDepositConfirm = false },
            title = { Text("Confirm deposit") },
            text = {
                Column {
                    CashRow("Action", "Deposit to cash balance")
                    CashRow("Amount", "$" + state.depositText.ifBlank { "0" }, emphasize = true)
                    CashRow("Pay with", pmLabel)
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "This charges your payment method now and credits your USD cash balance.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showDepositConfirm = false
                        viewModel.confirmDeposit()
                    },
                    modifier = Modifier.testTag("cash_deposit_confirm"),
                ) { Text("Deposit") }
            },
            dismissButton = { TextButton(onClick = { showDepositConfirm = false }) { Text("Cancel") } },
        )
    }

    if (showWithdrawConfirm) {
        AlertDialog(
            onDismissRequest = { showWithdrawConfirm = false },
            title = { Text("Confirm withdrawal") },
            text = {
                Column {
                    CashRow("Action", "Withdraw from cash balance")
                    CashRow("Amount", "$" + state.withdrawText.ifBlank { "0" }, emphasize = true)
                    CashRow("Remaining balance", "current ${CashMath.formatCentsUsd(state.balanceCents)}")
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "This moves funds out of your USD cash balance.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        showWithdrawConfirm = false
                        viewModel.confirmWithdraw()
                    },
                    modifier = Modifier.testTag("cash_withdraw_confirm"),
                ) { Text("Withdraw") }
            },
            dismissButton = { TextButton(onClick = { showWithdrawConfirm = false }) { Text("Cancel") } },
        )
    }
}

@Composable
private fun CashRow(label: String, value: String, emphasize: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(
            value,
            style = MaterialTheme.typography.bodyMedium,
            fontWeight = if (emphasize) FontWeight.Bold else FontWeight.Normal,
        )
    }
}
