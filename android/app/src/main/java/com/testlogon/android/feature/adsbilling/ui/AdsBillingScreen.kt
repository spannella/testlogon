@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adsbilling.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.ads.AdAccountSummary
import com.testlogon.android.core.model.ads.AdBillingEntry
import com.testlogon.android.core.model.ads.AdInvoice
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlTextField
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner

/** AND-367 - stable testTags for the ads-account billing screen + deposit sheet. */
object AdsBillingTestTags {
    const val SCREEN = "ads_billing_screen"
    const val BALANCE = "ads_balance"
    const val INVOICE = "ads_invoice"
    const val ADD_FUNDS = "ads_add_funds"
    const val DEPOSIT_AMOUNT = "ads_deposit_amount"
    const val DEPOSIT_CONFIRM = "ads_deposit_confirm"
    const val DEPOSIT_SUCCESS = "ads_deposit_success"
    const val ERROR_RETRY = "ads_error_retry"

    /** Per-row ledger tag (suffix is the row index). */
    fun ledgerRow(index: Int): String = "ads_ledger_row_$index"
}

/**
 * AND-367 - route-level ads-billing entry (reached from the More hub / an ads-accounts list downstream). The
 * VM reads {accountId} from SavedStateHandle. Hosts the summary + ledger + invoice read view and the deposit
 * (add-funds) sheet.
 */
@Composable
fun AdsBillingRoute(
    onBack: () -> Unit,
    viewModel: AdsBillingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val depositState by viewModel.depositState.collectAsStateWithLifecycle()
    val depositSheetVisible by viewModel.depositSheetVisible.collectAsStateWithLifecycle()
    val amountText by viewModel.amountText.collectAsStateWithLifecycle()
    AdsBillingScreen(
        state = state,
        depositState = depositState,
        depositSheetVisible = depositSheetVisible,
        amountText = amountText,
        canSubmitDeposit = viewModel.canSubmitDeposit,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onOpenDeposit = viewModel::openDeposit,
        onDismissDeposit = viewModel::dismissDeposit,
        onAmountChanged = viewModel::onAmountChanged,
        onConfirmDeposit = { viewModel.deposit() },
    )
}

/** AND-367 - stateless ads-account billing screen. */
@Composable
fun AdsBillingScreen(
    state: AdsBillingUiState,
    depositState: DepositState,
    depositSheetVisible: Boolean,
    amountText: String,
    canSubmitDeposit: Boolean,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenDeposit: () -> Unit,
    onDismissDeposit: () -> Unit,
    onAmountChanged: (String) -> Unit,
    onConfirmDeposit: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdsBillingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ads_billing_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_billing_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            when (state) {
                is AdsBillingUiState.Loading -> LoadingState()
                is AdsBillingUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdsBillingTestTags.ERROR_RETRY),
                )
                is AdsBillingUiState.Content -> AdsBillingContent(
                    state = state,
                    onOpenDeposit = onOpenDeposit,
                    onRetry = onRetry,
                )
            }
        }
    }

    if (state is AdsBillingUiState.Content && depositSheetVisible) {
        DepositSheet(
            depositState = depositState,
            amountText = amountText,
            canSubmitDeposit = canSubmitDeposit,
            onDismiss = onDismissDeposit,
            onAmountChanged = onAmountChanged,
            onConfirm = onConfirmDeposit,
        )
    }
}

@Composable
private fun AdsBillingContent(
    state: AdsBillingUiState.Content,
    onOpenDeposit: () -> Unit,
    onRetry: () -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        item {
            StaleBanner(stale = state.isStale, refreshing = false, onRetry = onRetry)
        }
        item {
            SummaryCard(account = state.account, onOpenDeposit = onOpenDeposit)
        }
        item {
            Text(
                text = stringResource(R.string.ads_billing_ledger_header),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (state.ledger.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.ads_billing_ledger_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            itemsIndexed(state.ledger) { index, entry ->
                LedgerRow(index = index, entry = entry)
            }
        }
        if (state.invoice != null) {
            item {
                InvoiceSection(invoice = state.invoice)
            }
        }
    }
}

@Composable
private fun SummaryCard(account: AdAccountSummary, onOpenDeposit: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            account.companyName?.let {
                Text(text = it, style = MaterialTheme.typography.titleLarge)
            }
            account.status?.let {
                Text(
                    text = stringResource(R.string.ads_billing_status_label, it),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            HorizontalDivider()
            LabeledRow(
                label = stringResource(R.string.ads_billing_balance_label),
                value = formatCents(account.balanceCents),
                valueModifier = Modifier.testTag(AdsBillingTestTags.BALANCE),
            )
            LabeledRow(
                label = stringResource(R.string.ads_billing_lifetime_spend_label),
                value = formatCents(account.lifetimeSpendCents),
            )
            TlButton(
                text = stringResource(R.string.ads_billing_add_funds),
                onClick = onOpenDeposit,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(AdsBillingTestTags.ADD_FUNDS),
            )
        }
    }
}

@Composable
private fun LedgerRow(index: Int, entry: AdBillingEntry) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdsBillingTestTags.ledgerRow(index)),
        verticalArrangement = Arrangement.spacedBy(2.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(
                text = entry.entryType ?: stringResource(R.string.ads_billing_entry_unknown),
                style = MaterialTheme.typography.bodyLarge,
            )
            Text(
                text = formatCents(entry.amountCents),
                style = MaterialTheme.typography.bodyLarge,
            )
        }
        val subtitle = listOfNotNull(entry.state, entry.reason).joinToString(" • ")
        if (subtitle.isNotEmpty()) {
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        entry.createdAt?.let {
            Text(
                text = stringResource(R.string.ads_billing_entry_date, it),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        HorizontalDivider()
    }
}

@Composable
private fun InvoiceSection(invoice: AdInvoice) {
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(AdsBillingTestTags.INVOICE),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = stringResource(
                    R.string.ads_billing_invoice_header,
                    invoice.month ?: stringResource(R.string.ads_billing_invoice_month_unknown),
                ),
                style = MaterialTheme.typography.titleMedium,
            )
            LabeledRow(
                label = stringResource(R.string.ads_billing_invoice_charges),
                value = formatCents(invoice.totalChargesCents),
            )
            LabeledRow(
                label = stringResource(R.string.ads_billing_invoice_deposits),
                value = formatCents(invoice.totalDepositsCents),
            )
            if (invoice.campaigns.isNotEmpty()) {
                HorizontalDivider()
                invoice.campaigns.forEach { line ->
                    LabeledRow(
                        label = line.campaignId
                            ?: stringResource(R.string.ads_billing_invoice_campaign_unknown),
                        value = formatCents(line.totalCents),
                    )
                }
            }
        }
    }
}

@Composable
private fun DepositSheet(
    depositState: DepositState,
    amountText: String,
    canSubmitDeposit: Boolean,
    onDismiss: () -> Unit,
    onAmountChanged: (String) -> Unit,
    onConfirm: () -> Unit,
) {
    // The sheet is open whenever a deposit interaction is in progress (Idle once opened, Submitting,
    // Success, or Error). When fully dismissed the VM sets Idle + empties the amount, and we render nothing.
    val sheetState = rememberModalBottomSheetState()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 8.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.deposit_sheet_title),
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = stringResource(R.string.deposit_sheet_subtitle),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            val submitting = depositState is DepositState.Submitting
            val showInvalid = amountText.isNotBlank() && !canSubmitDeposit
            TlTextField(
                value = amountText,
                onValueChange = onAmountChanged,
                label = stringResource(R.string.deposit_amount_label),
                enabled = !submitting,
                isError = showInvalid,
                errorText = if (showInvalid) stringResource(R.string.deposit_amount_range_error) else null,
                helperText = stringResource(R.string.deposit_amount_helper),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                modifier = Modifier.testTag(AdsBillingTestTags.DEPOSIT_AMOUNT),
            )

            when (depositState) {
                is DepositState.Error -> Text(
                    text = depositState.message,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodyMedium,
                )
                is DepositState.Success -> Text(
                    text = depositState.newBalanceCents?.let {
                        stringResource(R.string.deposit_success_with_balance, formatCents(it))
                    } ?: stringResource(R.string.deposit_success),
                    color = MaterialTheme.colorScheme.primary,
                    style = MaterialTheme.typography.bodyMedium,
                    modifier = Modifier.testTag(AdsBillingTestTags.DEPOSIT_SUCCESS),
                )
                else -> Unit
            }

            TlButton(
                text = stringResource(R.string.deposit_confirm),
                onClick = onConfirm,
                enabled = canSubmitDeposit && !submitting,
                loading = submitting,
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag(AdsBillingTestTags.DEPOSIT_CONFIRM),
            )
        }
    }
}

@Composable
private fun LabeledRow(label: String, value: String, valueModifier: Modifier = Modifier) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(text = value, style = MaterialTheme.typography.bodyMedium, modifier = valueModifier)
    }
}
