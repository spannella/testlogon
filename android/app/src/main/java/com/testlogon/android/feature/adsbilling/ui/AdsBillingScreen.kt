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
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import com.testlogon.android.data.billing.PaymentMethod
import androidx.compose.material3.FilterChip
import androidx.compose.material3.TabRow
import androidx.compose.material3.Tab
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import com.testlogon.android.feature.checkout.CheckoutCryptoMath

/** AND-367 - stable testTags for the ads-account billing screen + deposit sheet. */
object AdsBillingTestTags {
    const val SCREEN = "ads_billing_screen"
    const val BALANCE = "ads_balance"
    const val INVOICE = "ads_invoice"
    const val ADD_FUNDS = "ads_add_funds"
    const val DEPOSIT_AMOUNT = "ads_deposit_amount"
    const val DEPOSIT_PM = "ads_deposit_payment_method"
    const val DEPOSIT_CONFIRM = "ads_deposit_confirm"
    const val DEPOSIT_SUCCESS = "ads_deposit_success"
    const val DEPOSIT_DONE = "ads_deposit_done"
    const val FUND_TAB_CARD = "ads_fund_tab_card"
    const val FUND_TAB_CRYPTO = "ads_fund_tab_crypto"
    const val CRYPTO_ASSET_PICKER = "ads_crypto_asset_picker"
    const val CRYPTO_RATE = "ads_crypto_rate"
    const val CRYPTO_COUNTDOWN = "ads_crypto_countdown"
    const val CRYPTO_INSUFFICIENT = "ads_crypto_insufficient"
    const val CRYPTO_FUND_CONFIRM = "ads_crypto_fund_confirm"
    const val CRYPTO_UNAVAILABLE = "ads_crypto_unavailable"
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
    val paymentMethods by viewModel.paymentMethods.collectAsStateWithLifecycle()
    val selectedPaymentMethodId by viewModel.selectedPaymentMethodId.collectAsStateWithLifecycle()
    val crypto by viewModel.crypto.collectAsStateWithLifecycle()
    val cryptoFundingMode by viewModel.cryptoFundingMode.collectAsStateWithLifecycle()
    AdsBillingScreen(
        state = state,
        depositState = depositState,
        depositSheetVisible = depositSheetVisible,
        amountText = amountText,
        paymentMethods = paymentMethods,
        selectedPaymentMethodId = selectedPaymentMethodId,
        canSubmitDeposit = viewModel.canSubmitDeposit,
        crypto = crypto,
        cryptoFundingMode = cryptoFundingMode,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onOpenDeposit = viewModel::openDeposit,
        onDismissDeposit = viewModel::dismissDeposit,
        onAmountChanged = viewModel::onAmountChanged,
        onPaymentMethodSelected = viewModel::onPaymentMethodSelected,
        onConfirmDeposit = { viewModel.deposit() },
        onPresetSelected = viewModel::onPresetSelected,
        onCryptoModeChanged = viewModel::setCryptoFundingMode,
        onCryptoAssetSelected = viewModel::onCryptoAssetSelected,
        onConfirmCryptoFund = { viewModel.fundWithCrypto() },
    )
}

/** AND-367 - stateless ads-account billing screen. */
@Composable
fun AdsBillingScreen(
    state: AdsBillingUiState,
    depositState: DepositState,
    depositSheetVisible: Boolean,
    amountText: String,
    paymentMethods: List<PaymentMethod>,
    selectedPaymentMethodId: String?,
    canSubmitDeposit: Boolean,
    crypto: CryptoFundUiState,
    cryptoFundingMode: Boolean,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onOpenDeposit: () -> Unit,
    onDismissDeposit: () -> Unit,
    onAmountChanged: (String) -> Unit,
    onPaymentMethodSelected: (String) -> Unit,
    onConfirmDeposit: () -> Unit,
    onPresetSelected: (Long) -> Unit,
    onCryptoModeChanged: (Boolean) -> Unit,
    onCryptoAssetSelected: (String) -> Unit,
    onConfirmCryptoFund: () -> Unit,
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
            paymentMethods = paymentMethods,
            selectedPaymentMethodId = selectedPaymentMethodId,
            canSubmitDeposit = canSubmitDeposit,
            crypto = crypto,
            cryptoFundingMode = cryptoFundingMode,
            onDismiss = onDismissDeposit,
            onAmountChanged = onAmountChanged,
            onPaymentMethodSelected = onPaymentMethodSelected,
            onConfirm = onConfirmDeposit,
            onPresetSelected = onPresetSelected,
            onCryptoModeChanged = onCryptoModeChanged,
            onCryptoAssetSelected = onCryptoAssetSelected,
            onConfirmCryptoFund = onConfirmCryptoFund,
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
    paymentMethods: List<PaymentMethod>,
    selectedPaymentMethodId: String?,
    canSubmitDeposit: Boolean,
    crypto: CryptoFundUiState,
    cryptoFundingMode: Boolean,
    onDismiss: () -> Unit,
    onAmountChanged: (String) -> Unit,
    onPaymentMethodSelected: (String) -> Unit,
    onConfirm: () -> Unit,
    onPresetSelected: (Long) -> Unit,
    onCryptoModeChanged: (Boolean) -> Unit,
    onCryptoAssetSelected: (String) -> Unit,
    onConfirmCryptoFund: () -> Unit,
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
            val terminal = depositState is DepositState.Success

            // FE-160: Card/wallet vs. Fund-with-crypto selector.
            if (!terminal) {
                TabRow(selectedTabIndex = if (cryptoFundingMode) 1 else 0) {
                    Tab(
                        selected = !cryptoFundingMode,
                        onClick = { if (!submitting) onCryptoModeChanged(false) },
                        text = { Text(stringResource(R.string.fund_tab_card)) },
                        modifier = Modifier.testTag(AdsBillingTestTags.FUND_TAB_CARD),
                    )
                    Tab(
                        selected = cryptoFundingMode,
                        onClick = { if (!submitting) onCryptoModeChanged(true) },
                        text = { Text(stringResource(R.string.fund_tab_crypto)) },
                        modifier = Modifier.testTag(AdsBillingTestTags.FUND_TAB_CRYPTO),
                    )
                }
                PresetTopUps(enabled = !submitting, onPresetSelected = onPresetSelected)
            }

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

            if (cryptoFundingMode) {
                CryptoFundSection(
                    crypto = crypto,
                    enabled = !submitting,
                    onCryptoAssetSelected = onCryptoAssetSelected,
                )
            } else {
                PaymentMethodPicker(
                    paymentMethods = paymentMethods,
                    selectedPaymentMethodId = selectedPaymentMethodId,
                    enabled = !submitting,
                    onSelect = onPaymentMethodSelected,
                )
            }

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

            // ADV3-3 (B8): on a successful deposit swap Confirm for a terminal "Done" that dismisses the
            // sheet, so the completed deposit cannot be accidentally re-submitted from the open sheet.
            if (depositState is DepositState.Success) {
                TlButton(
                    text = stringResource(R.string.deposit_done),
                    onClick = onDismiss,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AdsBillingTestTags.DEPOSIT_DONE),
                )
            } else if (cryptoFundingMode) {
                TlButton(
                    text = stringResource(R.string.fund_crypto_confirm),
                    onClick = onConfirmCryptoFund,
                    enabled = canSubmitDeposit && crypto.canFund && !submitting,
                    loading = submitting,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag(AdsBillingTestTags.CRYPTO_FUND_CONFIRM),
                )
            } else {
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
}

/**
 * ADV-306 - the deposit card picker. When the caller has saved methods it charges a CARD (the deposit posts
 * the selected payment_method_id); with none saved it tells the user the account WALLET is used (the deposit
 * posts no id and the server credits from the wallet).
 */
@Composable
private fun PaymentMethodPicker(
    paymentMethods: List<PaymentMethod>,
    selectedPaymentMethodId: String?,
    enabled: Boolean,
    onSelect: (String) -> Unit,
) {
    if (paymentMethods.isEmpty()) {
        Text(
            text = stringResource(R.string.deposit_payment_method_wallet),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(AdsBillingTestTags.DEPOSIT_PM),
        )
        return
    }
    val selected = paymentMethods.firstOrNull { it.id == selectedPaymentMethodId } ?: paymentMethods.first()
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = selected.pickerLabel(),
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.deposit_payment_method_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            enabled = enabled,
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth()
                .testTag(AdsBillingTestTags.DEPOSIT_PM),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            paymentMethods.forEach { method ->
                DropdownMenuItem(
                    text = { Text(method.pickerLabel()) },
                    onClick = {
                        onSelect(method.id)
                        expanded = false
                    },
                )
            }
        }
    }
}

/** A human label for a saved payment method (custom label, else brand/type + last4, + a default marker). */
private fun PaymentMethod.pickerLabel(): String {
    val head = label?.takeIf { it.isNotBlank() }
        ?: listOfNotNull(
            (rawBrand ?: methodType).replaceFirstChar { it.uppercase() },
            last4?.let { "card ending $it" },
        ).joinToString(" ")
    return if (isDefault) "$head (default)" else head
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


/**
 * FE-160 - quick top-up preset chips ($25 / $50 / $100 / $250). Tapping one fills the amount field
 * (which drives both the card deposit and the crypto quote).
 */
@OptIn(ExperimentalLayoutApi::class)
@Composable
private fun PresetTopUps(enabled: Boolean, onPresetSelected: (Long) -> Unit) {
    FlowRow(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        AdDepositMath.PRESET_TOPUPS_CENTS.forEach { cents ->
            FilterChip(
                selected = false,
                enabled = enabled,
                onClick = { onPresetSelected(cents) },
                label = { Text(AdDepositMath.topUpLabel(cents)) },
            )
        }
    }
}

/**
 * FE-160 - the "Fund with crypto balance" section of the deposit sheet: asset picker from custody
 * balances, the rate-lock display (rate + total coin + conversion fee + live "locked for Ns" countdown),
 * and insufficient / unavailable handling. Mirrors the FE-152 checkout crypto section (CheckoutCryptoMath
 * reused verbatim for the display lines + countdown).
 */
@Composable
private fun CryptoFundSection(
    crypto: CryptoFundUiState,
    enabled: Boolean,
    onCryptoAssetSelected: (String) -> Unit,
) {
    if (!crypto.enabled) {
        Text(
            text = stringResource(R.string.fund_crypto_unavailable),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(AdsBillingTestTags.CRYPTO_UNAVAILABLE),
        )
        return
    }
    if (crypto.assets.isEmpty()) {
        Text(
            text = stringResource(R.string.fund_crypto_no_balance),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        return
    }

    CryptoAssetPicker(
        assets = crypto.assets,
        selectedSymbol = crypto.selectedSymbol,
        enabled = enabled,
        onSelect = onCryptoAssetSelected,
    )

    val quote = crypto.quote
    when {
        crypto.quoting -> Text(
            text = stringResource(R.string.fund_crypto_quoting),
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        quote != null -> {
            LabeledRow(
                label = stringResource(R.string.fund_crypto_rate),
                value = CheckoutCryptoMath.rateLine(quote),
                valueModifier = Modifier.testTag(AdsBillingTestTags.CRYPTO_RATE),
            )
            LabeledRow(
                label = stringResource(R.string.fund_crypto_fee),
                value = CheckoutCryptoMath.feeLine(quote),
            )
            LabeledRow(
                label = stringResource(R.string.fund_crypto_total),
                value = CheckoutCryptoMath.totalLine(quote),
            )
            Text(
                text = CheckoutCryptoMath.lockedForLabel(crypto.secondsRemaining),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.primary,
                modifier = Modifier.testTag(AdsBillingTestTags.CRYPTO_COUNTDOWN),
            )
            if (crypto.insufficient) {
                Text(
                    text = stringResource(R.string.fund_crypto_insufficient),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.testTag(AdsBillingTestTags.CRYPTO_INSUFFICIENT),
                )
            }
        }
    }
    if (crypto.error != null) {
        Text(
            text = crypto.error,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.error,
        )
    }
}

/** FE-160 - the custody-balance asset dropdown for crypto funding. */
@Composable
private fun CryptoAssetPicker(
    assets: List<AdCryptoAssetOption>,
    selectedSymbol: String?,
    enabled: Boolean,
    onSelect: (String) -> Unit,
) {
    val selected = assets.firstOrNull { it.symbol == selectedSymbol }
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { if (enabled) expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = selected?.let { "${it.symbol} - ${it.balanceText} available" }
                ?: stringResource(R.string.fund_crypto_pick_asset),
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.fund_crypto_asset_label)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            enabled = enabled,
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth()
                .testTag(AdsBillingTestTags.CRYPTO_ASSET_PICKER),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            assets.forEach { asset ->
                DropdownMenuItem(
                    text = { Text("${asset.symbol} (${asset.name}) - ${asset.balanceText}") },
                    onClick = {
                        onSelect(asset.symbol)
                        expanded = false
                    },
                )
            }
        }
    }
}
