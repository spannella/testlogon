package com.testlogon.android.feature.billing.wallet

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.ReceiptLong
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.i18n.asString
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.billing.BillingBalance
import com.testlogon.android.data.billing.BillingMoney
import com.testlogon.android.data.billing.LedgerEntry
import com.testlogon.android.data.billing.WalletBalance
import java.util.Locale

/** PW18 — stable testTags for the Wallet transactions screen. */
object WalletTransactionsTestTags {
    const val SCREEN = "wallet_transactions_screen"
    const val BALANCE = "wallet_transactions_balance"
    const val ACCOUNT_BALANCE = "wallet_account_balance"
    const val LIST = "wallet_transactions_list"
    const val ROW = "wallet_transactions_row"
    const val EMPTY = "wallet_transactions_empty"
    const val ERROR = "wallet_transactions_error"
}

/** PW18 — route-level Wallet transactions entry, reached from the Wallet hub. */
@Composable
fun WalletTransactionsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: WalletTransactionsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    WalletTransactionsScreen(
        state = state,
        onRetry = viewModel::retry,
        onBack = onBack,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletTransactionsScreen(
    state: WalletTransactionsUiState,
    onRetry: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(WalletTransactionsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.wallet_transactions_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("wallet_transactions_back")) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = stringResource(R.string.action_back))
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (val load = state.load) {
                is WalletTransactionsLoadState.Loading -> LoadingState()

                is WalletTransactionsLoadState.Error -> ErrorState(
                    message = load.message.asString(),
                    onRetry = onRetry,
                    modifier = Modifier.testTag(WalletTransactionsTestTags.ERROR),
                )

                is WalletTransactionsLoadState.Loaded -> Column(Modifier.fillMaxSize()) {
                    state.wallet?.let { WalletBalanceHeader(it) }
                    // PAR-20: account-balance breakdown between the header and the ledger (best-effort).
                    state.balance?.let { AccountBalanceSection(it) }
                    if (load.transactions.isEmpty()) {
                        EmptyState(
                            title = stringResource(R.string.wallet_transactions_empty_title),
                            body = stringResource(R.string.wallet_transactions_empty_body),
                            imageVector = Icons.Outlined.ReceiptLong,
                            modifier = Modifier.testTag(WalletTransactionsTestTags.EMPTY),
                        )
                    } else {
                        TransactionsList(load.transactions)
                    }
                }
            }
        }
    }
}

@Composable
private fun WalletBalanceHeader(wallet: WalletBalance) {
    val locale = Locale.getDefault()
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(16.dp)
            .testTag(WalletTransactionsTestTags.BALANCE),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                stringResource(R.string.wallet_transactions_balance_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                formatWalletMoney(wallet.balance, locale),
                style = MaterialTheme.typography.headlineSmall,
            )
        }
    }
}

/**
 * PAR-20 — the "Account balance" breakdown. Rows, in order: Amount due, Pending due, Owed (settled),
 * Owed (pending), Paid (settled), Paid (pending). The two `due*` rows are OMITTED when null (parity
 * with the iOS WalletScreen). Money is rendered via the shared integer-cents [formatWalletMoney].
 */
@Composable
private fun AccountBalanceSection(balance: BillingBalance) {
    val locale = Locale.getDefault()
    Card(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 16.dp)
            .padding(bottom = 16.dp)
            .testTag(WalletTransactionsTestTags.ACCOUNT_BALANCE),
    ) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                stringResource(R.string.wallet_balance_section_title),
                style = MaterialTheme.typography.titleMedium,
            )
            balance.dueSettled?.let {
                AccountBalanceRow(stringResource(R.string.wallet_balance_amount_due), it, locale)
            }
            balance.duePending?.let {
                AccountBalanceRow(stringResource(R.string.wallet_balance_pending_due), it, locale)
            }
            AccountBalanceRow(stringResource(R.string.wallet_balance_owed_settled), balance.owedSettled, locale)
            AccountBalanceRow(stringResource(R.string.wallet_balance_owed_pending), balance.owedPending, locale)
            AccountBalanceRow(stringResource(R.string.wallet_balance_paid_settled), balance.paymentsSettled, locale)
            AccountBalanceRow(stringResource(R.string.wallet_balance_paid_pending), balance.paymentsPending, locale)
        }
    }
}

@Composable
private fun AccountBalanceRow(label: String, money: BillingMoney, locale: Locale) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Text(
            formatWalletMoney(money, locale),
            style = MaterialTheme.typography.bodyMedium,
            textAlign = TextAlign.End,
            modifier = Modifier.padding(start = 16.dp),
        )
    }
}

@Composable
private fun TransactionsList(transactions: List<LedgerEntry>) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(WalletTransactionsTestTags.LIST),
    ) {
        itemsIndexed(transactions, key = { index, item -> "${item.sk}#$index" }) { _, entry ->
            TransactionRow(entry)
            HorizontalDivider()
        }
    }
}

@Composable
private fun TransactionRow(entry: LedgerEntry) {
    val locale = Locale.getDefault()
    val date = formatLedgerDate(entry.timestampEpochSeconds, locale)
    val title = entry.reason?.takeIf { it.isNotBlank() }
        ?: stringResource(R.string.wallet_transactions_default_reason)
    val isCredit = entry.type.equals("credit", ignoreCase = true)
    val amountColor =
        if (isCredit) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(WalletTransactionsTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(
            modifier = Modifier.weight(1f),
            verticalArrangement = Arrangement.spacedBy(2.dp),
        ) {
            Text(title, style = MaterialTheme.typography.titleSmall)
            val meta = listOfNotNull(date, entry.state.replaceFirstChar { it.uppercase() })
                .joinToString(" · ")
            if (meta.isNotBlank()) {
                Text(
                    meta,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        Text(
            text = formatLedgerAmount(entry.type, entry.amount, locale),
            style = MaterialTheme.typography.titleSmall,
            color = amountColor,
            textAlign = TextAlign.End,
            modifier = Modifier.padding(start = 12.dp),
        )
    }
}
