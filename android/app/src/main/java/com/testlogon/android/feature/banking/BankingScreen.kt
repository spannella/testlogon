@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.banking

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.banking.BankAccount
import com.testlogon.android.data.banking.BankTransaction

// ─── Accounts list ─────────────────────────────────────────────────────────────

/** Route-level linked-accounts list (reached from the More -> Wallet hub). */
@Composable
fun BankingAccountsRoute(
    onBack: () -> Unit,
    onOpenAccount: (String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BankingViewModel = hiltViewModel(),
) {
    val state by viewModel.accounts.collectAsStateWithLifecycle()
    LaunchedEffect(Unit) { viewModel.loadAccounts() }
    BankingAccountsScreen(state = state, onBack = onBack, onOpenAccount = onOpenAccount, modifier = modifier)
}

@Composable
fun BankingAccountsScreen(
    state: AccountsUiState,
    onBack: () -> Unit,
    onOpenAccount: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Banking accounts") },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { padding ->
        val accounts = state.accounts.data
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.accounts.loading && accounts == null -> CenteredProgress()
                state.accounts.error != null -> CenteredMessage(state.accounts.error)
                state.unavailable -> UnavailableState(
                    "Banking is not available",
                    "Linked bank accounts are not enabled for this account yet.",
                )
                accounts.isNullOrEmpty() -> UnavailableState(
                    "No linked accounts",
                    "You have not linked any bank accounts yet.",
                )
                else -> LazyColumn(Modifier.fillMaxSize()) {
                    items(accounts, key = { it.accountId }) { acc ->
                        AccountRow(acc, onClick = { onOpenAccount(acc.accountId) })
                        HorizontalDivider()
                    }
                }
            }
        }
    }
}

@Composable
private fun AccountRow(account: BankAccount, onClick: () -> Unit) {
    Column(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(16.dp),
    ) {
        Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
            Text(account.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            if (account.isDefault) {
                Spacer(Modifier.width(8.dp))
                AssistChip(onClick = {}, label = { Text("Default") })
            }
        }
        val subtitle = BankingMath.accountSubtitle(account.accountNumberMasked, account.iban, account.routingNumber)
        if (subtitle != null) {
            Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        }
        Text(
            "${account.accountType} · ${account.currency.uppercase()}",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

// ─── Account detail + transactions ─────────────────────────────────────────────

@Composable
fun BankingAccountDetailRoute(
    accountId: String,
    onBack: () -> Unit,
    onOpenTransaction: (String, String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BankingViewModel = hiltViewModel(),
) {
    val state by viewModel.detail.collectAsStateWithLifecycle()
    LaunchedEffect(accountId) { viewModel.loadDetail(accountId) }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text(state.account.data?.label ?: "Account") },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                state.account.loading && state.account.data == null -> CenteredProgress()
                state.account.error != null && state.account.data == null -> CenteredMessage(state.account.error)
                else -> LazyColumn(Modifier.fillMaxSize()) {
                    item {
                        BalanceCard(state)
                        Text(
                            "Transactions",
                            style = MaterialTheme.typography.titleMedium,
                            fontWeight = FontWeight.SemiBold,
                            modifier = Modifier.padding(16.dp),
                        )
                    }
                    val txns = state.transactions.data
                    if (state.transactions.loading && txns == null) {
                        item { CenteredProgress() }
                    } else if (state.txnUnavailable) {
                        item { UnavailableState("Transactions unavailable", "Transaction history is not enabled for this account.") }
                    } else if (txns.isNullOrEmpty()) {
                        item { UnavailableState("No transactions", "This account has no posted transactions yet.") }
                    } else {
                        items(txns, key = { it.transactionId }) { txn ->
                            TransactionRow(txn, onClick = { onOpenTransaction(state.accountId, txn.transactionId) })
                            HorizontalDivider()
                        }
                        if (state.cursor != null) {
                            item {
                                Box(Modifier.fillMaxWidth().padding(16.dp), contentAlignment = Alignment.Center) {
                                    OutlinedButton(onClick = { viewModel.loadMoreTransactions() }, enabled = !state.loadingMore) {
                                        Text(if (state.loadingMore) "Loading…" else "Load more")
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun BalanceCard(state: AccountDetailUiState) {
    Card(Modifier.fillMaxWidth().padding(16.dp)) {
        Column(Modifier.padding(16.dp)) {
            Text("Current balance", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            val bal = state.balance.data
            when {
                state.balance.loading && bal == null -> Text("…", style = MaterialTheme.typography.headlineSmall)
                bal != null -> {
                    Text(
                        BankingMath.formatBalance(bal.current, bal.currency),
                        style = MaterialTheme.typography.headlineSmall,
                        fontWeight = FontWeight.Bold,
                    )
                    Text(
                        "Available ${BankingMath.formatBalance(bal.available, bal.currency)}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                else -> Text("Balance unavailable", style = MaterialTheme.typography.bodyMedium)
            }
            val acc = state.account.data
            if (acc != null) {
                val subtitle = BankingMath.accountSubtitle(acc.accountNumberMasked, acc.iban, acc.routingNumber)
                if (subtitle != null) {
                    Spacer(Modifier.height(8.dp))
                    Text(subtitle, style = MaterialTheme.typography.bodySmall)
                }
            }
        }
    }
}

@Composable
private fun TransactionRow(txn: BankTransaction, onClick: () -> Unit) {
    Row(
        Modifier.fillMaxWidth().clickable(onClick = onClick).padding(16.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(Modifier.weight(1f)) {
            Text(txn.description.ifEmpty { txn.type }, style = MaterialTheme.typography.bodyLarge)
            Text(
                "${txn.status}${if (txn.hasMetadata) " · noted" else ""}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val debit = BankingMath.isDebit(txn.amount.value)
        Text(
            BankingMath.formatTxnAmount(txn.amount.value, txn.amount.currency),
            style = MaterialTheme.typography.bodyLarge,
            fontWeight = FontWeight.SemiBold,
            color = if (debit) MaterialTheme.colorScheme.error else MaterialTheme.colorScheme.primary,
        )
    }
}

// ─── Transaction metadata editing ──────────────────────────────────────────────

@Composable
fun BankingTransactionRoute(
    accountId: String,
    transactionId: String,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: BankingViewModel = hiltViewModel(),
) {
    val state by viewModel.metadata.collectAsStateWithLifecycle()
    LaunchedEffect(accountId, transactionId) { viewModel.loadTransaction(accountId, transactionId) }
    Scaffold(
        modifier = modifier,
        topBar = {
            TopAppBar(
                title = { Text("Transaction") },
                navigationIcon = { BackButton(onBack) },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            val txn = state.transaction.data
            if (txn != null) {
                Card(Modifier.fillMaxWidth().padding(16.dp)) {
                    Column(Modifier.padding(16.dp)) {
                        Text(txn.description.ifEmpty { txn.type }, style = MaterialTheme.typography.titleMedium)
                        Text(
                            BankingMath.formatTxnAmount(txn.amount.value, txn.amount.currency),
                            style = MaterialTheme.typography.headlineSmall,
                            fontWeight = FontWeight.Bold,
                        )
                        Text(txn.status, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }
            }
            if (state.mutationError != null) {
                Text(
                    state.mutationError!!,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall,
                    modifier = Modifier.padding(horizontal = 16.dp),
                )
            }
            LazyColumn(Modifier.fillMaxSize()) {
                item { NarrativeSection(state, viewModel) }
                item { TagsSection(state, viewModel) }
                item { CommentsSection(state, viewModel) }
            }
        }
    }
}

@Composable
private fun NarrativeSection(state: TxnMetadataUiState, viewModel: BankingViewModel) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Text("Narrative", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        OutlinedTextField(
            value = state.narrativeDraft,
            onValueChange = viewModel::onNarrativeDraftChange,
            label = { Text("Add a note") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { viewModel.saveNarrative() }, enabled = state.canSaveNarrative) {
            Text(if (state.savingNarrative) "Saving…" else "Save narrative")
        }
    }
    HorizontalDivider()
}

@Composable
private fun TagsSection(state: TxnMetadataUiState, viewModel: BankingViewModel) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Text("Tags", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        val tags = state.metadata.data?.tags.orEmpty()
        if (tags.isNotEmpty()) {
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                tags.forEach { tag ->
                    AssistChip(
                        onClick = { viewModel.removeTag(tag.tagId) },
                        label = { Text(tag.value) },
                        trailingIcon = { Icon(Icons.Filled.Close, contentDescription = "Remove tag") },
                    )
                }
            }
        }
        OutlinedTextField(
            value = state.tagDraft,
            onValueChange = viewModel::onTagDraftChange,
            label = { Text("Add a tag") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { viewModel.addTag() }, enabled = state.canAddTag) {
            Text(if (state.addingTag) "Adding…" else "Add tag")
        }
    }
    HorizontalDivider()
}

@Composable
private fun CommentsSection(state: TxnMetadataUiState, viewModel: BankingViewModel) {
    Column(Modifier.fillMaxWidth().padding(16.dp)) {
        Text("Comments", style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        state.metadata.data?.comments.orEmpty().forEach { comment ->
            Row(Modifier.fillMaxWidth().padding(vertical = 4.dp), verticalAlignment = Alignment.CenterVertically) {
                Text(comment.text, Modifier.weight(1f), style = MaterialTheme.typography.bodyMedium)
                IconButton(onClick = { viewModel.deleteComment(comment.commentId) }) {
                    Icon(Icons.Filled.Close, contentDescription = "Delete comment")
                }
            }
        }
        OutlinedTextField(
            value = state.commentDraft,
            onValueChange = viewModel::onCommentDraftChange,
            label = { Text("Add a comment") },
            modifier = Modifier.fillMaxWidth(),
        )
        Spacer(Modifier.height(8.dp))
        Button(onClick = { viewModel.addComment() }, enabled = state.canAddComment) {
            Text(if (state.addingComment) "Adding…" else "Add comment")
        }
    }
}

// ─── Shared bits ────────────────────────────────────────────────────────────────

@Composable
private fun BackButton(onBack: () -> Unit) {
    IconButton(onClick = onBack) {
        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
    }
}

@Composable
private fun CenteredProgress() {
    Box(Modifier.fillMaxWidth().padding(32.dp), contentAlignment = Alignment.Center) {
        CircularProgressIndicator()
    }
}

@Composable
private fun CenteredMessage(text: String?) {
    Box(Modifier.fillMaxSize().padding(32.dp), contentAlignment = Alignment.Center) {
        Text(text ?: "Something went wrong", style = MaterialTheme.typography.bodyMedium)
    }
}

@Composable
private fun UnavailableState(title: String, body: String) {
    Column(
        Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(body, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

