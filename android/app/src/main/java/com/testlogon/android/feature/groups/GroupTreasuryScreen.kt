@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.groups.Contributor
import com.testlogon.android.core.model.groups.TreasuryBalance
import com.testlogon.android.core.model.groups.TreasuryLedgerEntry
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-355 (sub-pages) - stable testTags for the group treasury screen. */
object GroupTreasuryTestTags {
    const val SCREEN = "group_treasury_screen"
    const val BALANCE = "group_treasury_balance"
    const val LEDGER_ROW_PREFIX = "group_treasury_ledger_"
}

@Composable
fun GroupTreasuryRoute(
    onBack: () -> Unit,
    viewModel: GroupTreasuryViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupTreasuryScreen(state = state, onBack = onBack, onRetry = viewModel::onRetry)
}

@Composable
fun GroupTreasuryScreen(
    state: GroupTreasuryUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(GroupTreasuryTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_treasury_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is GroupTreasuryUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupTreasuryUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupTreasuryUiState.Content ->
                GroupTreasuryContent(state = state, modifier = Modifier.padding(padding))
        }
    }
}

@Composable
private fun GroupTreasuryContent(
    state: GroupTreasuryUiState.Content,
    modifier: Modifier = Modifier,
) {
    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        item { BalanceCard(state.balance) }

        item {
            Text(
                text = stringResource(R.string.group_treasury_ledger_section),
                style = MaterialTheme.typography.titleMedium,
            )
        }
        if (state.ledger.isEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.group_treasury_ledger_empty),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        } else {
            items(state.ledger, key = { it.entryId }) { entry ->
                LedgerRow(entry)
                HorizontalDivider()
            }
        }

        if (state.contributors.isNotEmpty()) {
            item {
                Text(
                    text = stringResource(R.string.group_treasury_contributors_section),
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            items(state.contributors, key = { it.userId }) { c ->
                ContributorRow(c)
                HorizontalDivider()
            }
        }
    }
}

@Composable
private fun BalanceCard(balance: TreasuryBalance) {
    Card(modifier = Modifier.fillMaxWidth().testTag(GroupTreasuryTestTags.BALANCE)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(
                text = stringResource(R.string.group_treasury_balance_label),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = formatMoney(balance.balanceCents, balance.currency),
                style = MaterialTheme.typography.headlineMedium,
            )
            balance.fundraisingGoalCents?.let { goal ->
                Text(
                    text = stringResource(
                        R.string.group_treasury_goal,
                        formatMoney(goal, balance.currency),
                    ),
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
            Text(
                text = stringResource(
                    R.string.group_treasury_contributed,
                    formatMoney(balance.totalContributedCents, balance.currency),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = stringResource(
                    R.string.group_treasury_spent,
                    formatMoney(balance.totalSpentCents, balance.currency),
                ),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun LedgerRow(entry: TreasuryLedgerEntry) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(GroupTreasuryTestTags.LEDGER_ROW_PREFIX + entry.entryId)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = entry.reason.ifBlank { entry.category.ifBlank { entry.entryId } },
                style = MaterialTheme.typography.bodyLarge,
            )
            val sub = listOfNotNull(
                entry.actorDisplayName ?: entry.actorUserId,
                formatEpochSeconds(entry.createdAt),
            ).joinToString(" - ")
            if (sub.isNotBlank()) {
                Text(
                    text = sub,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
        val sign = if (entry.isDebit) "-" else "+"
        Text(
            text = sign + formatMoney(entry.amountCents, entry.currency),
            style = MaterialTheme.typography.bodyLarge,
            textAlign = TextAlign.End,
            color = if (entry.isDebit) {
                MaterialTheme.colorScheme.error
            } else {
                MaterialTheme.colorScheme.primary
            },
        )
    }
}

@Composable
private fun ContributorRow(c: Contributor) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Text(
            text = c.displayName ?: c.userId,
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = formatMoney(c.totalContributedCents, null),
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}
