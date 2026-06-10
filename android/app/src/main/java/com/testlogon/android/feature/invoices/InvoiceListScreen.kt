@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.invoices

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.paging.LoadState
import androidx.paging.compose.LazyPagingItems
import androidx.paging.compose.collectAsLazyPagingItems
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.invoices.InvoiceStatus
import com.testlogon.android.data.invoices.InvoiceSummary

/** AND-243 — stable testTags for the invoices list screen. */
object InvoiceListTestTags {
    const val SCREEN = "invoices_screen"
    const val LIST = "invoices_list"
    const val EMPTY = "invoices_empty"
    const val ERROR = "invoices_error"
    const val ROW = "invoice_row"
    const val APPEND_FOOTER = "invoices_append_footer"
    const val APPEND_RETRY = "invoices_append_retry"
}

/** AND-243 — route-level invoices list entry, reachable from billing / the More hub. */
@Composable
fun InvoiceListRoute(
    onInvoiceClick: (invoiceNumber: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: InvoiceListViewModel = hiltViewModel(),
) {
    val invoices = viewModel.invoices.collectAsLazyPagingItems()
    InvoiceListScreen(
        invoices = invoices,
        onInvoiceClick = onInvoiceClick,
        onRefresh = { viewModel.refresh() },
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun InvoiceListScreen(
    invoices: LazyPagingItems<InvoiceSummary>,
    onInvoiceClick: (String) -> Unit,
    onRefresh: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(InvoiceListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.invoices_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack, modifier = Modifier.testTag("invoices_back")) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        val refreshState = invoices.loadState.refresh
        Box(Modifier.fillMaxSize().padding(padding)) {
            when {
                refreshState is LoadState.Loading && invoices.itemCount == 0 ->
                    LoadingState(message = stringResource(R.string.invoices_loading))

                refreshState is LoadState.Error && invoices.itemCount == 0 -> {
                    val message = (refreshState.error as? InvoicesLoadException)?.message
                        ?: stringResource(R.string.invoices_error_generic)
                    ErrorState(
                        message = message,
                        onRetry = invoices::retry,
                        modifier = Modifier.testTag(InvoiceListTestTags.ERROR),
                    )
                }

                refreshState is LoadState.NotLoading && invoices.itemCount == 0 ->
                    EmptyState(
                        title = stringResource(R.string.invoices_empty),
                        modifier = Modifier.testTag(InvoiceListTestTags.EMPTY),
                    )

                else -> InvoicesList(invoices = invoices, onRefresh = onRefresh, onInvoiceClick = onInvoiceClick)
            }
        }
    }
}

@Composable
private fun InvoicesList(
    invoices: LazyPagingItems<InvoiceSummary>,
    onRefresh: () -> Unit,
    onInvoiceClick: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = invoices.loadState.refresh is LoadState.Loading && invoices.itemCount > 0,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        LazyColumn(modifier = Modifier.fillMaxSize().testTag(InvoiceListTestTags.LIST)) {
            items(
                count = invoices.itemCount,
                key = { index -> invoices.peek(index)?.invoiceNumber ?: index },
            ) { index ->
                val invoice = invoices[index]
                if (invoice != null) {
                    InvoiceRow(invoice = invoice, onClick = { onInvoiceClick(invoice.invoiceNumber) })
                }
            }

            when (invoices.loadState.append) {
                is LoadState.Loading -> item {
                    Box(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(InvoiceListTestTags.APPEND_FOOTER),
                        contentAlignment = Alignment.Center,
                    ) {
                        CircularProgressIndicator(modifier = Modifier.size(24.dp))
                    }
                }
                is LoadState.Error -> item {
                    Row(
                        Modifier.fillMaxWidth().padding(16.dp).testTag(InvoiceListTestTags.APPEND_FOOTER),
                        horizontalArrangement = Arrangement.Center,
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(
                            stringResource(R.string.invoices_append_error),
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        TextButton(
                            onClick = invoices::retry,
                            modifier = Modifier.testTag(InvoiceListTestTags.APPEND_RETRY),
                        ) { Text(stringResource(R.string.action_retry)) }
                    }
                }
                else -> Unit
            }
        }
    }
}

@Composable
private fun InvoiceRow(invoice: InvoiceSummary, onClick: () -> Unit) {
    val dateText = formatInvoiceDate(invoice.createdAtEpochSeconds)
        ?: stringResource(R.string.invoices_date_unknown)
    val totalText = formatInvoiceMoney(invoice.total)
    val cd = buildString {
        append(invoice.invoiceNumber)
        append(", "); append(dateText)
        append(", "); append(totalText)
        if (invoice.status == InvoiceStatus.EMAILED) {
            append(", "); append(stringResource(R.string.invoices_status_emailed))
        }
    }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 56.dp)
            .clickable(onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(InvoiceListTestTags.ROW)
            .clearAndSetSemantics { contentDescription = cd },
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = invoice.invoiceNumber,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = "$dateText · ${invoice.invoiceType}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        if (invoice.status == InvoiceStatus.EMAILED) {
            AssistChip(
                onClick = onClick,
                label = { Text(stringResource(R.string.invoices_status_emailed)) },
                colors = AssistChipDefaults.assistChipColors(),
                modifier = Modifier.padding(end = 8.dp),
            )
        }
        Text(text = totalText, style = MaterialTheme.typography.bodyLarge)
    }
}
