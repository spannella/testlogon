@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infrahosts

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Dns
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.infrahosts.HostDto
import com.testlogon.android.feature.infracommon.infraErrorMessage
import com.testlogon.android.feature.infracommon.statusColor

object HostInventoryTestTags {
    const val SCREEN = "hosts_screen"
    const val LIST = "hosts_list"
    const val EMPTY = "hosts_empty"
    const val FORBIDDEN = "hosts_forbidden"
    const val ERROR_RETRY = "hosts_error_retry"
    const val FILTER_ALL = "hosts_filter_all"
    fun filter(p: String) = "hosts_filter_$p"
    fun row(id: String) = "hosts_row_$id"
}

@Composable
fun HostInventoryRoute(
    onBack: () -> Unit,
    viewModel: HostInventoryViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    HostInventoryScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onFilter = viewModel::setProtocolFilter,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun HostInventoryScreen(
    state: HostsUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onFilter: (String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(state.transientError) {
        state.transientError?.let {
            snackbar.showSnackbar(infraErrorMessage(it))
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(HostInventoryTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Host inventory") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            if (state.protocols.isNotEmpty() && state.data !is HostsDataState.Forbidden) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .horizontalScroll(rememberScrollState())
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    FilterChip(
                        selected = state.protocolFilter == null,
                        onClick = { onFilter(null) },
                        label = { Text("All") },
                        modifier = Modifier.testTag(HostInventoryTestTags.FILTER_ALL),
                    )
                    state.protocols.forEach { p ->
                        FilterChip(
                            selected = state.protocolFilter == p,
                            onClick = { onFilter(p) },
                            label = { Text(p.uppercase()) },
                            modifier = Modifier.testTag(HostInventoryTestTags.filter(p)),
                        )
                    }
                }
            }
            val isRefreshing = (state.data as? HostsDataState.Content)?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (val d = state.data) {
                    is HostsDataState.Loading -> LoadingState()
                    is HostsDataState.Empty -> EmptyState(
                        modifier = Modifier.testTag(HostInventoryTestTags.EMPTY),
                        title = "No hosts",
                        body = "Your saved connection hosts appear here.",
                        imageVector = Icons.Outlined.Dns,
                    )
                    is HostsDataState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(HostInventoryTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You do not have access to host inventory.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is HostsDataState.Error -> ErrorState(
                        modifier = Modifier.testTag(HostInventoryTestTags.ERROR_RETRY),
                        message = infraErrorMessage(d.type),
                        onRetry = onRetry,
                    )
                    is HostsDataState.Content -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(HostInventoryTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = d.hosts, key = { it.hostId }) { host ->
                            HostRow(host)
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun HostRow(host: HostDto) {
    Card(modifier = Modifier.fillMaxWidth().testTag(HostInventoryTestTags.row(host.hostId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(
                    host.label.ifBlank { host.hostname.ifBlank { host.hostId } },
                    style = MaterialTheme.typography.titleSmall,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                )
                Text(host.protocol.uppercase(), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                if (host.status.isNotBlank() && host.status != "unknown") {
                    Text(host.status, style = MaterialTheme.typography.labelSmall, color = statusColor(host.status))
                }
            }
            val addr = buildString {
                if (host.username.isNotBlank()) append("${host.username}@")
                append(host.hostname)
                if (host.port > 0) append(":${host.port}")
            }
            Text(addr, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (host.group.isNotBlank()) {
                Text("Group: ${host.group}", style = MaterialTheme.typography.bodySmall)
            }
            if (host.connectionCount > 0) {
                Text("${host.connectionCount} connections", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
        }
    }
}
