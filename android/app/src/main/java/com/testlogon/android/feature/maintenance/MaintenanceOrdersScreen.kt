@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.maintenance

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** WOV — stable testTags for the Maintenance Work Orders screen. */
object MaintenanceOrdersTestTags {
    const val SCREEN = "maintenance_orders_screen"
    const val FAB = "maintenance_orders_fab"
    const val RETRY = "maintenance_orders_retry"
    const val CREATE_SUBMIT = "maintenance_create_submit"

    fun row(workOrderId: String): String = "maintenance_order_row_$workOrderId"
}

@Composable
fun MaintenanceOrdersRoute(
    onBack: () -> Unit,
    viewModel: MaintenanceOrdersViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MaintenanceOrdersScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
        onCreate = viewModel::create,
        onTransition = viewModel::transition,
    )
}

@Composable
fun MaintenanceOrdersScreen(
    state: MaintenanceOrdersUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (propertyId: String, title: String, description: String?, priority: WoPriority) -> Unit,
    onTransition: (MaintenanceOrder, WoStatus) -> Unit,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = Modifier.testTag(MaintenanceOrdersTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Work orders") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state !is MaintenanceOrdersUiState.Unavailable) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.testTag(MaintenanceOrdersTestTags.FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "New work order") }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is MaintenanceOrdersUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is MaintenanceOrdersUiState.Unavailable ->
                    CenteredMessage("Work orders aren't enabled for this account.")

                is MaintenanceOrdersUiState.Empty ->
                    CenteredMessage("No work orders yet. Tap + to create one.")

                is MaintenanceOrdersUiState.Error -> Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(state.error.message, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = onRetry, modifier = Modifier.testTag(MaintenanceOrdersTestTags.RETRY)) {
                        Text("Retry")
                    }
                }

                is MaintenanceOrdersUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(state.orders, key = { it.workOrderId }) { order ->
                            OrderRow(order = order, onTransition = onTransition)
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateOrderDialog(
            onDismiss = { showCreate = false },
            onSubmit = { propertyId, title, description, priority ->
                onCreate(propertyId, title, description, priority)
                showCreate = false
            },
        )
    }
}

@Composable
private fun androidx.compose.foundation.layout.BoxScope.CenteredMessage(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.align(Alignment.Center).padding(24.dp),
    )
}

@Composable
private fun OrderRow(order: MaintenanceOrder, onTransition: (MaintenanceOrder, WoStatus) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(MaintenanceOrdersTestTags.row(order.workOrderId)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(order.title, style = MaterialTheme.typography.titleMedium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(statusLabel(order.status)) })
                AssistChip(onClick = {}, label = { Text(priorityLabel(order.priority)) })
            }
            order.description?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            val nexts = allowedTransitions(order.status).toList()
            if (nexts.isNotEmpty()) {
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    nexts.forEach { target ->
                        OutlinedButton(onClick = { onTransition(order, target) }) {
                            Text(statusLabel(target))
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun CreateOrderDialog(
    onDismiss: () -> Unit,
    onSubmit: (propertyId: String, title: String, description: String?, priority: WoPriority) -> Unit,
) {
    var propertyId by remember { mutableStateOf("") }
    var title by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var priority by remember { mutableStateOf(WoPriority.NORMAL) }

    Dialog(onDismissRequest = onDismiss) {
        Card {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New work order", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = propertyId,
                    onValueChange = { propertyId = it },
                    label = { Text("Property ID") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = title,
                    onValueChange = { title = it },
                    label = { Text("Title") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description (optional)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text),
                    modifier = Modifier.fillMaxWidth(),
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    listOf(WoPriority.URGENT, WoPriority.HIGH, WoPriority.NORMAL, WoPriority.LOW)
                        .forEach { p ->
                            FilterChip(
                                selected = priority == p,
                                onClick = { priority = p },
                                label = { Text(priorityLabel(p)) },
                            )
                        }
                }
                androidx.compose.foundation.layout.Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.End,
                ) {
                    TextButton(onClick = onDismiss) { Text("Cancel") }
                    Button(
                        onClick = {
                            onSubmit(
                                propertyId.trim(),
                                title.trim(),
                                description.trim().takeIf { it.isNotBlank() },
                                priority,
                            )
                        },
                        enabled = propertyId.isNotBlank() && title.isNotBlank(),
                        modifier = Modifier.testTag(MaintenanceOrdersTestTags.CREATE_SUBMIT),
                    ) { Text("Create") }
                }
            }
        }
    }
}

private fun statusLabel(s: WoStatus): String = when (s) {
    WoStatus.OPEN -> "Open"
    WoStatus.ASSIGNED -> "Assign"
    WoStatus.IN_PROGRESS -> "Start"
    WoStatus.COMPLETED -> "Complete"
    WoStatus.CANCELLED -> "Cancel"
    WoStatus.UNKNOWN -> "Unknown"
}

private fun priorityLabel(p: WoPriority): String = when (p) {
    WoPriority.URGENT -> "Urgent"
    WoPriority.HIGH -> "High"
    WoPriority.NORMAL -> "Normal"
    WoPriority.LOW -> "Low"
    WoPriority.UNKNOWN -> "—"
}
