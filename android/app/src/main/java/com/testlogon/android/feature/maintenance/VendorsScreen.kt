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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle

/** WOV-004 — stable testTags for the Maintenance Vendors screen. */
object VendorsTestTags {
    const val SCREEN = "maintenance_vendors_screen"
    const val FAB = "maintenance_vendors_fab"
    const val RETRY = "maintenance_vendors_retry"
    const val CREATE_SUBMIT = "maintenance_vendor_create_submit"

    fun row(vendorId: String): String = "maintenance_vendor_row_$vendorId"
}

@Composable
fun VendorsRoute(
    onBack: () -> Unit,
    viewModel: VendorsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val categories by viewModel.categories.collectAsStateWithLifecycle()
    VendorsScreen(
        state = state,
        categories = categories,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::load,
        onCreate = viewModel::createVendor,
        onToggleStatus = viewModel::toggleStatus,
    )
}

@Composable
fun VendorsScreen(
    state: VendorsUiState,
    categories: List<String>,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (name: String, tradeCategory: String, email: String?, phone: String?) -> Unit,
    onToggleStatus: (Vendor) -> Unit,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = Modifier.testTag(VendorsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Vendors") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (state !is VendorsUiState.Unavailable) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.testTag(VendorsTestTags.FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "New vendor") }
            }
        },
    ) { padding ->
        Box(Modifier.padding(padding).fillMaxSize()) {
            when (state) {
                is VendorsUiState.Loading ->
                    CircularProgressIndicator(Modifier.align(Alignment.Center))

                is VendorsUiState.Unavailable ->
                    CenteredVendorMessage("Vendors aren't enabled for this account.")

                is VendorsUiState.Empty ->
                    CenteredVendorMessage("No vendors yet. Tap + to add one.")

                is VendorsUiState.Error -> Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally,
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text(state.error.message, style = MaterialTheme.typography.bodyMedium)
                    Button(onClick = onRetry, modifier = Modifier.testTag(VendorsTestTags.RETRY)) {
                        Text("Retry")
                    }
                }

                is VendorsUiState.Content -> PullToRefreshBox(
                    isRefreshing = state.isRefreshing,
                    onRefresh = onRefresh,
                ) {
                    LazyColumn(
                        modifier = Modifier.fillMaxSize().padding(horizontal = 16.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        items(state.vendors, key = { it.vendorId }) { vendor ->
                            VendorRow(vendor = vendor, onToggleStatus = onToggleStatus)
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateVendorDialog(
            categories = categories,
            onDismiss = { showCreate = false },
            onSubmit = { name, category, email, phone ->
                onCreate(name, category, email, phone)
                showCreate = false
            },
        )
    }
}

@Composable
private fun androidx.compose.foundation.layout.BoxScope.CenteredVendorMessage(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier.align(Alignment.Center).padding(24.dp),
    )
}

@Composable
private fun VendorRow(vendor: Vendor, onToggleStatus: (Vendor) -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth().testTag(VendorsTestTags.row(vendor.vendorId)),
    ) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(vendor.name, style = MaterialTheme.typography.titleMedium)
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                AssistChip(onClick = {}, label = { Text(vendorStatusLabel(vendor.status)) })
                AssistChip(onClick = {}, label = { Text(vendor.tradeCategory) })
            }
            vendor.email?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodyMedium)
            }
            if (canSetVendorStatus(vendor.status, vendor.status.toggleTarget)) {
                OutlinedButton(onClick = { onToggleStatus(vendor) }) {
                    Text(vendorToggleActionLabel(vendor.status))
                }
            }
        }
    }
}

@Composable
private fun CreateVendorDialog(
    categories: List<String>,
    onDismiss: () -> Unit,
    onSubmit: (name: String, tradeCategory: String, email: String?, phone: String?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var email by remember { mutableStateOf("") }
    var phone by remember { mutableStateOf("") }
    var category by remember { mutableStateOf(categories.firstOrNull() ?: "general") }

    Dialog(onDismissRequest = onDismiss) {
        Card {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("New vendor", style = MaterialTheme.typography.titleLarge)
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = email,
                    onValueChange = { email = it },
                    label = { Text("Email (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = phone,
                    onValueChange = { phone = it },
                    label = { Text("Phone (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    categories.forEach { c ->
                        FilterChip(
                            selected = category == c,
                            onClick = { category = c },
                            label = { Text(c) },
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
                                name.trim(),
                                category,
                                email.trim().takeIf { it.isNotBlank() },
                                phone.trim().takeIf { it.isNotBlank() },
                            )
                        },
                        enabled = name.isNotBlank() && category.isNotBlank(),
                        modifier = Modifier.testTag(VendorsTestTags.CREATE_SUBMIT),
                    ) { Text("Add") }
                }
            }
        }
    }
}
