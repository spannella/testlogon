@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminroot

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminroot.AdminTenantsRepository
import com.testlogon.android.data.adminroot.TenantDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

object AdminTenantsTags {
    const val SCREEN = "admin_tenants_screen"
    const val FORBIDDEN = "admin_tenants_forbidden"
    const val RETRY = "admin_tenants_retry"
    const val ROW = "admin_tenants_row"
    const val FAB = "admin_tenants_fab"
}

sealed interface AdminTenantsUiState {
    data object Loading : AdminTenantsUiState
    data class Content(
        val tenants: List<TenantDto>,
        val isRefreshing: Boolean = false,
        val actionError: String? = null,
    ) : AdminTenantsUiState
    data object Forbidden : AdminTenantsUiState
    data class Error(val type: AdminRootErrorType) : AdminTenantsUiState
}

@HiltViewModel
class AdminTenantsViewModel @Inject constructor(
    private val repo: AdminTenantsRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdminTenantsUiState>(AdminTenantsUiState.Loading)
    val state: StateFlow<AdminTenantsUiState> = _state.asStateFlow()

    init { load(reset = true) }

    fun retry() = load(reset = true)

    fun refresh() {
        (_state.value as? AdminTenantsUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun create(slug: String, displayName: String, plan: String, primaryDomain: String?) {
        viewModelScope.launch {
            when (val r = repo.create(slug, displayName, plan, primaryDomain.takeIf { !it.isNullOrBlank() })) {
                is ApiResult.Success -> load(reset = false)
                else -> setActionError(r)
            }
        }
    }

    fun updateStatus(tenantId: String, status: String) {
        viewModelScope.launch {
            when (val r = repo.update(tenantId, null, null, status)) {
                is ApiResult.Success -> load(reset = false)
                else -> setActionError(r)
            }
        }
    }

    fun delete(tenantId: String) {
        viewModelScope.launch {
            when (val r = repo.delete(tenantId)) {
                is ApiResult.Success -> load(reset = false)
                else -> setActionError(r)
            }
        }
    }

    private fun setActionError(r: ApiResult<*>) {
        val msg = if (r.isForbidden()) "Root access required." else adminRootErrorMessage(r.adminRootErrorType())
        (_state.value as? AdminTenantsUiState.Content)?.let { _state.value = it.copy(actionError = msg) }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = AdminTenantsUiState.Loading
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> _state.value = AdminTenantsUiState.Content(r.data)
                else -> if (r.isForbidden()) {
                    _state.value = AdminTenantsUiState.Forbidden
                } else {
                    _state.value = AdminTenantsUiState.Error(r.adminRootErrorType())
                }
            }
        }
    }
}

@Composable
fun AdminTenantsRoute(onBack: () -> Unit, viewModel: AdminTenantsViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminTenantsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onCreate = viewModel::create,
        onArchive = { id -> viewModel.updateStatus(id, "suspended") },
        onDelete = viewModel::delete,
    )
}

@Composable
fun AdminTenantsScreen(
    state: AdminTenantsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onCreate: (slug: String, displayName: String, plan: String, primaryDomain: String?) -> Unit,
    onArchive: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    var showCreate by remember { mutableStateOf(false) }
    val branch = when (state) {
        AdminTenantsUiState.Loading -> AdminRootBranch.Loading
        AdminTenantsUiState.Forbidden -> AdminRootBranch.Forbidden
        is AdminTenantsUiState.Error -> AdminRootBranch.Error(state.type)
        is AdminTenantsUiState.Content -> AdminRootBranch.Content(state.isRefreshing)
    }
    AdminRootScaffold(
        title = "Tenants",
        branch = branch,
        onBack = onBack,
        onRefresh = onRefresh,
        onRetry = onRetry,
        screenTag = AdminTenantsTags.SCREEN,
        forbiddenTag = AdminTenantsTags.FORBIDDEN,
        retryTag = AdminTenantsTags.RETRY,
        forbiddenBody = "Tenant administration is root-only. Your account is not authorised.",
        actions = {
            if (state is AdminTenantsUiState.Content) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.padding(end = 8.dp).testTag(AdminTenantsTags.FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "Add tenant") }
            }
        },
    ) {
        val content = state as AdminTenantsUiState.Content
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content.actionError?.let { item { Text(it, color = MaterialTheme.colorScheme.error) } }
            if (content.tenants.isEmpty()) {
                item { Text("No tenants yet.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(content.tenants, key = { it.tenantId }) { t ->
                AdminRootSectionCard(title = t.displayName.ifBlank { t.slug }) {
                    AdminRootStatRow("Slug", t.slug)
                    AdminRootStatRow("Plan", t.plan)
                    AdminRootStatRow("Status", t.status)
                    AdminRootStatRow("Members", t.memberCount.toString())
                    if (t.customDomains.isNotEmpty()) {
                        AdminRootStatRow("Domains", t.customDomains.joinToString(", "))
                    }
                    androidx.compose.foundation.layout.Row(
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                        modifier = Modifier.fillMaxWidth().testTag(AdminTenantsTags.ROW),
                    ) {
                        TextButton(onClick = { onArchive(t.tenantId) }) { Text("Suspend") }
                        TextButton(onClick = { onDelete(t.tenantId) }) { Text("Delete") }
                    }
                }
            }
        }
    }
    if (showCreate) {
        TenantCreateDialog(
            onDismiss = { showCreate = false },
            onConfirm = { slug, name, plan, domain ->
                onCreate(slug, name, plan, domain)
                showCreate = false
            },
        )
    }
}

@Composable
private fun TenantCreateDialog(
    onDismiss: () -> Unit,
    onConfirm: (slug: String, displayName: String, plan: String, primaryDomain: String?) -> Unit,
) {
    var slug by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var plan by remember { mutableStateOf("starter") }
    var domain by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New tenant") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = slug, onValueChange = { slug = it }, label = { Text("Slug") }, singleLine = true)
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Display name") }, singleLine = true)
                PlanDropdown(plan = plan, onPlan = { plan = it })
                OutlinedTextField(value = domain, onValueChange = { domain = it }, label = { Text("Primary domain (optional)") }, singleLine = true)
            }
        },
        confirmButton = {
            Button(
                onClick = { onConfirm(slug.trim(), name.trim(), plan, domain.trim()) },
                enabled = slug.isNotBlank() && name.isNotBlank(),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun PlanDropdown(plan: String, onPlan: (String) -> Unit) {
    val options = listOf("free", "starter", "enterprise")
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = plan,
            onValueChange = {},
            readOnly = true,
            label = { Text("Plan") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { opt ->
                DropdownMenuItem(text = { Text(opt) }, onClick = { onPlan(opt); expanded = false })
            }
        }
    }
}
