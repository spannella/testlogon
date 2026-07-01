@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminroot

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminroot.AdminSsoRepository
import com.testlogon.android.data.adminroot.SsoProviderDto
import com.testlogon.android.data.adminroot.SsoProviderForm
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

object AdminSsoTags {
    const val SCREEN = "admin_sso_screen"
    const val FORBIDDEN = "admin_sso_forbidden"
    const val RETRY = "admin_sso_retry"
    const val FAB = "admin_sso_fab"
    const val ROW = "admin_sso_row"
}

sealed interface AdminSsoUiState {
    data object Loading : AdminSsoUiState
    data class Content(
        val providers: List<SsoProviderDto>,
        val isRefreshing: Boolean = false,
        val actionError: String? = null,
    ) : AdminSsoUiState
    data object Forbidden : AdminSsoUiState
    data class Error(val type: AdminRootErrorType) : AdminSsoUiState
}

@HiltViewModel
class AdminSsoViewModel @Inject constructor(
    private val repo: AdminSsoRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdminSsoUiState>(AdminSsoUiState.Loading)
    val state: StateFlow<AdminSsoUiState> = _state.asStateFlow()

    init { load(reset = true) }

    fun retry() = load(reset = true)

    fun refresh() {
        (_state.value as? AdminSsoUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun create(form: SsoProviderForm) {
        viewModelScope.launch {
            when (val r = repo.create(form)) {
                is ApiResult.Success -> load(reset = false)
                else -> setActionError(r)
            }
        }
    }

    fun delete(providerId: String) {
        viewModelScope.launch {
            when (val r = repo.delete(providerId)) {
                is ApiResult.Success -> load(reset = false)
                else -> setActionError(r)
            }
        }
    }

    private fun setActionError(r: ApiResult<*>) {
        val msg = if (r.isForbidden()) "Root access required." else adminRootErrorMessage(r.adminRootErrorType())
        (_state.value as? AdminSsoUiState.Content)?.let { _state.value = it.copy(actionError = msg) }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = AdminSsoUiState.Loading
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> _state.value = AdminSsoUiState.Content(r.data)
                else -> if (r.isForbidden()) {
                    _state.value = AdminSsoUiState.Forbidden
                } else {
                    _state.value = AdminSsoUiState.Error(r.adminRootErrorType())
                }
            }
        }
    }
}

@Composable
fun AdminSsoRoute(onBack: () -> Unit, viewModel: AdminSsoViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminSsoScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onCreate = viewModel::create,
        onDelete = viewModel::delete,
    )
}

@Composable
fun AdminSsoScreen(
    state: AdminSsoUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onCreate: (SsoProviderForm) -> Unit,
    onDelete: (String) -> Unit,
) {
    var showCreate by remember { mutableStateOf(false) }
    val branch = when (state) {
        AdminSsoUiState.Loading -> AdminRootBranch.Loading
        AdminSsoUiState.Forbidden -> AdminRootBranch.Forbidden
        is AdminSsoUiState.Error -> AdminRootBranch.Error(state.type)
        is AdminSsoUiState.Content -> AdminRootBranch.Content(state.isRefreshing)
    }
    AdminRootScaffold(
        title = "SSO providers",
        branch = branch,
        onBack = onBack,
        onRefresh = onRefresh,
        onRetry = onRetry,
        screenTag = AdminSsoTags.SCREEN,
        forbiddenTag = AdminSsoTags.FORBIDDEN,
        retryTag = AdminSsoTags.RETRY,
        forbiddenBody = "SSO provider administration is root-only. Your account is not authorised.",
        actions = {
            if (state is AdminSsoUiState.Content) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.padding(end = 8.dp).testTag(AdminSsoTags.FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "Add provider") }
            }
        },
    ) {
        val content = state as AdminSsoUiState.Content
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content.actionError?.let { item { Text(it, color = MaterialTheme.colorScheme.error) } }
            if (content.providers.isEmpty()) {
                item { Text("No SSO providers configured.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(content.providers, key = { it.providerId }) { p ->
                AdminRootSectionCard(title = p.displayName.ifBlank { p.providerId }) {
                    AdminRootStatRow("Protocol", p.protocol.uppercase())
                    AdminRootStatRow("Default role", p.defaultRole)
                    AdminRootStatRow("JIT provisioning", if (p.jitProvisioningEnabled) "On" else "Off")
                    AdminRootStatRow("SSO-only", if (p.ssoOnly) "Yes" else "No")
                    p.idpEntityId?.takeIf { it.isNotBlank() }?.let { AdminRootStatRow("IdP entity", it) }
                    if (p.allowedEmailDomains.isNotEmpty()) {
                        AdminRootStatRow("Email domains", p.allowedEmailDomains.joinToString(", "))
                    }
                    Row(modifier = Modifier.fillMaxWidth().testTag(AdminSsoTags.ROW)) {
                        TextButton(onClick = { onDelete(p.providerId) }) { Text("Delete") }
                    }
                }
            }
        }
    }
    if (showCreate) {
        SsoCreateDialog(
            onDismiss = { showCreate = false },
            onConfirm = { form ->
                onCreate(form)
                showCreate = false
            },
        )
    }
}

@Composable
private fun SsoCreateDialog(onDismiss: () -> Unit, onConfirm: (SsoProviderForm) -> Unit) {
    var name by remember { mutableStateOf("") }
    var defaultRole by remember { mutableStateOf("user") }
    var domains by remember { mutableStateOf("") }
    var ssoOnly by remember { mutableStateOf(false) }
    var jit by remember { mutableStateOf(true) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New SSO provider") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Display name") }, singleLine = true)
                OutlinedTextField(value = defaultRole, onValueChange = { defaultRole = it }, label = { Text("Default role") }, singleLine = true)
                OutlinedTextField(
                    value = domains,
                    onValueChange = { domains = it },
                    label = { Text("Allowed email domains (comma-separated)") },
                )
                ToggleRow("JIT provisioning", jit) { jit = it }
                ToggleRow("SSO-only", ssoOnly) { ssoOnly = it }
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onConfirm(
                        SsoProviderForm(
                            displayName = name.trim(),
                            protocol = "saml",
                            defaultRole = defaultRole.trim().ifBlank { "user" },
                            ssoOnly = ssoOnly,
                            jitProvisioningEnabled = jit,
                            autoUpdateProfile = true,
                            autoUpdateRole = false,
                            allowedEmailDomains = domains.split(",").map { it.trim() }.filter { it.isNotBlank() },
                        ),
                    )
                },
                enabled = name.isNotBlank(),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun ToggleRow(label: String, checked: Boolean, onChange: (Boolean) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Switch(checked = checked, onCheckedChange = onChange)
    }
}
