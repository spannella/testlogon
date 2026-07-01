@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminroot

import android.text.format.DateUtils
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
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
import com.testlogon.android.data.adminroot.AdminRolesRepository
import com.testlogon.android.data.adminroot.RoleAuditEntryDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

object AdminRolesTags {
    const val SCREEN = "admin_roles_screen"
    const val FORBIDDEN = "admin_roles_forbidden"
    const val RETRY = "admin_roles_retry"
    const val FAB = "admin_roles_fab"
}

sealed interface AdminRolesUiState {
    data object Loading : AdminRolesUiState
    data class Content(
        val audit: List<RoleAuditEntryDto>,
        val isRefreshing: Boolean = false,
        val actionMessage: String? = null,
    ) : AdminRolesUiState
    data object Forbidden : AdminRolesUiState
    data class Error(val type: AdminRootErrorType) : AdminRolesUiState
}

@HiltViewModel
class AdminRolesViewModel @Inject constructor(
    private val repo: AdminRolesRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdminRolesUiState>(AdminRolesUiState.Loading)
    val state: StateFlow<AdminRolesUiState> = _state.asStateFlow()

    init { load(reset = true) }

    fun retry() = load(reset = true)

    fun refresh() {
        (_state.value as? AdminRolesUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun grant(targetUserSub: String, reason: String) {
        viewModelScope.launch {
            when (val r = repo.grant(targetUserSub, reason)) {
                is ApiResult.Success -> reloadWith("Granted admin to $targetUserSub")
                else -> setActionMessage(r)
            }
        }
    }

    fun revoke(targetUserSub: String, reason: String) {
        viewModelScope.launch {
            when (val r = repo.revoke(targetUserSub, reason)) {
                is ApiResult.Success -> reloadWith("Revoked admin from $targetUserSub")
                else -> setActionMessage(r)
            }
        }
    }

    private fun reloadWith(message: String) {
        (_state.value as? AdminRolesUiState.Content)?.let { _state.value = it.copy(actionMessage = message) }
        load(reset = false)
    }

    private fun setActionMessage(r: ApiResult<*>) {
        val msg = if (r.isForbidden()) "Root access required." else adminRootErrorMessage(r.adminRootErrorType())
        (_state.value as? AdminRolesUiState.Content)?.let { _state.value = it.copy(actionMessage = msg) }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = AdminRolesUiState.Loading
        viewModelScope.launch {
            when (val r = repo.audit()) {
                is ApiResult.Success -> _state.value = AdminRolesUiState.Content(r.data)
                else -> if (r.isForbidden()) {
                    _state.value = AdminRolesUiState.Forbidden
                } else {
                    _state.value = AdminRolesUiState.Error(r.adminRootErrorType())
                }
            }
        }
    }
}

@Composable
fun AdminRolesRoute(onBack: () -> Unit, viewModel: AdminRolesViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminRolesScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onGrant = viewModel::grant,
        onRevoke = viewModel::revoke,
    )
}

@Composable
fun AdminRolesScreen(
    state: AdminRolesUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onGrant: (String, String) -> Unit,
    onRevoke: (String, String) -> Unit,
) {
    var showDialog by remember { mutableStateOf(false) }
    val branch = when (state) {
        AdminRolesUiState.Loading -> AdminRootBranch.Loading
        AdminRolesUiState.Forbidden -> AdminRootBranch.Forbidden
        is AdminRolesUiState.Error -> AdminRootBranch.Error(state.type)
        is AdminRolesUiState.Content -> AdminRootBranch.Content(state.isRefreshing)
    }
    AdminRootScaffold(
        title = "Role management",
        branch = branch,
        onBack = onBack,
        onRefresh = onRefresh,
        onRetry = onRetry,
        screenTag = AdminRolesTags.SCREEN,
        forbiddenTag = AdminRolesTags.FORBIDDEN,
        retryTag = AdminRolesTags.RETRY,
        forbiddenBody = "Role grants/revokes are root-only. Your account is not authorised.",
        actions = {
            if (state is AdminRolesUiState.Content) {
                FloatingActionButton(
                    onClick = { showDialog = true },
                    modifier = Modifier.padding(end = 8.dp).testTag(AdminRolesTags.FAB),
                ) { Icon(Icons.Filled.PersonAdd, contentDescription = "Grant/revoke role") }
            }
        },
    ) {
        val content = state as AdminRolesUiState.Content
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content.actionMessage?.let { item { Text(it, color = MaterialTheme.colorScheme.primary) } }
            item {
                Text(
                    "Role change history",
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            if (content.audit.isEmpty()) {
                item { Text("No role changes recorded.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(content.audit, key = { it.eventId ?: (it.ts.toString() + it.targetUserSub) }) { e ->
                AdminRootSectionCard(title = (e.action ?: "role change").replace('_', ' ')) {
                    e.targetUserSub?.let { AdminRootStatRow("Target", it) }
                    e.actorSub?.let { AdminRootStatRow("By", it) }
                    if (e.previousRole != null || e.newRole != null) {
                        AdminRootStatRow("Role", "${e.previousRole ?: "?"} -> ${e.newRole ?: "?"}")
                    }
                    e.reason?.takeIf { it.isNotBlank() }?.let { AdminRootStatRow("Reason", it) }
                    e.ts?.takeIf { it > 0 }?.let {
                        AdminRootStatRow(
                            "When",
                            DateUtils.getRelativeTimeSpanString(it * 1000L, System.currentTimeMillis(), DateUtils.MINUTE_IN_MILLIS).toString(),
                        )
                    }
                }
            }
        }
    }
    if (showDialog) {
        RoleActionDialog(
            onDismiss = { showDialog = false },
            onGrant = { sub, reason -> onGrant(sub, reason); showDialog = false },
            onRevoke = { sub, reason -> onRevoke(sub, reason); showDialog = false },
        )
    }
}

@Composable
private fun RoleActionDialog(
    onDismiss: () -> Unit,
    onGrant: (String, String) -> Unit,
    onRevoke: (String, String) -> Unit,
) {
    var sub by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Grant / revoke admin") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = sub, onValueChange = { sub = it }, label = { Text("Target user (email/sub)") }, singleLine = true)
                OutlinedTextField(value = reason, onValueChange = { reason = it }, label = { Text("Reason (optional)") })
            }
        },
        confirmButton = {
            Button(onClick = { onGrant(sub.trim(), reason.trim()) }, enabled = sub.isNotBlank()) { Text("Grant admin") }
        },
        dismissButton = {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = { onRevoke(sub.trim(), reason.trim()) }, enabled = sub.isNotBlank()) { Text("Revoke") }
                TextButton(onClick = onDismiss) { Text("Cancel") }
            }
        },
    )
}
