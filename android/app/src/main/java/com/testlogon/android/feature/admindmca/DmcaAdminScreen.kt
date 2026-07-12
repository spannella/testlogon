@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admindmca

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Copyright
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.admindmca.DmcaClaimDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object DmcaAdminTestTags {
    const val SCREEN = "dmca_admin_screen"
    const val LIST = "dmca_admin_list"
    const val EMPTY = "dmca_admin_empty"
    const val FORBIDDEN = "dmca_admin_forbidden"
    const val ERROR_RETRY = "dmca_admin_error_retry"
    fun claim(id: String) = "dmca_claim_$id"
    fun resolve(id: String) = "dmca_resolve_$id"
    const val RESOLVE_CONFIRM = "dmca_resolve_confirm"
    fun resolutionOption(r: String) = "dmca_resolution_$r"
}

@Composable
fun DmcaAdminRoute(
    onBack: () -> Unit,
    viewModel: DmcaAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    DmcaAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onResolve = viewModel::resolve,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun DmcaAdminScreen(
    state: DmcaAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onResolve: (String, String, String?) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var resolveTarget by remember { mutableStateOf<String?>(null) }
    val content = state as? DmcaAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { dmcaErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    Scaffold(
        modifier = modifier.testTag(DmcaAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("DMCA claims") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        val isRefreshing = content?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is DmcaAdminUiState.Loading -> LoadingState()
                is DmcaAdminUiState.Empty -> EmptyState(
                    modifier = Modifier.testTag(DmcaAdminTestTags.EMPTY),
                    title = "No claims",
                    body = "There are no DMCA claims to review.",
                    imageVector = Icons.Outlined.Copyright,
                )
                is DmcaAdminUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(DmcaAdminTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need content-moderation admin access to review DMCA claims.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is DmcaAdminUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(DmcaAdminTestTags.ERROR_RETRY),
                    message = dmcaErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is DmcaAdminUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(DmcaAdminTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = state.claims, key = { it.claimId }) { c ->
                        ClaimRow(
                            claim = c,
                            inFlight = state.actionInFlightId == c.claimId,
                            actionsEnabled = state.actionInFlightId == null,
                            onResolve = { resolveTarget = c.claimId },
                        )
                    }
                }
            }
        }
    }

    resolveTarget?.let { targetId ->
        ResolveDialog(
            onDismiss = { resolveTarget = null },
            onConfirm = { resolution, notes ->
                onResolve(targetId, resolution, notes)
                resolveTarget = null
            },
        )
    }
}

@Composable
private fun ClaimRow(
    claim: DmcaClaimDto,
    inFlight: Boolean,
    actionsEnabled: Boolean,
    onResolve: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(DmcaAdminTestTags.claim(claim.claimId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(claim.claimantName.ifBlank { "Claimant" }, style = MaterialTheme.typography.titleSmall)
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Text(claim.status.ifBlank { "-" }.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary)
                Text("Strike ${claim.strikeNumber}", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                Text(claim.contentType.ifBlank { "-" }, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            if (claim.originalWorkDescription.isNotBlank()) {
                Text(claim.originalWorkDescription, style = MaterialTheme.typography.bodySmall, maxLines = 3, overflow = TextOverflow.Ellipsis)
            }
            if (claim.contentUrl.isNotBlank()) {
                Text(claim.contentUrl, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
            }
            claim.resolution?.takeIf { it.isNotBlank() }?.let {
                Text("Resolution: $it", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.tertiary)
            }
            if (inFlight) {
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
            } else if (claim.resolvedAt == null || claim.resolvedAt == 0L) {
                Button(
                    onClick = onResolve,
                    enabled = actionsEnabled,
                    modifier = Modifier.fillMaxWidth().testTag(DmcaAdminTestTags.resolve(claim.claimId)),
                ) { Text("Resolve") }
            }
        }
    }
}

@Composable
private fun ResolveDialog(onDismiss: () -> Unit, onConfirm: (String, String?) -> Unit) {
    var selected by remember { mutableStateOf(DMCA_RESOLUTIONS.first()) }
    var notes by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Resolve claim") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                DMCA_RESOLUTIONS.forEach { r ->
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .selectable(selected = selected == r, onClick = { selected = r })
                            .testTag(DmcaAdminTestTags.resolutionOption(r)),
                        verticalAlignment = androidx.compose.ui.Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == r, onClick = { selected = r })
                        Text(r.replace('_', ' ').replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(
                    value = notes,
                    onValueChange = { notes = it },
                    label = { Text("Notes (optional)") },
                    modifier = Modifier.fillMaxWidth(),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(selected, notes.ifBlank { null }) },
                modifier = Modifier.testTag(DmcaAdminTestTags.RESOLVE_CONFIRM),
            ) { Text("Confirm") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

internal fun dmcaErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
