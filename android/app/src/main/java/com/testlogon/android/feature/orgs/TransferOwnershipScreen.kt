@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.orgs

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.orgs.OrgMember
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** PAR-35(c) - stable testTags for the transfer-ownership picker. */
object TransferOwnershipTestTags {
    const val SCREEN = "org_transfer_screen"
    const val ROW_PREFIX = "org_transfer_row_"
}

/**
 * PAR-35(c) - route-level transfer-ownership member picker (owner-only; reached from the org overview).
 * On a successful transfer this pops back and signals the caller to reload the overview roles.
 */
@Composable
fun TransferOwnershipRoute(
    onBack: () -> Unit,
    onTransferred: () -> Unit,
    viewModel: TransferOwnershipViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(viewModel) {
        viewModel.events.collect { event ->
            when (event) {
                is TransferOwnershipEvent.Transferred -> onTransferred()
                is TransferOwnershipEvent.Message -> snackbarHostState.showSnackbar(event.text)
            }
        }
    }

    TransferOwnershipScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onPick = viewModel::transferTo,
    )
}

@Composable
fun TransferOwnershipScreen(
    state: TransferOwnershipUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onPick: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var confirmMember by remember { mutableStateOf<OrgMember?>(null) }
    Scaffold(
        modifier = modifier.testTag(TransferOwnershipTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.org_transfer_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.org_transfer_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is TransferOwnershipUiState.Loading -> LoadingState()
                is TransferOwnershipUiState.Empty ->
                    EmptyState(title = stringResource(R.string.org_transfer_empty))
                is TransferOwnershipUiState.Error ->
                    ErrorState(message = state.error.message, onRetry = onRetry)
                is TransferOwnershipUiState.Content ->
                    Column(Modifier.fillMaxSize()) {
                        Text(
                            text = stringResource(R.string.org_transfer_body),
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(16.dp),
                        )
                        LazyColumn(modifier = Modifier.fillMaxSize()) {
                            items(state.candidates, key = { it.userSub }) { member ->
                                TransferRow(
                                    member = member,
                                    inFlight = state.transferringSub == member.userSub,
                                    enabled = state.transferringSub == null,
                                    onClick = { confirmMember = member },
                                )
                            }
                        }
                    }
            }
        }
    }

    val target = confirmMember
    if (target != null) {
        AlertDialog(
            onDismissRequest = { confirmMember = null },
            title = { Text(stringResource(R.string.org_transfer_confirm_title, target.userSub)) },
            text = { Text(stringResource(R.string.org_transfer_confirm_body)) },
            confirmButton = {
                TextButton(onClick = {
                    confirmMember = null
                    onPick(target.userSub)
                }) {
                    Text(stringResource(R.string.org_transfer_confirm_action))
                }
            },
            dismissButton = {
                TextButton(onClick = { confirmMember = null }) {
                    Text(stringResource(R.string.org_transfer_cancel))
                }
            },
        )
    }
}

@Composable
private fun TransferRow(
    member: OrgMember,
    inFlight: Boolean,
    enabled: Boolean,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TransferOwnershipTestTags.ROW_PREFIX + member.userSub)
            .clickable(enabled = enabled, onClick = onClick)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
            Text(
                text = member.userSub,
                style = MaterialTheme.typography.bodyLarge,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = roleLabel(member.role),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        if (inFlight) {
            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
        }
    }
}
