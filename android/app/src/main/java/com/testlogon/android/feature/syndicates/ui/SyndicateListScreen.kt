@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.syndicates.ui

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.syndicates.SyndicateListItem
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import kotlinx.coroutines.flow.collectLatest

/** Batch-7 - stable testTags for the syndicate list + create flow. */
object SyndicateListTestTags {
    const val SCREEN = "syndicates_list_screen"
    const val ROW_PREFIX = "syndicate_row_"
    const val CREATE_FAB = "syndicates_create_fab"
    const val CREATE_DIALOG = "syndicate_create_dialog"
    const val CREATE_NAME = "syndicate_create_name"
    const val CREATE_DESCRIPTION = "syndicate_create_description"
    const val CREATE_SUBMIT = "syndicate_create_submit"
}

/** Batch-7 - route-level "my syndicates" list entry (the More-hub landing). */
@Composable
fun SyndicateListRoute(
    onBack: () -> Unit,
    onOpenSyndicate: (String) -> Unit,
    viewModel: SyndicateListViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val createState by viewModel.createState.collectAsStateWithLifecycle()
    LaunchedEffect(viewModel) {
        viewModel.created.collectLatest { id -> onOpenSyndicate(id) }
    }
    SyndicateListScreen(
        state = state,
        createState = createState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onOpenSyndicate = onOpenSyndicate,
        onOpenCreate = viewModel::openCreate,
        onDismissCreate = viewModel::dismissCreate,
        onCreateNameChange = viewModel::onCreateNameChange,
        onCreateDescriptionChange = viewModel::onCreateDescriptionChange,
        onSubmitCreate = viewModel::submitCreate,
    )
}

@Composable
fun SyndicateListScreen(
    state: SyndicateListUiState,
    createState: CreateSyndicateFormState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onOpenSyndicate: (String) -> Unit,
    onOpenCreate: () -> Unit,
    onDismissCreate: () -> Unit,
    onCreateNameChange: (String) -> Unit,
    onCreateDescriptionChange: (String) -> Unit,
    onSubmitCreate: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(SyndicateListTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.syndicates_list_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.syndicate_back),
                        )
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = onOpenCreate,
                modifier = Modifier.testTag(SyndicateListTestTags.CREATE_FAB),
            ) {
                Icon(Icons.Filled.Add, contentDescription = stringResource(R.string.syndicate_create_title))
            }
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is SyndicateListUiState.Loading -> LoadingState()
                is SyndicateListUiState.Empty,
                is SyndicateListUiState.NotAvailable ->
                    EmptyState(
                        title = stringResource(R.string.syndicates_list_empty_title),
                        body = stringResource(R.string.syndicates_list_empty_body),
                    )
                is SyndicateListUiState.Error ->
                    ErrorState(message = state.error.message, onRetry = onRetry)
                is SyndicateListUiState.Content ->
                    SyndicateListContent(
                        state = state,
                        onRefresh = onRefresh,
                        onRetry = onRetry,
                        onOpenSyndicate = onOpenSyndicate,
                    )
            }
        }
    }

    if (createState.visible) {
        CreateSyndicateDialog(
            form = createState,
            onNameChange = onCreateNameChange,
            onDescriptionChange = onCreateDescriptionChange,
            onSubmit = onSubmitCreate,
            onDismiss = onDismissCreate,
        )
    }
}

@Composable
private fun SyndicateListContent(
    state: SyndicateListUiState.Content,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onOpenSyndicate: (String) -> Unit,
) {
    PullToRefreshBox(
        isRefreshing = state.isRefreshing,
        onRefresh = onRefresh,
        modifier = Modifier.fillMaxSize(),
    ) {
        Column(Modifier.fillMaxSize()) {
            val stale = state.staleError
            if (stale != null) {
                OfflineBanner(message = stale.message, onRetry = onRetry)
            }
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                items(state.items, key = { it.id }) { item ->
                    SyndicateRow(item = item, onClick = { onOpenSyndicate(item.id) })
                }
            }
        }
    }
}

@Composable
private fun SyndicateRow(
    item: SyndicateListItem,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(SyndicateListTestTags.ROW_PREFIX + item.id)
            .clickable(onClick = onClick)
            .padding(vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(
                text = item.name.ifBlank { item.id },
                style = MaterialTheme.typography.titleMedium,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }
        val role = item.role
        if (!role.isNullOrBlank()) {
            AssistChip(
                onClick = onClick,
                label = { Text(stringResource(R.string.syndicate_role_label, role)) },
            )
        }
    }
}

/** Batch-7 - the create-syndicate dialog (name + optional description). */
@Composable
private fun CreateSyndicateDialog(
    form: CreateSyndicateFormState,
    onNameChange: (String) -> Unit,
    onDescriptionChange: (String) -> Unit,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    AlertDialog(
        modifier = Modifier.testTag(SyndicateListTestTags.CREATE_DIALOG),
        onDismissRequest = { if (!form.submitting) onDismiss() },
        title = { Text(stringResource(R.string.syndicate_create_title)) },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                OutlinedTextField(
                    value = form.name,
                    onValueChange = onNameChange,
                    singleLine = true,
                    isError = form.nameError != null,
                    label = { Text(stringResource(R.string.syndicate_create_name_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(SyndicateListTestTags.CREATE_NAME),
                )
                OutlinedTextField(
                    value = form.description,
                    onValueChange = onDescriptionChange,
                    label = { Text(stringResource(R.string.syndicate_create_description_label)) },
                    modifier = Modifier.fillMaxWidth().testTag(SyndicateListTestTags.CREATE_DESCRIPTION),
                )
                val err = form.submitError
                if (err != null) {
                    Text(
                        text = err,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                }
            }
        },
        confirmButton = {
            Button(
                onClick = onSubmit,
                enabled = form.isValid && !form.submitting,
                modifier = Modifier.testTag(SyndicateListTestTags.CREATE_SUBMIT),
            ) {
                if (form.submitting) {
                    CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                } else {
                    Text(stringResource(R.string.syndicate_create_submit))
                }
            }
        },
        dismissButton = {
            TextButton(onClick = onDismiss, enabled = !form.submitting) {
                Text(stringResource(R.string.syndicate_create_cancel))
            }
        },
    )
}
