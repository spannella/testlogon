@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.messaging.groupcreate

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material.icons.filled.Close
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.InputChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
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
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.role
import androidx.compose.ui.semantics.selected
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R

/** AND-157 — stable testTags for the group-create screen. */
object GroupCreateTestTags {
    const val SCREEN = "group_create_screen"
    const val NAME = "group_create_name"
    const val SEARCH = "group_create_search"
    const val LIST = "group_create_list"
    const val ROW = "group_create_row"
    const val CHIP = "group_create_chip"
    const val CREATE = "group_create_submit"
    const val PROGRESS = "group_create_progress"
}

/**
 * AND-157 — route-level group-create screen. Collects the one-shot [GroupCreateEvent.Created] effect
 * and delegates navigation into the new thread to [onGroupCreated] (the NavHost owns navigation).
 */
@Composable
fun GroupCreateRoute(
    onGroupCreated: (conversationId: String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GroupCreateViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.events.collect { event ->
            when (event) {
                is GroupCreateEvent.Created -> onGroupCreated(event.conversationId)
            }
        }
    }

    LaunchedEffect(state.errorMessage) {
        state.errorMessage?.let {
            snackbarHostState.showSnackbar(it)
            viewModel.onErrorShown()
        }
    }

    GroupCreateScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onNameChange = viewModel::onNameChange,
        onQueryChange = viewModel::onQueryChange,
        onToggleParticipant = viewModel::onToggleParticipant,
        onRemoveParticipant = viewModel::onRemoveParticipant,
        onCreateClick = viewModel::onCreateClick,
        onBack = onBack,
        modifier = modifier,
    )
}

@Composable
fun GroupCreateScreen(
    state: GroupCreateUiState,
    onNameChange: (String) -> Unit,
    onQueryChange: (String) -> Unit,
    onToggleParticipant: (String) -> Unit,
    onRemoveParticipant: (String) -> Unit,
    onCreateClick: () -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    snackbarHostState: SnackbarHostState = remember { SnackbarHostState() },
) {
    var showDiscard by remember { mutableStateOf(false) }
    val hasInput = state.name.isNotBlank() || state.selected.isNotEmpty()
    val attemptBack: () -> Unit = { if (hasInput) showDiscard = true else onBack() }

    Scaffold(
        modifier = modifier.testTag(GroupCreateTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_create_title)) },
                navigationIcon = {
                    IconButton(onClick = attemptBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
                actions = {
                    if (state.isSubmitting) {
                        CircularProgressIndicator(
                            strokeWidth = 2.dp,
                            modifier = Modifier
                                .padding(end = 16.dp)
                                .testTag(GroupCreateTestTags.PROGRESS),
                        )
                    } else {
                        IconButton(
                            onClick = onCreateClick,
                            enabled = state.canCreate,
                            modifier = Modifier.testTag(GroupCreateTestTags.CREATE),
                        ) {
                            Icon(
                                Icons.Filled.Check,
                                contentDescription = stringResource(R.string.group_create_action_cd),
                            )
                        }
                    }
                },
            )
        },
    ) { padding ->
        Column(
            Modifier
                .fillMaxSize()
                .padding(padding),
        ) {
            OutlinedTextField(
                value = state.name,
                onValueChange = onNameChange,
                singleLine = true,
                label = { Text(stringResource(R.string.group_create_name_label)) },
                supportingText = { Text("${state.name.length}/${GroupCreateUiState.MAX_NAME_LENGTH}") },
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp)
                    .testTag(GroupCreateTestTags.NAME),
            )

            if (state.selected.isNotEmpty()) {
                FlowRow(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp),
                ) {
                    state.selected.forEach { p ->
                        InputChip(
                            selected = true,
                            onClick = { onRemoveParticipant(p.userId) },
                            label = { Text(p.displayName, maxLines = 1, overflow = TextOverflow.Ellipsis) },
                            trailingIcon = {
                                Icon(
                                    Icons.Filled.Close,
                                    contentDescription = stringResource(
                                        R.string.group_remove_participant_cd,
                                        p.displayName,
                                    ),
                                )
                            },
                            modifier = Modifier
                                .padding(end = 8.dp)
                                .testTag(GroupCreateTestTags.CHIP),
                        )
                    }
                }
            }

            OutlinedTextField(
                value = state.query,
                onValueChange = onQueryChange,
                singleLine = true,
                label = { Text(stringResource(R.string.group_create_search_label)) },
                keyboardOptions = KeyboardOptions(),
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp, vertical = 8.dp)
                    .testTag(GroupCreateTestTags.SEARCH),
            )

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .testTag(GroupCreateTestTags.LIST),
            ) {
                items(state.candidates, key = { it.userId }) { candidate ->
                    val isSelected = state.selectedIds.contains(candidate.userId)
                    CandidateRow(
                        candidate = candidate,
                        selected = isSelected,
                        onClick = { onToggleParticipant(candidate.userId) },
                    )
                }
            }
        }
    }

    if (showDiscard) {
        AlertDialog(
            onDismissRequest = { showDiscard = false },
            title = { Text(stringResource(R.string.group_create_discard_title)) },
            text = { Text(stringResource(R.string.group_create_discard_body)) },
            confirmButton = {
                TextButton(onClick = { showDiscard = false; onBack() }) {
                    Text(stringResource(R.string.group_create_discard_confirm))
                }
            },
            dismissButton = {
                TextButton(onClick = { showDiscard = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun CandidateRow(
    candidate: ParticipantUi,
    selected: Boolean,
    onClick: () -> Unit,
) {
    val rowCd = stringResource(R.string.group_create_row_cd, candidate.displayName)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 48.dp)
            .clickable(onClick = onClick)
            .semantics(mergeDescendants = true) {
                role = Role.Checkbox
                this.selected = selected
                contentDescription = rowCd
            }
            .padding(horizontal = 16.dp, vertical = 12.dp)
            .testTag(GroupCreateTestTags.ROW),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = candidate.displayName,
            style = MaterialTheme.typography.bodyLarge,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.weight(1f),
        )
        if (selected) {
            Icon(
                Icons.Filled.Check,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
            )
        }
    }
}
