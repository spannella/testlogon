@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.groups

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-355 (sub-pages) - stable testTags for the group settings screen. */
object GroupSettingsTestTags {
    const val SCREEN = "group_settings_screen"
    const val SAVE = "group_settings_save"
    const val NAME = "group_settings_name"
}

@Composable
fun GroupSettingsRoute(
    onBack: () -> Unit,
    viewModel: GroupSettingsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    GroupSettingsScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onSave = viewModel::save,
        onNoticeShown = viewModel::consumeNotice,
    )
}

@Composable
fun GroupSettingsScreen(
    state: GroupSettingsUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onSave: (name: String, description: String, visibility: String, topic: String) -> Unit,
    onNoticeShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    (state as? GroupSettingsUiState.Content)?.notice?.let { notice ->
        LaunchedEffect(notice) {
            snackbarHostState.showSnackbar(notice)
            onNoticeShown()
        }
    }
    Scaffold(
        modifier = modifier.testTag(GroupSettingsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.group_settings_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.groups_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            is GroupSettingsUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding))

            is GroupSettingsUiState.Error ->
                ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )

            is GroupSettingsUiState.Content ->
                GroupSettingsForm(state = state, onSave = onSave, modifier = Modifier.padding(padding))
        }
    }
}

private const val VISIBILITY_PUBLIC = "public"
private const val VISIBILITY_PRIVATE = "private"

@Composable
private fun GroupSettingsForm(
    state: GroupSettingsUiState.Content,
    onSave: (name: String, description: String, visibility: String, topic: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val group = state.group
    var name by remember(group) { mutableStateOf(group.name) }
    var description by remember(group) { mutableStateOf(group.description.orEmpty()) }
    var topic by remember(group) { mutableStateOf(group.topic.orEmpty()) }
    var visibility by remember(group) {
        mutableStateOf(group.visibility?.takeIf { it.isNotBlank() } ?: VISIBILITY_PUBLIC)
    }
    val enabled = state.canEdit && !state.isSaving

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (!state.canEdit) {
            Text(
                text = stringResource(R.string.group_settings_read_only),
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        OutlinedTextField(
            value = name,
            onValueChange = { name = it },
            label = { Text(stringResource(R.string.group_settings_name_label)) },
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth().testTag(GroupSettingsTestTags.NAME),
        )
        OutlinedTextField(
            value = description,
            onValueChange = { description = it },
            label = { Text(stringResource(R.string.group_settings_description_label)) },
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )
        OutlinedTextField(
            value = topic,
            onValueChange = { topic = it },
            label = { Text(stringResource(R.string.group_settings_topic_label)) },
            singleLine = true,
            enabled = enabled,
            modifier = Modifier.fillMaxWidth(),
        )
        Text(
            text = stringResource(R.string.group_settings_visibility_label),
            style = MaterialTheme.typography.titleSmall,
        )
        VisibilityOption(
            label = stringResource(R.string.group_settings_visibility_public),
            selected = visibility == VISIBILITY_PUBLIC,
            enabled = enabled,
            onSelect = { visibility = VISIBILITY_PUBLIC },
        )
        VisibilityOption(
            label = stringResource(R.string.group_settings_visibility_private),
            selected = visibility == VISIBILITY_PRIVATE,
            enabled = enabled,
            onSelect = { visibility = VISIBILITY_PRIVATE },
        )
        if (state.canEdit) {
            Button(
                onClick = { onSave(name, description, visibility, topic) },
                enabled = enabled && name.isNotBlank(),
                modifier = Modifier.fillMaxWidth().testTag(GroupSettingsTestTags.SAVE),
            ) {
                if (state.isSaving) {
                    CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(20.dp))
                } else {
                    Text(stringResource(R.string.group_settings_save))
                }
            }
        }
    }
}

@Composable
private fun VisibilityOption(
    label: String,
    selected: Boolean,
    enabled: Boolean,
    onSelect: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .selectable(selected = selected, enabled = enabled, onClick = onSelect),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        RadioButton(selected = selected, onClick = onSelect, enabled = enabled)
        Text(text = label, style = MaterialTheme.typography.bodyLarge)
    }
}
