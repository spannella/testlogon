package com.testlogon.android.feature.settings.media

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.selection.toggleable
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.ListItem
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.VideoResolution
import com.testlogon.android.core.ui.state.LoadingState

/** AND-079 — route-level Media preferences entry. */
@Composable
fun MediaPreferencesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MediaPreferencesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    androidx.compose.runtime.LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is MediaPrefsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }
    MediaPreferencesScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::load,
        onMutedChanged = viewModel::onDefaultMutedChanged,
        onVideoOffChanged = viewModel::onDefaultVideoOffChanged,
        onResolutionSelected = viewModel::onResolutionSelected,
        onSave = viewModel::save,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MediaPreferencesScreen(
    state: MediaPrefsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onMutedChanged: (Boolean) -> Unit,
    onVideoOffChanged: (Boolean) -> Unit,
    onResolutionSelected: (VideoResolution) -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("media_prefs_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.media_prefs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.settings_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        when (state) {
            MediaPrefsUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).testTag("media_prefs_loading"))

            is MediaPrefsUiState.Error ->
                Column(
                    modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(state.message, modifier = Modifier.testTag("media_prefs_error"))
                    Button(onClick = onRetry, modifier = Modifier.testTag("media_prefs_retry")) {
                        Text(stringResource(R.string.media_prefs_retry))
                    }
                }

            is MediaPrefsUiState.Ready -> ReadyContent(
                state = state,
                padding = padding,
                onMutedChanged = onMutedChanged,
                onVideoOffChanged = onVideoOffChanged,
                onResolutionSelected = onResolutionSelected,
                onSave = onSave,
            )
        }
    }
}

@Composable
private fun ReadyContent(
    state: MediaPrefsUiState.Ready,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onMutedChanged: (Boolean) -> Unit,
    onVideoOffChanged: (Boolean) -> Unit,
    onResolutionSelected: (VideoResolution) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .verticalScroll(rememberScrollState()),
    ) {
        if (state.isStale) {
            Text(
                text = stringResource(R.string.media_prefs_stale_banner),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.fillMaxWidth().padding(16.dp).testTag("media_prefs_stale"),
            )
        }
        SwitchRow(
            tag = "media_pref_muted",
            title = stringResource(R.string.media_prefs_start_muted_title),
            subtitle = stringResource(R.string.media_prefs_start_muted_desc),
            checked = state.prefs.defaultAudioMuted,
            onCheckedChange = onMutedChanged,
        )
        SwitchRow(
            tag = "media_pref_video_off",
            title = stringResource(R.string.media_prefs_video_off_title),
            subtitle = stringResource(R.string.media_prefs_video_off_desc),
            checked = state.prefs.defaultVideoOff,
            onCheckedChange = onVideoOffChanged,
        )
        HorizontalDivider()
        Text(
            text = stringResource(R.string.media_prefs_resolution_title),
            style = MaterialTheme.typography.titleSmall,
            modifier = Modifier.padding(start = 16.dp, top = 12.dp, bottom = 4.dp),
        )
        Column(Modifier.selectableGroup()) {
            VideoResolution.entries.forEach { res ->
                ResolutionRow(
                    resolution = res,
                    selected = state.prefs.videoResolution == res,
                    onSelect = { onResolutionSelected(res) },
                )
            }
        }
        Button(
            onClick = onSave,
            enabled = state.isDirty && !state.isSaving,
            modifier = Modifier.fillMaxWidth().padding(16.dp).testTag("media_prefs_save"),
        ) {
            Text(stringResource(R.string.media_prefs_save))
        }
    }
}

@Composable
private fun SwitchRow(
    tag: String,
    title: String,
    subtitle: String,
    checked: Boolean,
    onCheckedChange: (Boolean) -> Unit,
) {
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag(tag)
            .toggleable(value = checked, role = Role.Switch, onValueChange = onCheckedChange),
        headlineContent = { Text(title) },
        supportingContent = { Text(subtitle, style = MaterialTheme.typography.bodySmall) },
        trailingContent = { Switch(checked = checked, onCheckedChange = null) },
    )
}

@Composable
private fun ResolutionRow(
    resolution: VideoResolution,
    selected: Boolean,
    onSelect: () -> Unit,
) {
    val label = stringResource(
        when (resolution) {
            VideoResolution.P360 -> R.string.media_prefs_resolution_360
            VideoResolution.P480 -> R.string.media_prefs_resolution_480
            VideoResolution.P720 -> R.string.media_prefs_resolution_720
            VideoResolution.P1080 -> R.string.media_prefs_resolution_1080
        },
    )
    ListItem(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("media_pref_res_${resolution.wire}")
            .selectable(selected = selected, role = Role.RadioButton, onClick = onSelect),
        headlineContent = { Text(label) },
        leadingContent = { RadioButton(selected = selected, onClick = null) },
    )
}
