@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.settings.pushevents

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.outlined.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.LoadingState

object PushEventPrefsTestTags {
    const val SCREEN = "push_event_prefs_screen"
    const val LIST = "push_event_prefs_list"
    const val ROW_PREFIX = "push_event_row_"
    const val SWITCH_PREFIX = "push_event_switch_"
}

/** D2 - route-level per-event PUSH preferences entry. */
@Composable
fun PushEventPrefsRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PushEventPrefsViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is PushEventPrefsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }
    PushEventPrefsScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::retry,
        onToggle = viewModel::onToggle,
        modifier = modifier,
    )
}

@Composable
fun PushEventPrefsScreen(
    state: PushEventPrefsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onToggle: (eventType: String, enabled: Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(PushEventPrefsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.push_event_prefs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Outlined.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbarHostState) },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is PushEventPrefsUiState.Loading -> LoadingState()
                is PushEventPrefsUiState.Error ->
                    Column(
                        Modifier.fillMaxSize().padding(24.dp),
                        verticalArrangement = Arrangement.spacedBy(16.dp),
                    ) {
                        Text(state.message)
                        if (state.retryable) {
                            Button(onClick = onRetry) { Text(stringResource(R.string.media_prefs_retry)) }
                        }
                    }
                is PushEventPrefsUiState.Ready ->
                    LazyColumn(
                        Modifier.fillMaxSize().testTag(PushEventPrefsTestTags.LIST),
                    ) {
                        item {
                            Text(
                                text = stringResource(R.string.push_event_prefs_header),
                                style = MaterialTheme.typography.bodyMedium,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(16.dp),
                            )
                        }
                        items(state.rows, key = { it.eventType }) { row ->
                            PushEventRowItem(
                                row = row,
                                enabledInteractive = !state.saving,
                                onToggle = { enabled -> onToggle(row.eventType, enabled) },
                            )
                            HorizontalDivider()
                        }
                    }
            }
        }
    }
}

@Composable
private fun PushEventRowItem(
    row: PushEventRow,
    enabledInteractive: Boolean,
    onToggle: (Boolean) -> Unit,
) {
    Row(
        Modifier
            .fillMaxWidth()
            .testTag(PushEventPrefsTestTags.ROW_PREFIX + row.eventType)
            .padding(horizontal = 16.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Column(Modifier.weight(1f).padding(end = 12.dp)) {
            Text(stringResource(row.titleRes), style = MaterialTheme.typography.bodyLarge)
            Text(
                stringResource(row.subtitleRes),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Switch(
            checked = row.enabled,
            onCheckedChange = onToggle,
            enabled = enabledInteractive,
            modifier = Modifier.testTag(PushEventPrefsTestTags.SWITCH_PREFIX + row.eventType),
        )
    }
}
