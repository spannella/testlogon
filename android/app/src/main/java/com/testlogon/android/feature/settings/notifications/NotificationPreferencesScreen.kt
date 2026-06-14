package com.testlogon.android.feature.settings.notifications

import androidx.compose.foundation.layout.Arrangement
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
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
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
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.toggleableState
import androidx.compose.ui.state.ToggleableState
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.model.NotificationChannel
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-080 — route-level Notification preferences entry. */
@Composable
fun NotificationPreferencesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: NotificationPreferencesViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is NotificationPrefsEffect.ShowMessage -> snackbarHostState.showSnackbar(effect.message)
            }
        }
    }
    NotificationPreferencesScreen(
        state = state,
        snackbarHostState = snackbarHostState,
        onBack = onBack,
        onRetry = viewModel::load,
        onToggle = viewModel::onToggle,
        modifier = modifier,
    )
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NotificationPreferencesScreen(
    state: NotificationPrefsUiState,
    snackbarHostState: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onToggle: (alertType: String, channel: NotificationChannel, enabled: Boolean) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("notif_prefs_screen"),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.notif_prefs_title)) },
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
            NotificationPrefsUiState.Loading ->
                LoadingState(modifier = Modifier.padding(padding).testTag("notif_prefs_loading"))

            NotificationPrefsUiState.Empty ->
                EmptyState(
                    title = stringResource(R.string.notif_prefs_empty),
                    modifier = Modifier.padding(padding).testTag("notif_prefs_empty"),
                )

            is NotificationPrefsUiState.Error ->
                Column(
                    modifier = Modifier.fillMaxSize().padding(padding).padding(24.dp),
                    verticalArrangement = Arrangement.spacedBy(16.dp),
                ) {
                    Text(state.message, modifier = Modifier.testTag("notif_prefs_error"))
                    Button(onClick = onRetry, modifier = Modifier.testTag("notif_prefs_retry")) {
                        Text(stringResource(R.string.media_prefs_retry))
                    }
                }

            is NotificationPrefsUiState.Ready ->
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding).testTag("notif_prefs_list"),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    if (state.isStale) {
                        item {
                            Text(
                                text = stringResource(R.string.notif_prefs_stale_banner),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.testTag("notif_prefs_stale"),
                            )
                        }
                    }
                    items(state.rows, key = { it.alertType }) { row ->
                        CategoryCard(row = row, onToggle = onToggle)
                    }
                }
        }
    }
}

@Composable
private fun CategoryCard(
    row: CategoryRow,
    onToggle: (alertType: String, channel: NotificationChannel, enabled: Boolean) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag("notif_category_${row.alertType}")) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text(stringResource(row.titleRes), style = MaterialTheme.typography.titleMedium)
            ChannelToggle(
                alertType = row.alertType,
                channel = NotificationChannel.PUSH,
                labelRes = R.string.notif_prefs_channel_push,
                checked = row.pref.push,
                onToggle = onToggle,
            )
            ChannelToggle(
                alertType = row.alertType,
                channel = NotificationChannel.EMAIL,
                labelRes = R.string.notif_prefs_channel_email,
                checked = row.pref.email,
                onToggle = onToggle,
            )
            ChannelToggle(
                alertType = row.alertType,
                channel = NotificationChannel.SMS,
                labelRes = R.string.notif_prefs_channel_sms,
                checked = row.pref.sms,
                onToggle = onToggle,
            )
        }
    }
}

@Composable
private fun ChannelToggle(
    alertType: String,
    channel: NotificationChannel,
    labelRes: Int,
    checked: Boolean,
    onToggle: (alertType: String, channel: NotificationChannel, enabled: Boolean) -> Unit,
) {
    val label = stringResource(labelRes)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("notif_toggle_${alertType}_${channel.name.lowercase()}")
            .semantics {
                contentDescription = label
                toggleableState = if (checked) ToggleableState.On else ToggleableState.Off
            },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, style = MaterialTheme.typography.bodyMedium)
        Switch(
            checked = checked,
            onCheckedChange = { onToggle(alertType, channel, it) },
        )
    }
}
