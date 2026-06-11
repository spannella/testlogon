@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.calendar.integrations

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.calendar.Calendar
import com.testlogon.android.data.gcal.ProviderCalendar
import kotlinx.coroutines.launch

/** AND-273 — stable test tags for the Google Calendar Connect screen. */
object GoogleCalendarTestTags {
    const val SCREEN = "gcal_screen"
    const val CONNECT = "gcal_connect"
    const val DISCONNECT = "gcal_disconnect"
    const val SYNC = "gcal_sync"
    const val LIST = "gcal_calendars"
    fun calendar(id: String) = "gcal_calendar_$id"
    fun mapping(id: String) = "gcal_mapping_$id"
}

/**
 * AND-273 — route-level Google Calendar Connect screen. Hoists the ViewModel, collects state + one-shot
 * effects (opens the Custom Tab via [GoogleCalendarTabLauncher]; shows snackbars), and re-reads status on
 * ON_RESUME so a Custom-Tab return refreshes the connection.
 */
@Composable
fun GoogleCalendarConnectRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: GoogleCalendarViewModel = hiltViewModel(),
    tabLauncher: GoogleCalendarTabLauncher = CustomTabsGoogleCalendarTabLauncher(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val context = LocalContext.current
    val snackbarHost = remember { SnackbarHostState() }
    val scope = rememberCoroutineScope()

    LaunchedEffect(Unit) {
        viewModel.effects.collect { effect ->
            when (effect) {
                is GoogleCalendarEffect.OpenCustomTab ->
                    tabLauncher.launch(context, effect.authorizationUrl)
                is GoogleCalendarEffect.ShowMessage ->
                    scope.launch { snackbarHost.showSnackbar(effect.message) }
            }
        }
    }

    // AND-273: re-read status when the user returns to the app (Custom Tab dismissed / completed).
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        viewModel.onReturnedFromCustomTab()
    }

    GoogleCalendarConnectScreen(
        state = state,
        snackbarHost = snackbarHost,
        onBack = onBack,
        onConnect = viewModel::onConnectClicked,
        onDisconnect = viewModel::onDisconnect,
        onMapCalendar = viewModel::onMapCalendar,
        onRunSync = viewModel::onRunSync,
        onRetry = viewModel::onRetry,
        modifier = modifier,
    )
}

@Composable
fun GoogleCalendarConnectScreen(
    state: GoogleCalendarUiState,
    snackbarHost: SnackbarHostState,
    onBack: () -> Unit,
    onConnect: () -> Unit,
    onDisconnect: () -> Unit,
    onMapCalendar: (googleCalendarId: String, internalCalendarId: String) -> Unit,
    onRunSync: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showDisconnectDialog by remember { mutableStateOf(false) }
    Scaffold(
        modifier = modifier.testTag(GoogleCalendarTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHost) },
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.gcal_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.action_back),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is GoogleCalendarUiState.Loading -> LoadingState()
                is GoogleCalendarUiState.Connecting -> LoadingState(message = stringResource(R.string.gcal_connecting))
                is GoogleCalendarUiState.Disconnected -> DisconnectedCard(state.message, onConnect)
                is GoogleCalendarUiState.Error ->
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    else ErrorState(message = state.message, onRetry = onRetry)
                is GoogleCalendarUiState.Connected ->
                    ConnectedBody(
                        state = state,
                        onMapCalendar = onMapCalendar,
                        onRunSync = onRunSync,
                        onDisconnectRequest = { showDisconnectDialog = true },
                    )
            }
        }
    }

    if (showDisconnectDialog) {
        AlertDialog(
            onDismissRequest = { showDisconnectDialog = false },
            title = { Text(stringResource(R.string.gcal_disconnect_title)) },
            text = { Text(stringResource(R.string.gcal_disconnect_body)) },
            confirmButton = {
                TextButton(onClick = {
                    showDisconnectDialog = false
                    onDisconnect()
                }) { Text(stringResource(R.string.gcal_disconnect)) }
            },
            dismissButton = {
                TextButton(onClick = { showDisconnectDialog = false }) {
                    Text(stringResource(R.string.action_cancel))
                }
            },
        )
    }
}

@Composable
private fun DisconnectedCard(message: String?, onConnect: () -> Unit) {
    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
        Text(stringResource(R.string.gcal_disconnected_label), style = MaterialTheme.typography.titleMedium)
        Text(stringResource(R.string.gcal_disconnected_body), style = MaterialTheme.typography.bodyMedium)
        if (message != null) {
            Text(message, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
        }
        Button(onClick = onConnect, modifier = Modifier.testTag(GoogleCalendarTestTags.CONNECT)) {
            Text(stringResource(R.string.gcal_connect))
        }
    }
}

@Composable
private fun ConnectedBody(
    state: GoogleCalendarUiState.Connected,
    onMapCalendar: (String, String) -> Unit,
    onRunSync: () -> Unit,
    onDisconnectRequest: () -> Unit,
) {
    if (state.stale) OfflineBanner(onRetry = {})
    Column(Modifier.fillMaxWidth().padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        Text(stringResource(R.string.gcal_connected_label), style = MaterialTheme.typography.titleMedium)
        if (state.accountEmail != null) {
            Text(state.accountEmail, style = MaterialTheme.typography.bodyMedium)
        }
        if (state.reauthRequired) {
            Text(
                stringResource(R.string.gcal_reauth_required),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
        Column {
            OutlinedButton(
                onClick = onRunSync,
                enabled = !state.syncRunning,
                modifier = Modifier.testTag(GoogleCalendarTestTags.SYNC),
            ) { Text(stringResource(R.string.gcal_run_sync)) }
            TextButton(
                onClick = onDisconnectRequest,
                modifier = Modifier.testTag(GoogleCalendarTestTags.DISCONNECT),
            ) { Text(stringResource(R.string.gcal_disconnect)) }
        }
    }
    when (state.listState) {
        ListState.LOADING -> LoadingState(fullScreen = false)
        ListState.EMPTY ->
            Text(
                stringResource(R.string.gcal_no_calendars),
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        ListState.ERROR ->
            Text(
                stringResource(R.string.gcal_calendars_error),
                modifier = Modifier.padding(16.dp),
                color = MaterialTheme.colorScheme.error,
            )
        ListState.LOADED ->
            ProviderCalendarList(state.calendars, state.internalCalendars, onMapCalendar)
    }
}

@Composable
private fun ProviderCalendarList(
    calendars: List<ProviderCalendar>,
    internalCalendars: List<Calendar>,
    onMapCalendar: (String, String) -> Unit,
) {
    LazyColumn(
        Modifier.fillMaxSize().testTag(GoogleCalendarTestTags.LIST),
        contentPadding = PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(calendars, key = { it.googleCalendarId }) { cal ->
            ProviderCalendarRow(cal, internalCalendars, onMapCalendar)
        }
    }
}

@Composable
private fun ProviderCalendarRow(
    cal: ProviderCalendar,
    internalCalendars: List<Calendar>,
    onMapCalendar: (String, String) -> Unit,
) {
    Surface(
        tonalElevation = 1.dp,
        modifier = Modifier.fillMaxWidth().testTag(GoogleCalendarTestTags.calendar(cal.googleCalendarId)),
    ) {
        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(cal.summary.ifBlank { cal.googleCalendarId }, style = MaterialTheme.typography.bodyLarge)
            val badge = buildString {
                if (cal.primary) append(stringResource(R.string.gcal_badge_primary))
                cal.accessRole?.let { if (isNotEmpty()) append(" · "); append(it) }
            }
            if (badge.isNotEmpty()) {
                Text(badge, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            MappingPicker(cal, internalCalendars, onMapCalendar)
        }
    }
}

@Composable
private fun MappingPicker(
    cal: ProviderCalendar,
    internalCalendars: List<Calendar>,
    onMapCalendar: (String, String) -> Unit,
) {
    var expanded by remember { mutableStateOf(false) }
    val mappedName = internalCalendars
        .firstOrNull { it.calendarId == cal.mappedInternalCalendarId }
        ?.name
        ?: stringResource(R.string.gcal_unmapped)
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
    ) {
        OutlinedTextField(
            value = mappedName,
            onValueChange = {},
            readOnly = true,
            label = { Text(stringResource(R.string.gcal_map_to)) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(GoogleCalendarTestTags.mapping(cal.googleCalendarId)),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            internalCalendars.forEach { internal ->
                DropdownMenuItem(
                    text = { Text(internal.name) },
                    onClick = {
                        expanded = false
                        onMapCalendar(cal.googleCalendarId, internal.calendarId)
                    },
                )
            }
        }
    }
}
