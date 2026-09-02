@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
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
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.CrmEvent
import com.testlogon.android.data.crm.CrmPecMath

object CrmEventsTestTags {
    const val SCREEN = "crm_events_screen"
    const val CONTENT = "crm_events_content"
    const val LOADING = "crm_events_loading"
    const val ERROR = "crm_events_error"
    const val FAB = "crm_events_fab"
}

@Composable
fun CrmEventsRoute(
    onEventClick: (String) -> Unit,
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: CrmEventsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    CrmEventsScreen(
        state = state,
        onEventClick = onEventClick,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onCreate = viewModel::createEvent,
        onClearCreateError = viewModel::clearCreateError,
        modifier = modifier,
    )
}

@Composable
fun CrmEventsScreen(
    state: CrmEventsUiState,
    onEventClick: (String) -> Unit,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (String, String?, Int?, (String) -> Unit) -> Unit,
    onClearCreateError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(CrmEventsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Events") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showCreate = true },
                modifier = Modifier.testTag(CrmEventsTestTags.FAB),
            ) { Icon(Icons.Filled.Add, contentDescription = "New event") }
        },
    ) { padding ->
        when (state.phase) {
            CrmEventsUiState.Phase.Loading -> LoadingState(
                modifier = Modifier.padding(padding).testTag(CrmEventsTestTags.LOADING),
            )
            CrmEventsUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load events.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding).testTag(CrmEventsTestTags.ERROR),
            )
            CrmEventsUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) InfoBanner("The Events module is not enabled for this account.")
                    if (state.events.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Events unavailable" else "No events yet",
                            body = if (state.moduleDisabled) null else "Tap + to create your first event.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(CrmEventsTestTags.CONTENT),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.events, key = { it.eventId }) { event ->
                                EventRow(event, onClick = { onEventClick(event.eventId) })
                            }
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateEventSheet(
            submitting = state.createSubmitting,
            error = state.createError,
            onDismiss = {
                showCreate = false
                onClearCreateError()
            },
            onSubmit = { name, desc, maxAtt ->
                onCreate(name, desc, maxAtt) { _ -> showCreate = false }
            },
        )
    }
}

@Composable
private fun EventRow(event: CrmEvent, onClick: () -> Unit) {
    Card(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(event.name.ifBlank { "(untitled)" }, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                if (event.description.isNotBlank()) {
                    Text(
                        event.description,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        maxLines = 2,
                    )
                }
                Text(CrmPecMath.formatDate(event.createdAt), style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            }
            AssistChip(
                onClick = {},
                label = {
                    Text(
                        if (event.maxAttendance != null && event.maxAttendance > 0) "Cap ${event.maxAttendance}" else "Open",
                    )
                },
            )
        }
    }
}

@Composable
private fun CreateEventSheet(
    submitting: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onSubmit: (name: String, description: String?, maxAttendance: Int?) -> Unit,
) {
    var name by remember { mutableStateOf("") }
    var description by remember { mutableStateOf("") }
    var maxAtt by remember { mutableStateOf("") }

    AlertDialog(
        onDismissRequest = { if (!submitting) onDismiss() },
        title = { Text("New event") },
        text = {
            Column(
                modifier = Modifier.verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedTextField(name, { name = it }, label = { Text("Name") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(description, { description = it }, label = { Text("Description (optional)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(
                    maxAtt,
                    { input -> maxAtt = input.filter { it.isDigit() } },
                    label = { Text("Max attendance (optional)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (error != null) {
                    Text(error, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                }
            }
        },
        confirmButton = {
            TextButton(enabled = !submitting, onClick = { onSubmit(name, description, maxAtt.toIntOrNull()) }) {
                if (submitting) CircularProgressIndicator(modifier = Modifier.size(18.dp)) else Text("Create")
            }
        },
        dismissButton = { TextButton(enabled = !submitting, onClick = onDismiss) { Text("Cancel") } },
    )
}
