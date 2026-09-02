@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner
import com.testlogon.android.data.crm.Prospect
import com.testlogon.android.data.crm.ProspectCreateInDto
import com.testlogon.android.data.crm.LeadsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

object CrmProspectsTestTags {
    const val SCREEN = "crm_prospects_screen"
    const val CONTENT = "crm_prospects_content"
    const val FAB = "crm_prospects_fab"
}

data class ProspectPoolUiState(
    val phase: Phase = Phase.Loading,
    val prospects: List<Prospect> = emptyList(),
    val moduleDisabled: Boolean = false,
    val isRefreshing: Boolean = false,
    val isOffline: Boolean = false,
    val errorMessage: String? = null,
    val createSubmitting: Boolean = false,
    val createError: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-LED — the marketing prospect pool (/ui/leads/prospects). List + create + delete. A 404
 * (module disabled) degrades to an empty, non-error state (mirrors the leads list idiom).
 */
@HiltViewModel
class ProspectPoolViewModel @Inject constructor(
    private val repository: LeadsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ProspectPoolUiState())
    val uiState: StateFlow<ProspectPoolUiState> = _uiState.asStateFlow()

    init { load(fromUser = false) }

    fun onRefresh() = load(fromUser = true)
    fun onRetry() = load(fromUser = true)

    private fun load(fromUser: Boolean) {
        val hasContent = _uiState.value.prospects.isNotEmpty()
        _uiState.update {
            it.copy(
                phase = if (hasContent) it.phase else ProspectPoolUiState.Phase.Loading,
                isRefreshing = fromUser && hasContent,
            )
        }
        viewModelScope.launch {
            when (val r = repository.listProspects()) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = ProspectPoolUiState.Phase.Content,
                        prospects = r.data.prospects,
                        moduleDisabled = r.data.moduleDisabled,
                        isRefreshing = false,
                        isOffline = false,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(
                        phase = if (it.prospects.isNotEmpty()) ProspectPoolUiState.Phase.Content else ProspectPoolUiState.Phase.Error,
                        isRefreshing = false,
                        errorMessage = r.error.message,
                    )
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(
                        phase = if (it.prospects.isNotEmpty()) ProspectPoolUiState.Phase.Content else ProspectPoolUiState.Phase.Error,
                        isRefreshing = false,
                        isOffline = true,
                        errorMessage = "You're offline. Try again.",
                    )
                }
            }
        }
    }

    fun createProspect(
        email: String,
        firstName: String?,
        lastName: String?,
        company: String?,
        onCreated: () -> Unit,
    ) {
        if (email.isBlank()) {
            _uiState.update { it.copy(createError = "Email is required.") }
            return
        }
        _uiState.update { it.copy(createSubmitting = true, createError = null) }
        viewModelScope.launch {
            val body = ProspectCreateInDto(
                email = email.trim(),
                firstName = firstName?.trim()?.ifBlank { null },
                lastName = lastName?.trim()?.ifBlank { null },
                company = company?.trim()?.ifBlank { null },
            )
            when (val r = repository.createProspect(body)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(createSubmitting = false, createError = null) }
                    onCreated()
                    load(fromUser = false)
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(createSubmitting = false, createError = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(createSubmitting = false, createError = "You're offline. Try again.")
                }
            }
        }
    }

    fun deleteProspect(prospectId: String) {
        viewModelScope.launch {
            when (repository.deleteProspect(prospectId)) {
                is ApiResult.Success -> load(fromUser = false)
                is ApiResult.Failure -> _uiState.update { it.copy(errorMessage = "Couldn't delete prospect.") }
                is ApiResult.NetworkError -> _uiState.update { it.copy(errorMessage = "You're offline. Try again.") }
            }
        }
    }

    fun clearCreateError() = _uiState.update { it.copy(createError = null) }
}

@Composable
fun ProspectPoolRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ProspectPoolViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ProspectPoolScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::onRefresh,
        onRetry = viewModel::onRetry,
        onCreate = viewModel::createProspect,
        onDelete = viewModel::deleteProspect,
        onClearCreateError = viewModel::clearCreateError,
        modifier = modifier,
    )
}

@Composable
fun ProspectPoolScreen(
    state: ProspectPoolUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (String, String?, String?, String?, () -> Unit) -> Unit,
    onDelete: (String) -> Unit,
    onClearCreateError: () -> Unit,
    modifier: Modifier = Modifier,
) {
    var showCreate by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(CrmProspectsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Prospects") },
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
                modifier = Modifier.testTag(CrmProspectsTestTags.FAB),
            ) { Icon(Icons.Filled.Add, contentDescription = "New prospect") }
        },
    ) { padding ->
        when (state.phase) {
            ProspectPoolUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            ProspectPoolUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load prospects.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            ProspectPoolUiState.Phase.Content -> PullToRefreshBox(
                isRefreshing = state.isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.padding(padding).fillMaxSize(),
            ) {
                Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isOffline) OfflineBanner(onRetry = onRetry)
                    if (state.moduleDisabled) {
                        InfoBanner("The Leads module is not enabled for this account.")
                    }
                    if (state.prospects.isEmpty()) {
                        EmptyState(
                            title = if (state.moduleDisabled) "Prospects unavailable" else "No prospects yet",
                            body = if (state.moduleDisabled) null else "Tap + to add a prospect.",
                            modifier = Modifier.fillMaxSize(),
                        )
                    } else {
                        LazyColumn(
                            modifier = Modifier.fillMaxSize().testTag(CrmProspectsTestTags.CONTENT),
                            contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                            verticalArrangement = Arrangement.spacedBy(8.dp),
                        ) {
                            items(state.prospects, key = { it.prospectId }) { p ->
                                ProspectRow(p, onDelete = { onDelete(p.prospectId) })
                            }
                        }
                    }
                }
            }
        }
    }

    if (showCreate) {
        CreateProspectDialog(
            submitting = state.createSubmitting,
            error = state.createError,
            onDismiss = { showCreate = false; onClearCreateError() },
            onConfirm = { email, first, last, company ->
                onCreate(email, first, last, company) { showCreate = false }
            },
        )
    }
}

@Composable
private fun ProspectRow(prospect: Prospect, onDelete: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column(modifier = Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                Text(prospect.displayName, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
                val subtitle = listOfNotNull(prospect.company?.ifBlank { null }, prospect.email.ifBlank { null })
                    .joinToString(" · ")
                if (subtitle.isNotBlank()) {
                    Text(subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                if (prospect.suppressed) {
                    AssistChip(onClick = {}, label = { Text("Suppressed") })
                }
            }
            TextButton(onClick = onDelete) { Text("Delete") }
        }
    }
}

@Composable
private fun CreateProspectDialog(
    submitting: Boolean,
    error: String?,
    onDismiss: () -> Unit,
    onConfirm: (email: String, first: String?, last: String?, company: String?) -> Unit,
) {
    var email by remember { mutableStateOf("") }
    var first by remember { mutableStateOf("") }
    var last by remember { mutableStateOf("") }
    var company by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New prospect") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(email, { email = it }, label = { Text("Email") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(first, { first = it }, label = { Text("First name (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(last, { last = it }, label = { Text("Last name (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(company, { company = it }, label = { Text("Company (optional)") }, singleLine = true, modifier = Modifier.fillMaxWidth())
                error?.let { Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall) }
            }
        },
        confirmButton = {
            TextButton(
                enabled = !submitting && email.isNotBlank(),
                onClick = { onConfirm(email, first, last, company) },
            ) { Text("Add") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
