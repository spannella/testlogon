@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.kycadmin.KycTemplateDto
import com.testlogon.android.data.kycadmin.KycTemplatesAdminRepository
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.CardSection
import com.testlogon.android.feature.adminops.StatRow
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

sealed interface KycTemplatesListState {
    data object Loading : KycTemplatesListState
    data class Data(val items: List<KycTemplateDto>, val isRefreshing: Boolean = false) : KycTemplatesListState
    data object Empty : KycTemplatesListState
    data object Forbidden : KycTemplatesListState
    data class Error(val type: AdminOpsErrorType) : KycTemplatesListState
}

data class KycTemplatesUiState(
    val list: KycTemplatesListState = KycTemplatesListState.Loading,
    val detail: KycTemplateDto? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
)

@HiltViewModel
class KycTemplatesAdminViewModel @Inject constructor(
    private val repo: KycTemplatesAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycTemplatesUiState())
    val state: StateFlow<KycTemplatesUiState> = _state.asStateFlow()

    init { fetch(false) }
    fun retry() = fetch(false)
    fun refresh() {
        val cur = _state.value.list
        if (cur is KycTemplatesListState.Data) _state.value = _state.value.copy(list = cur.copy(isRefreshing = true))
        fetch(true)
    }

    fun clearMessage() { _state.value = _state.value.copy(message = null) }
    fun closeDetail() { _state.value = _state.value.copy(detail = null) }

    fun openDetail(templateId: String) {
        viewModelScope.launch {
            when (val r = repo.get(templateId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(detail = r.data)
                is ApiResult.Failure -> _state.value = _state.value.copy(message = failMsg(r.error.status))
                is ApiResult.NetworkError -> _state.value = _state.value.copy(message = adminOpsErrorMessage(AdminOpsErrorType.NETWORK))
            }
        }
    }

    fun create(slug: String, displayName: String, description: String, tier: String, fields: List<String>) =
        act("Template created") { repo.create(slug, displayName, description, tier, fields) }

    fun archive(templateId: String) = act("Template archived") {
        val r = repo.archive(templateId); if (r is ApiResult.Success) closeDetail(); r
    }

    fun activateVersion(templateId: String, version: Int) =
        actRefreshDetail(templateId, "Version activated") { repo.activateVersion(templateId, version) }

    fun deactivateVersion(templateId: String, version: Int) =
        actRefreshDetail(templateId, "Version deactivated") { repo.deactivateVersion(templateId, version) }

    private fun failMsg(status: Int): String =
        if (status == 403) "Not authorised." else adminOpsErrorMessage(adminOpsErrorFor(status))

    private fun act(okLabel: String, block: suspend () -> ApiResult<*>) {
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true)
        viewModelScope.launch {
            val msg = when (val r = block()) {
                is ApiResult.Success -> okLabel
                is ApiResult.Failure -> failMsg(r.error.status)
                is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
            }
            _state.value = _state.value.copy(actionInFlight = false, message = msg)
            fetch(true)
        }
    }

    private fun actRefreshDetail(templateId: String, okLabel: String, block: suspend () -> ApiResult<*>) {
        if (_state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true)
        viewModelScope.launch {
            val msg = when (val r = block()) {
                is ApiResult.Success -> okLabel
                is ApiResult.Failure -> failMsg(r.error.status)
                is ApiResult.NetworkError -> adminOpsErrorMessage(AdminOpsErrorType.NETWORK)
            }
            _state.value = _state.value.copy(actionInFlight = false, message = msg)
            openDetail(templateId)
            fetch(true)
        }
    }

    private fun fetch(isRefresh: Boolean) {
        if (!isRefresh) _state.value = _state.value.copy(list = KycTemplatesListState.Loading)
        viewModelScope.launch {
            when (val r = repo.list()) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    list = if (r.data.isEmpty()) KycTemplatesListState.Empty else KycTemplatesListState.Data(r.data),
                )
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    list = if (r.error.status == 403) KycTemplatesListState.Forbidden else KycTemplatesListState.Error(adminOpsErrorFor(r.error.status)),
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(list = KycTemplatesListState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }
}

object KycTemplatesTestTags {
    const val SCREEN = "kyc_templates_screen"
    const val LIST = "kyc_templates_list"
    const val EMPTY = "kyc_templates_empty"
    const val FORBIDDEN = "kyc_templates_forbidden"
    const val RETRY = "kyc_templates_retry"
    const val FAB = "kyc_templates_fab"
    const val CREATE_CONFIRM = "kyc_templates_create_confirm"
    fun row(id: String) = "kyc_templates_row_$id"
}

@Composable
fun KycTemplatesAdminRoute(
    onBack: () -> Unit,
    viewModel: KycTemplatesAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var createDialog by remember { mutableStateOf(false) }

    LaunchedEffect(state.message) { state.message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() } }

    if (state.detail != null) {
        val d = state.detail!!
        BackHandler(onBack = viewModel::closeDetail)
        KycTemplateDetail(
            template = d,
            actionInFlight = state.actionInFlight,
            snackbar = snackbar,
            onBack = viewModel::closeDetail,
            onArchive = { viewModel.archive(d.templateId) },
            onActivate = { v -> viewModel.activateVersion(d.templateId, v) },
            onDeactivate = { v -> viewModel.deactivateVersion(d.templateId, v) },
        )
        return
    }

    Scaffold(
        modifier = Modifier.testTag(KycTemplatesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("KYC templates") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { createDialog = true }, modifier = Modifier.testTag(KycTemplatesTestTags.FAB)) {
                Icon(Icons.Outlined.Add, contentDescription = "New template")
            }
        },
    ) { padding ->
        androidx.compose.material3.pulltorefresh.PullToRefreshBox(
            isRefreshing = (state.list as? KycTemplatesListState.Data)?.isRefreshing == true,
            onRefresh = viewModel::refresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (val l = state.list) {
                is KycTemplatesListState.Loading -> LoadingState()
                is KycTemplatesListState.Empty -> EmptyState(
                    modifier = Modifier.testTag(KycTemplatesTestTags.EMPTY),
                    title = "No templates", body = "Create a KYC document template.", imageVector = Icons.Outlined.Description,
                )
                is KycTemplatesListState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(KycTemplatesTestTags.FORBIDDEN),
                    title = "Not authorised", body = "Admin access required.",
                    imageVector = Icons.Outlined.Description, actionLabel = "Back", onAction = onBack,
                )
                is KycTemplatesListState.Error -> ErrorState(
                    modifier = Modifier.testTag(KycTemplatesTestTags.RETRY),
                    message = adminOpsErrorMessage(l.type), onRetry = viewModel::retry,
                )
                is KycTemplatesListState.Data -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(KycTemplatesTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = l.items, key = { it.templateId }) { t ->
                        Card(
                            modifier = Modifier.fillMaxWidth().testTag(KycTemplatesTestTags.row(t.templateId)),
                            onClick = { viewModel.openDetail(t.templateId) },
                        ) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                Text(t.displayName.ifBlank { t.slug }, style = MaterialTheme.typography.titleSmall)
                                Text("${t.requiredTier.replace('_', ' ')}  ·  ${t.status}  ·  v${t.latestVersion}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                            }
                        }
                    }
                }
            }
        }
    }

    if (createDialog) {
        CreateTemplateDialog(
            onDismiss = { createDialog = false },
            onConfirm = { slug, name, desc, tier, fields ->
                viewModel.create(slug, name, desc, tier, fields); createDialog = false
            },
        )
    }
}

@Composable
private fun KycTemplateDetail(
    template: KycTemplateDto,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onArchive: () -> Unit,
    onActivate: (Int) -> Unit,
    onDeactivate: (Int) -> Unit,
) {
    Scaffold(
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(template.displayName.ifBlank { template.slug }) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(padding),
            contentPadding = PaddingValues(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            item {
                CardSection("Template") {
                    StatRow("Slug", template.slug)
                    StatRow("Tier", template.requiredTier.replace('_', ' '))
                    StatRow("Status", template.status)
                    StatRow("Latest version", template.latestVersion.toString())
                    if (template.description.isNotBlank()) StatRow("Description", template.description)
                    if (template.placeholderFields.isNotEmpty()) StatRow("Fields", template.placeholderFields.joinToString(", "))
                }
            }
            if (template.versions.isNotEmpty()) {
                item { Text("Versions", style = MaterialTheme.typography.titleMedium) }
                items(items = template.versions, key = { it.version }) { v ->
                    CardSection("v${v.version}") {
                        StatRow("Status", v.status)
                        StatRow("PDF uploaded", if (v.pdfUploaded) "Yes" else "No")
                        Row(Modifier.fillMaxWidth().padding(top = 8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            OutlinedButton(onClick = { onActivate(v.version) }, enabled = !actionInFlight) { Text("Activate") }
                            OutlinedButton(onClick = { onDeactivate(v.version) }, enabled = !actionInFlight) { Text("Deactivate") }
                        }
                    }
                }
            }
            item {
                OutlinedButton(onClick = onArchive, enabled = !actionInFlight, modifier = Modifier.fillMaxWidth()) {
                    Text("Archive template")
                }
            }
        }
    }
}

@Composable
private fun CreateTemplateDialog(
    onDismiss: () -> Unit,
    onConfirm: (String, String, String, String, List<String>) -> Unit,
) {
    var slug by remember { mutableStateOf("") }
    var name by remember { mutableStateOf("") }
    var desc by remember { mutableStateOf("") }
    var tier by remember { mutableStateOf("tier_1") }
    var fields by remember { mutableStateOf("") }
    val tiers = listOf("none", "tier_1", "tier_2", "tier_3")

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("New template") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = slug, onValueChange = { slug = it }, label = { Text("Slug") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Display name") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = desc, onValueChange = { desc = it }, label = { Text("Description (optional)") }, modifier = Modifier.fillMaxWidth())
                OutlinedTextField(value = fields, onValueChange = { fields = it }, label = { Text("Placeholder fields (comma-sep)") }, modifier = Modifier.fillMaxWidth())
                Text("Required tier", style = MaterialTheme.typography.labelMedium)
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    tiers.forEach { t ->
                        androidx.compose.material3.FilterChip(
                            selected = tier == t, onClick = { tier = t }, label = { Text(t.replace('_', ' ')) },
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    val fieldList = fields.split(',').map { it.trim() }.filter { it.isNotEmpty() }
                    onConfirm(slug, name, desc, tier, fieldList)
                },
                enabled = slug.isNotBlank() && name.isNotBlank(),
                modifier = Modifier.testTag(KycTemplatesTestTags.CREATE_CONFIRM),
            ) { Text("Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
