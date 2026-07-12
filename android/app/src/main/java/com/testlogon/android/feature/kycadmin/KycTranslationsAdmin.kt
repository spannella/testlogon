@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Add
import androidx.compose.material.icons.outlined.Delete
import androidx.compose.material.icons.outlined.Translate
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.kycadmin.KycTranslationCoverageDto
import com.testlogon.android.data.kycadmin.KycTranslationDto
import com.testlogon.android.data.kycadmin.KycTranslationsAdminRepository
import com.testlogon.android.feature.adminops.AdminOpsErrorType
import com.testlogon.android.feature.adminops.adminOpsErrorFor
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.util.Locale
import javax.inject.Inject

sealed interface KycTranslationsLoadState {
    data object Loading : KycTranslationsLoadState
    data class Data(val isRefreshing: Boolean = false) : KycTranslationsLoadState
    data object Forbidden : KycTranslationsLoadState
    data class Error(val type: AdminOpsErrorType) : KycTranslationsLoadState
}

data class KycTranslationsUiState(
    val load: KycTranslationsLoadState = KycTranslationsLoadState.Loading,
    val language: String = "en",
    val coverage: Map<String, KycTranslationCoverageDto> = emptyMap(),
    val items: List<KycTranslationDto> = emptyList(),
    val actionInFlight: Boolean = false,
    val message: String? = null,
)

@HiltViewModel
class KycTranslationsAdminViewModel @Inject constructor(
    private val repo: KycTranslationsAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycTranslationsUiState())
    val state: StateFlow<KycTranslationsUiState> = _state.asStateFlow()

    init { fetch(false) }
    fun retry() = fetch(false)
    fun refresh() {
        (_state.value.load as? KycTranslationsLoadState.Data)?.let { _state.value = _state.value.copy(load = it.copy(isRefreshing = true)) }
        fetch(true)
    }
    fun clearMessage() { _state.value = _state.value.copy(message = null) }

    fun setLanguage(lang: String) {
        if (_state.value.language == lang) return
        _state.value = _state.value.copy(language = lang, load = KycTranslationsLoadState.Loading)
        fetch(false)
    }

    fun set(key: String, value: String) = act("Saved") { repo.set(_state.value.language, key, value, status = "published") }
    fun delete(key: String) = act("Deleted") { repo.delete(_state.value.language, key) }

    private fun failMsg(status: Int): String =
        if (status == 403) "Not authorised." else adminOpsErrorMessage(adminOpsErrorFor(status))

    private fun act(okLabel: String, block: suspend () -> ApiResult<Unit>) {
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

    private fun fetch(isRefresh: Boolean) {
        if (!isRefresh) _state.value = _state.value.copy(load = KycTranslationsLoadState.Loading)
        viewModelScope.launch {
            val cov = repo.coverage()
            val coverage = (cov as? ApiResult.Success)?.data ?: _state.value.coverage
            when (val r = repo.list(_state.value.language)) {
                is ApiResult.Success -> _state.value = _state.value.copy(
                    load = KycTranslationsLoadState.Data(), coverage = coverage, items = r.data,
                )
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    load = if (r.error.status == 403) KycTranslationsLoadState.Forbidden else KycTranslationsLoadState.Error(adminOpsErrorFor(r.error.status)),
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(load = KycTranslationsLoadState.Error(AdminOpsErrorType.NETWORK))
            }
        }
    }
}

object KycTranslationsTestTags {
    const val SCREEN = "kyc_translations_screen"
    const val LIST = "kyc_translations_list"
    const val FORBIDDEN = "kyc_translations_forbidden"
    const val RETRY = "kyc_translations_retry"
    const val FAB = "kyc_translations_fab"
    const val EDIT_CONFIRM = "kyc_translations_edit_confirm"
    fun row(key: String) = "kyc_translations_row_$key"
}

@Composable
fun KycTranslationsAdminRoute(
    onBack: () -> Unit,
    viewModel: KycTranslationsAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    var editKey by remember { mutableStateOf<KycTranslationDto?>(null) }
    var addNew by remember { mutableStateOf(false) }

    LaunchedEffect(state.message) { state.message?.let { snackbar.showSnackbar(it); viewModel.clearMessage() } }

    Scaffold(
        modifier = Modifier.testTag(KycTranslationsTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("KYC translations") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { addNew = true }, modifier = Modifier.testTag(KycTranslationsTestTags.FAB)) {
                Icon(Icons.Outlined.Add, contentDescription = "Add key")
            }
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            LanguageChips(
                languages = (state.coverage.keys + state.language).distinct().sorted(),
                selected = state.language,
                onSelect = viewModel::setLanguage,
            )
            state.coverage[state.language]?.let { c ->
                Text(
                    "Coverage: ${c.translatedKeys}/${c.totalKeys} (${String.format(Locale.US, "%.0f%%", c.coveragePct)})",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            androidx.compose.material3.pulltorefresh.PullToRefreshBox(
                isRefreshing = (state.load as? KycTranslationsLoadState.Data)?.isRefreshing == true,
                onRefresh = viewModel::refresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (val l = state.load) {
                    is KycTranslationsLoadState.Loading -> LoadingState()
                    is KycTranslationsLoadState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycTranslationsTestTags.FORBIDDEN),
                        title = "Not authorised", body = "Admin access required.",
                        imageVector = Icons.Outlined.Translate, actionLabel = "Back", onAction = onBack,
                    )
                    is KycTranslationsLoadState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycTranslationsTestTags.RETRY),
                        message = adminOpsErrorMessage(l.type), onRetry = viewModel::retry,
                    )
                    is KycTranslationsLoadState.Data -> {
                        if (state.items.isEmpty()) {
                            EmptyState(title = "No translations", body = "No keys for ${state.language}.", imageVector = Icons.Outlined.Translate)
                        } else {
                            LazyColumn(
                                modifier = Modifier.fillMaxSize().testTag(KycTranslationsTestTags.LIST),
                                contentPadding = PaddingValues(16.dp),
                                verticalArrangement = Arrangement.spacedBy(8.dp),
                            ) {
                                items(items = state.items, key = { it.key }) { t ->
                                    Card(
                                        modifier = Modifier.fillMaxWidth().testTag(KycTranslationsTestTags.row(t.key)),
                                        onClick = { editKey = t },
                                    ) {
                                        Row(Modifier.padding(12.dp).fillMaxWidth(), verticalAlignment = androidx.compose.ui.Alignment.CenterVertically) {
                                            Column(Modifier.weight(1f), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                                                Text(t.key, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                                Text(t.value, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                            }
                                            IconButton(onClick = { viewModel.delete(t.key) }, enabled = !state.actionInFlight) {
                                                Icon(Icons.Outlined.Delete, contentDescription = "Delete")
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    editKey?.let { t ->
        EditTranslationDialog(
            keyLocked = t.key, initialValue = t.value,
            onDismiss = { editKey = null },
            onConfirm = { _, value -> viewModel.set(t.key, value); editKey = null },
        )
    }
    if (addNew) {
        EditTranslationDialog(
            keyLocked = null, initialValue = "",
            onDismiss = { addNew = false },
            onConfirm = { key, value -> viewModel.set(key, value); addNew = false },
        )
    }
}

@Composable
private fun LanguageChips(languages: List<String>, selected: String, onSelect: (String) -> Unit) {
    val scroll = rememberScrollState()
    Row(
        Modifier
            .fillMaxWidth()
            .horizontalScroll(scroll)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        languages.forEach { lang ->
            androidx.compose.material3.FilterChip(
                selected = selected == lang, onClick = { onSelect(lang) }, label = { Text(lang) },
            )
        }
    }
}

@Composable
private fun EditTranslationDialog(
    keyLocked: String?,
    initialValue: String,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var key by remember { mutableStateOf(keyLocked ?: "") }
    var value by remember { mutableStateOf(initialValue) }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (keyLocked == null) "Add translation" else "Edit translation") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = key, onValueChange = { key = it }, label = { Text("Key") },
                    enabled = keyLocked == null, modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(value = value, onValueChange = { value = it }, label = { Text("Value") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onConfirm(key, value) },
                enabled = key.isNotBlank() && value.isNotBlank(),
                modifier = Modifier.testTag(KycTranslationsTestTags.EDIT_CONFIRM),
            ) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
