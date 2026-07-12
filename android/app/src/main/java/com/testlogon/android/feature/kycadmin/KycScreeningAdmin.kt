@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.kycadmin

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.selection.selectable
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Gavel
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
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
import com.testlogon.android.data.kycadmin.KycScreeningAdminRepository
import com.testlogon.android.data.kycadmin.KycScreeningResultDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** A6 — sanctions/PEP screening review queue (pending matches + review clear/confirm/escalate + rescreen). */

val KYC_SCREENING_RESULTS = listOf("potential_match", "confirmed_match", "clear")
val KYC_SCREENING_DECISIONS = listOf("clear", "confirm", "escalate")

sealed interface ScreeningListState {
    data object Loading : ScreeningListState
    data class Data(val items: List<KycScreeningResultDto>, val isRefreshing: Boolean = false) : ScreeningListState
    data object Empty : ScreeningListState
    data object Forbidden : ScreeningListState
    data class Error(val type: AdminOpsErrorType) : ScreeningListState
}

data class KycScreeningAdminUiState(
    val resultFilter: String = "potential_match",
    val list: ScreeningListState = ScreeningListState.Loading,
    val detail: KycScreeningResultDto? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

@HiltViewModel
class KycScreeningAdminViewModel @Inject constructor(
    private val repo: KycScreeningAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow(KycScreeningAdminUiState())
    val state: StateFlow<KycScreeningAdminUiState> = _state.asStateFlow()

    init { fetch(false) }

    fun retry() = fetch(false)

    fun setResult(result: String) {
        if (_state.value.resultFilter == result) return
        _state.value = _state.value.copy(resultFilter = result, list = ScreeningListState.Loading)
        fetch(false)
    }

    fun refresh() {
        val cur = _state.value.list
        _state.value = _state.value.copy(list = if (cur is ScreeningListState.Data) cur.copy(isRefreshing = true) else cur, transientError = null)
        fetch(true)
    }

    private fun fetch(isRefresh: Boolean) {
        viewModelScope.launch {
            when (val r = repo.pending(_state.value.resultFilter)) {
                is ApiResult.Success -> {
                    val items = r.data
                    _state.value = _state.value.copy(list = if (items.isEmpty()) ScreeningListState.Empty else ScreeningListState.Data(items))
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(
                    list = when (r.error.status) {
                        403 -> ScreeningListState.Forbidden
                        else -> (_state.value.list as? ScreeningListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                            ?: ScreeningListState.Error(if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                    },
                    transientError = if (isRefresh && _state.value.list is ScreeningListState.Data) (if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER) else null,
                )
                is ApiResult.NetworkError -> _state.value = _state.value.copy(
                    list = (_state.value.list as? ScreeningListState.Data)?.takeIf { isRefresh }?.copy(isRefreshing = false)
                        ?: ScreeningListState.Error(AdminOpsErrorType.NETWORK),
                    transientError = if (isRefresh && _state.value.list is ScreeningListState.Data) AdminOpsErrorType.NETWORK else null,
                )
            }
        }
    }

    fun openDetail(screeningId: String) {
        val item = (_state.value.list as? ScreeningListState.Data)?.items?.firstOrNull { it.screeningId == screeningId }
        if (item != null) _state.value = _state.value.copy(detail = item)
    }

    fun review(decision: String, note: String) {
        val d = _state.value.detail ?: return
        val caseId = d.caseId; val screenKey = d.screenKey
        if (caseId.isNullOrBlank() || screenKey.isNullOrBlank() || _state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.review(caseId, screenKey, decision, note)) {
                is ApiResult.Success -> {
                    _state.value = _state.value.copy(actionInFlight = false, message = "Match $decision", detail = r.data)
                    fetch(true)
                }
                is ApiResult.Failure -> _state.value = _state.value.copy(actionInFlight = false, transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun rescreen() {
        val caseId = _state.value.detail?.caseId
        if (caseId.isNullOrBlank() || _state.value.actionInFlight) return
        _state.value = _state.value.copy(actionInFlight = true, transientError = null, message = null)
        viewModelScope.launch {
            when (val r = repo.rescreen(caseId)) {
                is ApiResult.Success -> _state.value = _state.value.copy(actionInFlight = false, message = "Rescreen triggered")
                is ApiResult.Failure -> _state.value = _state.value.copy(actionInFlight = false, transientError = if (r.error.status == 401) AdminOpsErrorType.AUTH else AdminOpsErrorType.SERVER)
                is ApiResult.NetworkError -> _state.value = _state.value.copy(actionInFlight = false, transientError = AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun closeDetail() { _state.value = _state.value.copy(detail = null) }
    fun clearMessage() { _state.value = _state.value.copy(message = null, transientError = null) }
}

object KycScreeningAdminTestTags {
    const val SCREEN = "kyc_screening_screen"
    const val LIST = "kyc_screening_list"
    const val EMPTY = "kyc_screening_empty"
    const val FORBIDDEN = "kyc_screening_forbidden"
    const val RETRY = "kyc_screening_retry"
    const val DETAIL = "kyc_screening_detail"
    const val REVIEW = "kyc_screening_review"
    const val RESCREEN = "kyc_screening_rescreen"
    const val REVIEW_CONFIRM = "kyc_screening_review_confirm"
    fun row(id: String) = "kyc_screening_row_$id"
    fun resultChip(s: String) = "kyc_screening_result_$s"
}

@Composable
fun KycScreeningAdminRoute(onBack: () -> Unit, viewModel: KycScreeningAdminViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { kycAdminErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); viewModel.clearMessage() }
    }

    val detail = state.detail
    if (detail != null) {
        BackHandler(onBack = viewModel::closeDetail)
        ScreeningDetail(detail, state.actionInFlight, snackbar, viewModel::closeDetail, viewModel::review, viewModel::rescreen)
        return
    }

    Scaffold(
        modifier = Modifier.testTag(KycScreeningAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Screening review") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            Row(
                Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                KYC_SCREENING_RESULTS.forEach { s ->
                    FilterChip(
                        selected = state.resultFilter == s,
                        onClick = { viewModel.setResult(s) },
                        label = { Text(s.replace('_', ' ')) },
                        modifier = Modifier.testTag(KycScreeningAdminTestTags.resultChip(s)),
                    )
                }
            }
            val isRefreshing = (state.list as? ScreeningListState.Data)?.isRefreshing == true
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = viewModel::refresh, modifier = Modifier.fillMaxSize()) {
                when (val l = state.list) {
                    is ScreeningListState.Loading -> LoadingState()
                    is ScreeningListState.Empty -> EmptyState(
                        modifier = Modifier.testTag(KycScreeningAdminTestTags.EMPTY),
                        title = "Nothing to review", body = "No ${state.resultFilter.replace('_', ' ')} results.",
                        imageVector = Icons.Outlined.Gavel,
                    )
                    is ScreeningListState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycScreeningAdminTestTags.FORBIDDEN),
                        title = "Not authorised", body = "You need admin access to review screening.",
                        imageVector = Icons.Outlined.Lock, actionLabel = "Back", onAction = onBack,
                    )
                    is ScreeningListState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycScreeningAdminTestTags.RETRY),
                        message = kycAdminErrorMessage(l.type), onRetry = viewModel::retry,
                    )
                    is ScreeningListState.Data -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(KycScreeningAdminTestTags.LIST),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = l.items, key = { it.screeningId }) { r ->
                            Card(modifier = Modifier.fillMaxWidth().testTag(KycScreeningAdminTestTags.row(r.screeningId)), onClick = { viewModel.openDetail(r.screeningId) }) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(r.userSub ?: r.caseId ?: r.screeningId, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        Text(r.result.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.error)
                                        Text("${r.matchDetails.size} matches", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                        Text(r.screenType.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
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

@Composable
private fun ScreeningDetail(
    r: KycScreeningResultDto,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onReview: (String, String) -> Unit,
    onRescreen: () -> Unit,
) {
    var dialog by remember { mutableStateOf(false) }
    Scaffold(
        modifier = Modifier.testTag(KycScreeningAdminTestTags.DETAIL),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Screening result") },
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
                Card(Modifier.fillMaxWidth()) {
                    Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                        Text(r.userSub ?: r.caseId ?: r.screeningId, style = MaterialTheme.typography.titleMedium)
                        Text("Result: ${r.result.replace('_', ' ')}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.error)
                        Text("Type: ${r.screenType.replace('_', ' ')} - ${r.provider}", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        r.reviewDecision?.let { Text("Prior decision: $it", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.tertiary) }
                    }
                }
            }
            if (r.matchDetails.isNotEmpty()) {
                item { Text("Matches", style = MaterialTheme.typography.titleSmall) }
                items(items = r.matchDetails, key = { it.listName + it.matchedName }) { m ->
                    Card(Modifier.fillMaxWidth()) {
                        Column(Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                            Text(m.matchedName, style = MaterialTheme.typography.bodyMedium)
                            Text("${m.listName} - ${m.entityType} - ${(m.matchScore * 100).toInt()}%", style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                        }
                    }
                }
            }
            item {
                if (actionInFlight) {
                    Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                } else {
                    Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(onClick = { dialog = true }, modifier = Modifier.fillMaxWidth().testTag(KycScreeningAdminTestTags.REVIEW)) { Text("Review match") }
                        OutlinedButton(onClick = onRescreen, modifier = Modifier.fillMaxWidth().testTag(KycScreeningAdminTestTags.RESCREEN)) { Text("Rescreen case") }
                    }
                }
            }
        }
    }

    if (dialog) {
        var selected by remember { mutableStateOf(KYC_SCREENING_DECISIONS.first()) }
        var note by remember { mutableStateOf("") }
        AlertDialog(
            onDismissRequest = { dialog = false },
            title = { Text("Review match") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                    KYC_SCREENING_DECISIONS.forEach { o ->
                        Row(Modifier.fillMaxWidth().selectable(selected = selected == o, onClick = { selected = o }), verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(selected = selected == o, onClick = { selected = o })
                            Text(o.replaceFirstChar { it.uppercase() })
                        }
                    }
                    OutlinedTextField(value = note, onValueChange = { note = it }, label = { Text("Note") }, modifier = Modifier.fillMaxWidth())
                }
            },
            confirmButton = { TextButton(onClick = { onReview(selected, note); dialog = false }, modifier = Modifier.testTag(KycScreeningAdminTestTags.REVIEW_CONFIRM)) { Text("Confirm") } },
            dismissButton = { TextButton(onClick = { dialog = false }) { Text("Cancel") } },
        )
    }
}
