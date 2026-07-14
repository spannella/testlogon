@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminmod

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
import androidx.compose.material.icons.outlined.CheckCircle
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Card
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.pulltorefresh.PullToRefreshBox
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
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
import com.testlogon.android.data.adminmod.ModerationAdminRepository
import com.testlogon.android.data.adminmod.ModerationBanEntryDto
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import javax.inject.Inject

/** MODX-19 (D4): the active-ban roster + one-tap lift. */
object BanManagementTestTags {
    const val SCREEN = "ban_mgmt_screen"
    const val LIST = "ban_mgmt_list"
    const val EMPTY = "ban_mgmt_empty"
    const val FORBIDDEN = "ban_mgmt_forbidden"
    fun ban(userId: String) = "ban_row_$userId"
    fun lift(userId: String) = "ban_lift_$userId"
}

sealed interface BanManagementUiState {
    data object Loading : BanManagementUiState
    data class Content(
        val bans: List<ModerationBanEntryDto>,
        val liftInFlight: String? = null,
        val message: String? = null,
    ) : BanManagementUiState
    data object Empty : BanManagementUiState
    data object Forbidden : BanManagementUiState
    data class Error(val type: AdminOpsErrorType) : BanManagementUiState
}

@HiltViewModel
class BanManagementViewModel @Inject constructor(
    private val repo: ModerationAdminRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<BanManagementUiState>(BanManagementUiState.Loading)
    val state: StateFlow<BanManagementUiState> = _state.asStateFlow()

    init {
        load()
    }

    fun retry() = load()

    fun load() {
        _state.value = BanManagementUiState.Loading
        viewModelScope.launch {
            when (val r = repo.listBans(includeInactive = false)) {
                is ApiResult.Success ->
                    _state.value = if (r.data.items.isEmpty()) BanManagementUiState.Empty
                    else BanManagementUiState.Content(r.data.items)
                is ApiResult.Failure -> _state.value = when (r.error.status) {
                    403 -> BanManagementUiState.Forbidden
                    401 -> BanManagementUiState.Error(AdminOpsErrorType.AUTH)
                    else -> BanManagementUiState.Error(AdminOpsErrorType.SERVER)
                }
                is ApiResult.NetworkError -> _state.value = BanManagementUiState.Error(AdminOpsErrorType.NETWORK)
            }
        }
    }

    fun lift(userId: String) {
        val cur = _state.value as? BanManagementUiState.Content ?: return
        if (cur.liftInFlight != null) return
        _state.value = cur.copy(liftInFlight = userId, message = null)
        viewModelScope.launch {
            when (val r = repo.liftBan(userId, "lifted from ban management")) {
                is ApiResult.Success -> {
                    val prior = _state.value as? BanManagementUiState.Content ?: return@launch
                    val remaining = prior.bans.filterNot { it.userId == userId }
                    _state.value = if (remaining.isEmpty()) BanManagementUiState.Empty
                    else BanManagementUiState.Content(remaining, message = "Ban lifted.")
                }
                is ApiResult.Failure -> setMessage(if (r.error.status == 403) "Not authorised to lift bans." else "Lift failed. Try again.")
                is ApiResult.NetworkError -> setMessage("You appear to be offline. Check your connection.")
            }
        }
    }

    private fun setMessage(msg: String) {
        val cur = _state.value as? BanManagementUiState.Content ?: return
        _state.value = cur.copy(liftInFlight = null, message = msg)
    }

    fun clearMessage() {
        val cur = _state.value as? BanManagementUiState.Content ?: return
        _state.value = cur.copy(message = null)
    }
}

@Composable
fun BanManagementRoute(
    onBack: () -> Unit,
    viewModel: BanManagementViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    BanManagementScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::load,
        onLift = viewModel::lift,
        onClearMessage = viewModel::clearMessage,
    )
}

@Composable
fun BanManagementScreen(
    state: BanManagementUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onLift: (String) -> Unit,
    onClearMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val content = state as? BanManagementUiState.Content
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(content?.message) {
        content?.message?.let {
            snackbarHostState.showSnackbar(it)
            onClearMessage()
        }
    }
    Scaffold(
        modifier = modifier.testTag(BanManagementTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Ban management") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        PullToRefreshBox(
            isRefreshing = false,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is BanManagementUiState.Loading -> LoadingState()
                is BanManagementUiState.Empty -> EmptyState(
                    modifier = Modifier.testTag(BanManagementTestTags.EMPTY),
                    title = "No active bans",
                    body = "No accounts are currently banned.",
                    imageVector = Icons.Outlined.CheckCircle,
                )
                is BanManagementUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(BanManagementTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need content-moderation admin access to manage bans.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is BanManagementUiState.Error -> ErrorState(
                    message = adminOpsErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is BanManagementUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(BanManagementTestTags.LIST),
                    contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = state.bans, key = { it.userId + it.enforcementId }) { ban ->
                        BanRow(ban = ban, liftInFlight = state.liftInFlight == ban.userId, onLift = { onLift(ban.userId) })
                    }
                }
            }
        }
    }
}

@Composable
private fun BanRow(ban: ModerationBanEntryDto, liftInFlight: Boolean, onLift: () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(BanManagementTestTags.ban(ban.userId))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = ban.userId,
                style = MaterialTheme.typography.titleSmall,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
            Text(
                text = if (ban.permanent) "Permanent ban" else "Ban (${ban.durationDays} days)",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.primary,
            )
            if (ban.note.isNotBlank()) {
                Text(
                    text = ban.note,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    maxLines = 2,
                    overflow = TextOverflow.Ellipsis,
                )
            }
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End, verticalAlignment = Alignment.CenterVertically) {
                OutlinedButton(
                    onClick = onLift,
                    enabled = !liftInFlight,
                    modifier = Modifier.testTag(BanManagementTestTags.lift(ban.userId)),
                ) {
                    Text(if (liftInFlight) "Lifting…" else "Lift ban")
                }
            }
        }
    }
}
