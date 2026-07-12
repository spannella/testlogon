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
import androidx.compose.material.icons.outlined.FactCheck
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.getValue
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

/**
 * Generic list+detail scaffold shared by the KYC-admin document-shaped review queues (documents,
 * residency, proof-of-funds, id-scanner, liveness-call, screening, business). Each module maps its
 * DTOs into these lightweight UI models and supplies its own decision options + action lambda.
 */

data class KycReviewItemUi(
    val id: String,
    val title: String,
    val subtitle: String,
    val badge: String? = null,
)

data class KycReviewFieldUi(val label: String, val value: String)

data class KycReviewDetailUi(
    val id: String,
    val title: String,
    val status: String,
    val imageUrl: String? = null,
    val fields: List<KycReviewFieldUi> = emptyList(),
    /** Whether the decision actions should be offered (e.g. still pending). */
    val actionable: Boolean = true,
)

sealed interface KycReviewListState {
    data object Loading : KycReviewListState
    data class Data(val items: List<KycReviewItemUi>, val isRefreshing: Boolean = false) : KycReviewListState
    data object Empty : KycReviewListState
    data object Forbidden : KycReviewListState
    data class Error(val type: AdminOpsErrorType) : KycReviewListState
}

sealed interface KycReviewDetailState {
    data object Loading : KycReviewDetailState
    data class Data(val detail: KycReviewDetailUi) : KycReviewDetailState
    data object Forbidden : KycReviewDetailState
    data class Error(val type: AdminOpsErrorType) : KycReviewDetailState
}

data class KycReviewUiState(
    val statusFilter: String,
    val list: KycReviewListState = KycReviewListState.Loading,
    val detail: KycReviewDetailState? = null,
    val actionInFlight: Boolean = false,
    val message: String? = null,
    val transientError: AdminOpsErrorType? = null,
)

object KycReviewTestTags {
    fun screen(m: String) = "kyc_review_${m}_screen"
    fun list(m: String) = "kyc_review_${m}_list"
    fun empty(m: String) = "kyc_review_${m}_empty"
    fun forbidden(m: String) = "kyc_review_${m}_forbidden"
    fun retry(m: String) = "kyc_review_${m}_retry"
    fun detail(m: String) = "kyc_review_${m}_detail"
    fun row(m: String, id: String) = "kyc_review_${m}_row_$id"
    fun statusChip(m: String, s: String) = "kyc_review_${m}_status_$s"
    const val DECISION_CONFIRM = "kyc_review_decision_confirm"
    fun option(v: String) = "kyc_review_option_$v"
    fun actionBtn(v: String) = "kyc_review_action_$v"
}

/**
 * The generic queue+detail UI.
 * @param moduleKey short unique key for test tags (e.g. "documents").
 * @param decisionOptions the decision values offered (e.g. approve/reject). Empty = read-only queue.
 * @param onDecide (id, decision, note) — the module's action.
 */
@Composable
fun KycReviewQueueScreen(
    moduleKey: String,
    title: String,
    statuses: List<String>,
    decisionOptions: List<String>,
    state: KycReviewUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onSetStatus: (String) -> Unit,
    onOpenDetail: (String) -> Unit,
    onDecide: (String, String, String) -> Unit,
    onCloseDetail: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    LaunchedEffect(state.message, state.transientError) {
        val msg = state.message ?: state.transientError?.let { kycAdminErrorMessage(it) }
        if (msg != null) { snackbar.showSnackbar(msg); onMessageShown() }
    }

    if (state.detail != null) {
        BackHandler(onBack = onCloseDetail)
        KycReviewDetailScreen(
            moduleKey = moduleKey,
            detail = state.detail,
            decisionOptions = decisionOptions,
            actionInFlight = state.actionInFlight,
            snackbar = snackbar,
            onBack = onCloseDetail,
            onDecide = onDecide,
            modifier = modifier,
        )
        return
    }

    Scaffold(
        modifier = modifier.testTag(KycReviewTestTags.screen(moduleKey)),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text(title) },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            if (statuses.isNotEmpty()) {
                Row(
                    Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()).padding(horizontal = 12.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    statuses.forEach { s ->
                        FilterChip(
                            selected = state.statusFilter == s,
                            onClick = { onSetStatus(s) },
                            label = { Text(s.replace('_', ' ')) },
                            modifier = Modifier.testTag(KycReviewTestTags.statusChip(moduleKey, s)),
                        )
                    }
                }
            }
            val isRefreshing = (state.list as? KycReviewListState.Data)?.isRefreshing == true
            PullToRefreshBox(isRefreshing = isRefreshing, onRefresh = onRefresh, modifier = Modifier.fillMaxSize()) {
                when (val l = state.list) {
                    is KycReviewListState.Loading -> LoadingState()
                    is KycReviewListState.Empty -> EmptyState(
                        modifier = Modifier.testTag(KycReviewTestTags.empty(moduleKey)),
                        title = "Nothing to review",
                        body = "There are no ${state.statusFilter.replace('_', ' ')} items.",
                        imageVector = Icons.Outlined.FactCheck,
                    )
                    is KycReviewListState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(KycReviewTestTags.forbidden(moduleKey)),
                        title = "Not authorised",
                        body = "You need admin access to review these.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back", onAction = onBack,
                    )
                    is KycReviewListState.Error -> ErrorState(
                        modifier = Modifier.testTag(KycReviewTestTags.retry(moduleKey)),
                        message = kycAdminErrorMessage(l.type), onRetry = onRetry,
                    )
                    is KycReviewListState.Data -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag(KycReviewTestTags.list(moduleKey)),
                        contentPadding = PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(items = l.items, key = { it.id }) { item ->
                            Card(
                                modifier = Modifier.fillMaxWidth().testTag(KycReviewTestTags.row(moduleKey, item.id)),
                                onClick = { onOpenDetail(item.id) },
                            ) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                                    Text(item.title, style = MaterialTheme.typography.titleSmall, maxLines = 1, overflow = TextOverflow.Ellipsis)
                                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                                        item.badge?.let { Text(it.replace('_', ' '), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.primary) }
                                        Text(item.subtitle, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 1, overflow = TextOverflow.Ellipsis)
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
private fun KycReviewDetailScreen(
    moduleKey: String,
    detail: KycReviewDetailState,
    decisionOptions: List<String>,
    actionInFlight: Boolean,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onDecide: (String, String, String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var dialogOpen by remember { mutableStateOf(false) }

    Scaffold(
        modifier = modifier.testTag(KycReviewTestTags.detail(moduleKey)),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Detail") },
                navigationIcon = { IconButton(onClick = onBack) { Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back") } },
            )
        },
    ) { padding ->
        when (detail) {
            is KycReviewDetailState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is KycReviewDetailState.Forbidden -> EmptyState(
                modifier = Modifier.padding(padding).testTag(KycReviewTestTags.forbidden(moduleKey)),
                title = "Not authorised", body = "Admin access required.", imageVector = Icons.Outlined.Lock,
                actionLabel = "Back", onAction = onBack,
            )
            is KycReviewDetailState.Error -> ErrorState(
                modifier = Modifier.padding(padding), message = kycAdminErrorMessage(detail.type), onRetry = onBack,
            )
            is KycReviewDetailState.Data -> {
                val d = detail.detail
                LazyColumn(
                    modifier = Modifier.fillMaxSize().padding(padding),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    item {
                        Card(Modifier.fillMaxWidth()) {
                            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                Text(d.title, style = MaterialTheme.typography.titleMedium)
                                Text("Status: ${d.status.replace('_', ' ')}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.primary)
                            }
                        }
                    }
                    if (d.imageUrl != null) {
                        item {
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(12.dp)) {
                                    KycAdminDocImage(imageUrl = d.imageUrl, contentDescription = "Submitted document", imageTestTag = "${moduleKey}_doc_image")
                                }
                            }
                        }
                    }
                    if (d.fields.isNotEmpty()) {
                        item {
                            Card(Modifier.fillMaxWidth()) {
                                Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                    d.fields.forEach { f ->
                                        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                            Text(f.label, style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                            Text(f.value, style = MaterialTheme.typography.bodyMedium, maxLines = 2, overflow = TextOverflow.Ellipsis)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    if (decisionOptions.isNotEmpty() && d.actionable) {
                        item {
                            if (actionInFlight) {
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                            } else {
                                Button(
                                    onClick = { dialogOpen = true },
                                    modifier = Modifier.fillMaxWidth().testTag(KycReviewTestTags.actionBtn("decide")),
                                ) { Text("Take decision") }
                            }
                        }
                    }
                }

                if (dialogOpen) {
                    DecisionOptionDialog(
                        options = decisionOptions,
                        onDismiss = { dialogOpen = false },
                        onConfirm = { decision, note -> onDecide(d.id, decision, note); dialogOpen = false },
                    )
                }
            }
        }
    }
}

@Composable
private fun DecisionOptionDialog(
    options: List<String>,
    onDismiss: () -> Unit,
    onConfirm: (String, String) -> Unit,
) {
    var selected by remember { mutableStateOf(options.first()) }
    var note by remember { mutableStateOf("") }
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text("Decision") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                options.forEach { o ->
                    Row(
                        Modifier.fillMaxWidth().selectable(selected = selected == o, onClick = { selected = o }).testTag(KycReviewTestTags.option(o)),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        RadioButton(selected = selected == o, onClick = { selected = o })
                        Text(o.replace('_', ' ').replaceFirstChar { it.uppercase() })
                    }
                }
                OutlinedTextField(value = note, onValueChange = { note = it }, label = { Text("Note") }, modifier = Modifier.fillMaxWidth())
            }
        },
        confirmButton = { TextButton(onClick = { onConfirm(selected, note) }, modifier = Modifier.testTag(KycReviewTestTags.DECISION_CONFIRM)) { Text("Confirm") } },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}
