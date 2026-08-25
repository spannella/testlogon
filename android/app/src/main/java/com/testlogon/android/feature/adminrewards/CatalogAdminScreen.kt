@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminrewards

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
import androidx.compose.material.icons.outlined.CardGiftcard
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Card
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Switch
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
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.adminrewards.AdminCatalogItemDto
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

object CatalogAdminTestTags {
    const val SCREEN = "reward_catalog_admin_screen"
    const val LIST = "reward_catalog_admin_list"
    const val EMPTY = "reward_catalog_admin_empty"
    const val FORBIDDEN = "reward_catalog_admin_forbidden"
    const val ERROR_RETRY = "reward_catalog_admin_error_retry"
    const val CREATE = "reward_catalog_admin_create"
    const val FORM_SUBMIT = "reward_catalog_admin_form_submit"
    const val FORM_NAME = "reward_catalog_admin_form_name"
    const val FORM_SORT = "reward_catalog_admin_form_sort"
    const val FORM_FEATURED = "reward_catalog_admin_form_featured"
    const val DELETE_CONFIRM = "reward_catalog_admin_delete_confirm"
    fun row(id: String) = "reward_catalog_row_" + id
    fun edit(id: String) = "reward_catalog_edit_" + id
    fun delete(id: String) = "reward_catalog_delete_" + id
    fun toggle(id: String) = "reward_catalog_toggle_" + id
    fun featured(id: String) = "reward_catalog_featured_" + id
}

@Composable
fun CatalogAdminRoute(
    onBack: () -> Unit,
    viewModel: CatalogAdminViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    CatalogAdminScreen(
        state = state,
        onBack = onBack,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onCreate = viewModel::create,
        onUpdate = viewModel::update,
        onDelete = viewModel::delete,
        onToggleActive = viewModel::toggleActive,
        onMessageShown = viewModel::clearMessage,
    )
}

@Composable
fun CatalogAdminScreen(
    state: CatalogAdminUiState,
    onBack: () -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onCreate: (CatalogDraft) -> Unit,
    onUpdate: (String, CatalogDraft) -> Unit,
    onDelete: (String) -> Unit,
    onToggleActive: (AdminCatalogItemDto) -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var editing by remember { mutableStateOf<EditTarget?>(null) }
    var deleteTarget by remember { mutableStateOf<AdminCatalogItemDto?>(null) }
    val content = state as? CatalogAdminUiState.Content

    LaunchedEffect(content?.message, content?.transientError) {
        val msg = content?.message ?: content?.transientError?.let { catalogAdminErrorMessage(it) }
        if (msg != null) {
            snackbar.showSnackbar(msg)
            onMessageShown()
        }
    }

    val canCreate = state is CatalogAdminUiState.Content || state is CatalogAdminUiState.Empty

    Scaffold(
        modifier = modifier.testTag(CatalogAdminTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("Rewards catalog") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            if (canCreate) {
                ExtendedFloatingActionButton(
                    onClick = { editing = EditTarget(id = null, draft = emptyDraft()) },
                    icon = { Icon(Icons.Outlined.Add, contentDescription = null) },
                    text = { Text("New reward") },
                    modifier = Modifier.testTag(CatalogAdminTestTags.CREATE),
                )
            }
        },
    ) { padding ->
        val isRefreshing = content?.isRefreshing == true
        PullToRefreshBox(
            isRefreshing = isRefreshing,
            onRefresh = onRefresh,
            modifier = Modifier.fillMaxSize().padding(padding),
        ) {
            when (state) {
                is CatalogAdminUiState.Loading -> LoadingState()
                is CatalogAdminUiState.Empty -> EmptyState(
                    modifier = Modifier.testTag(CatalogAdminTestTags.EMPTY),
                    title = "No rewards yet",
                    body = "Create the first redeemable reward members can spend points on.",
                    imageVector = Icons.Outlined.CardGiftcard,
                )
                is CatalogAdminUiState.Forbidden -> EmptyState(
                    modifier = Modifier.testTag(CatalogAdminTestTags.FORBIDDEN),
                    title = "Not authorised",
                    body = "You need operator access to manage the rewards catalog.",
                    imageVector = Icons.Outlined.Lock,
                    actionLabel = "Back",
                    onAction = onBack,
                )
                is CatalogAdminUiState.Error -> ErrorState(
                    modifier = Modifier.testTag(CatalogAdminTestTags.ERROR_RETRY),
                    message = catalogAdminErrorMessage(state.type),
                    onRetry = onRetry,
                )
                is CatalogAdminUiState.Content -> LazyColumn(
                    modifier = Modifier.fillMaxSize().testTag(CatalogAdminTestTags.LIST),
                    contentPadding = PaddingValues(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    items(items = state.items, key = { it.id.orEmpty() }) { item ->
                        CatalogRow(
                            item = item,
                            actionsEnabled = !state.actionInFlight,
                            onEdit = { editing = EditTarget(id = item.id, draft = item.toDraft()) },
                            onDelete = { deleteTarget = item },
                            onToggle = { onToggleActive(item) },
                        )
                    }
                }
            }
        }
    }

    editing?.let { target ->
        CatalogFormDialog(
            initial = target.draft,
            isEdit = target.id != null,
            onDismiss = { editing = null },
            onSubmit = { draft ->
                val id = target.id
                if (id == null) onCreate(draft) else onUpdate(id, draft)
                editing = null
            },
        )
    }

    deleteTarget?.let { item ->
        AlertDialog(
            onDismissRequest = { deleteTarget = null },
            title = { Text("Delete reward") },
            text = { Text("Delete this reward? Members will no longer see it in the catalog.") },
            confirmButton = {
                TextButton(
                    onClick = {
                        item.id?.let(onDelete)
                        deleteTarget = null
                    },
                    modifier = Modifier.testTag(CatalogAdminTestTags.DELETE_CONFIRM),
                ) { Text("Delete") }
            },
            dismissButton = { TextButton(onClick = { deleteTarget = null }) { Text("Cancel") } },
        )
    }
}

private data class EditTarget(val id: String?, val draft: CatalogDraft)

@Composable
private fun CatalogRow(
    item: AdminCatalogItemDto,
    actionsEnabled: Boolean,
    onEdit: () -> Unit,
    onDelete: () -> Unit,
    onToggle: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag(CatalogAdminTestTags.row(item.id.orEmpty()))) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(
                    item.name.orEmpty().ifBlank { "Reward" },
                    style = MaterialTheme.typography.titleMedium,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis,
                    modifier = Modifier.weight(1f),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    if (item.featured == true) {
                        AssistChip(
                            onClick = {},
                            enabled = false,
                            label = { Text("Featured") },
                            modifier = Modifier.testTag(CatalogAdminTestTags.featured(item.id.orEmpty())),
                        )
                    }
                    AssistChip(
                        onClick = {},
                        enabled = false,
                        label = { Text(item.kind ?: "perk") },
                    )
                }
            }
            item.description?.takeIf { it.isNotBlank() }?.let {
                Text(it, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant, maxLines = 2, overflow = TextOverflow.Ellipsis)
            }
            Row(horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("" + (item.costPoints ?: 0L) + " pts", style = MaterialTheme.typography.labelLarge, color = MaterialTheme.colorScheme.primary)
                Text(formatCents(item.valueCents ?: 0L), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                item.redeemedCount?.let {
                    Text("" + it + " redeemed", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
                Text("order " + (item.sortOrder ?: 0L), style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                val limit = item.stockLimit
                if (limit == null) {
                    Text("Unlimited stock", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                } else {
                    val remaining = (limit - (item.redeemedCount ?: 0).toLong()).coerceAtLeast(0L)
                    Text("" + remaining + " / " + limit + " left", style = MaterialTheme.typography.labelMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
                }
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Row(modifier = Modifier.weight(1f), verticalAlignment = Alignment.CenterVertically) {
                    Switch(
                        checked = item.active ?: false,
                        onCheckedChange = { if (actionsEnabled) onToggle() },
                        enabled = actionsEnabled,
                        modifier = Modifier.testTag(CatalogAdminTestTags.toggle(item.id.orEmpty())),
                    )
                    Text(if (item.active == true) "Active" else "Inactive", style = MaterialTheme.typography.labelMedium)
                }
                OutlinedButton(
                    onClick = onEdit,
                    enabled = actionsEnabled,
                    modifier = Modifier.testTag(CatalogAdminTestTags.edit(item.id.orEmpty())),
                ) { Text("Edit") }
                OutlinedButton(
                    onClick = onDelete,
                    enabled = actionsEnabled,
                    modifier = Modifier.testTag(CatalogAdminTestTags.delete(item.id.orEmpty())),
                ) { Text("Delete") }
            }
        }
    }
}

@Composable
private fun CatalogFormDialog(
    initial: CatalogDraft,
    isEdit: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (CatalogDraft) -> Unit,
) {
    var name by remember { mutableStateOf(initial.name) }
    var description by remember { mutableStateOf(initial.description) }
    var costText by remember { mutableStateOf(if (initial.costPoints > 0) initial.costPoints.toString() else "") }
    var valueText by remember { mutableStateOf(if (initial.valueCents > 0) initial.valueCents.toString() else "") }
    var kind by remember { mutableStateOf(initial.kind) }
    var active by remember { mutableStateOf(initial.active) }
    var featured by remember { mutableStateOf(initial.featured) }
    var stockText by remember { mutableStateOf(initial.stockLimit?.toString() ?: "") }
    var sortText by remember { mutableStateOf(if (initial.sortOrder != 0L) initial.sortOrder.toString() else "") }

    val costPoints = costText.trim().toLongOrNull() ?: 0L
    val valueCents = valueText.trim().toLongOrNull() ?: 0L
    // Blank stock field = UNLIMITED (null); any digits = a concrete cap.
    val stockLimit: Long? = stockText.trim().takeIf { it.isNotEmpty() }?.toLongOrNull()
    // Blank sort field = 0 (default weight); any digits = an explicit weight.
    val sortOrder: Long = sortText.trim().toLongOrNull() ?: 0L
    val validation = validateCatalogItem(name, costPoints, valueCents, kind, stockLimit, sortOrder)

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (isEdit) "Edit reward" else "New reward") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("Name") },
                    isError = validation.errorFor("name") != null,
                    supportingText = { validation.errorFor("name")?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth().testTag(CatalogAdminTestTags.FORM_NAME),
                )
                OutlinedTextField(
                    value = description,
                    onValueChange = { description = it },
                    label = { Text("Description") },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = costText,
                    onValueChange = { costText = it.filter(Char::isDigit) },
                    label = { Text("Cost (points)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = validation.errorFor("costPoints") != null,
                    supportingText = { validation.errorFor("costPoints")?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = valueText,
                    onValueChange = { valueText = it.filter(Char::isDigit) },
                    label = { Text("Value (cents)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = validation.errorFor("valueCents") != null,
                    supportingText = { validation.errorFor("valueCents")?.let { Text(it) } },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = stockText,
                    onValueChange = { stockText = it.filter(Char::isDigit) },
                    label = { Text("Stock limit") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = validation.errorFor("stockLimit") != null,
                    supportingText = {
                        val err = validation.errorFor("stockLimit")
                        if (err != null) Text(err) else Text("Blank = unlimited")
                    },
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = sortText,
                    onValueChange = { sortText = it.filter(Char::isDigit) },
                    label = { Text("Sort order") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    isError = validation.errorFor("sortOrder") != null,
                    supportingText = {
                        val err = validation.errorFor("sortOrder")
                        if (err != null) Text(err) else Text("Lower shows first; blank = 0")
                    },
                    modifier = Modifier.fillMaxWidth().testTag(CatalogAdminTestTags.FORM_SORT),
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    CATALOG_KINDS.forEach { k ->
                        FilterChip(
                            selected = kind == k,
                            onClick = { kind = k },
                            label = { Text(k) },
                        )
                    }
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(checked = active, onCheckedChange = { active = it })
                    Text(if (active) "Active" else "Inactive", style = MaterialTheme.typography.labelMedium)
                }
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Switch(
                        checked = featured,
                        onCheckedChange = { featured = it },
                        modifier = Modifier.testTag(CatalogAdminTestTags.FORM_FEATURED),
                    )
                    Text(if (featured) "Featured" else "Not featured", style = MaterialTheme.typography.labelMedium)
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    onSubmit(
                        CatalogDraft(
                            name = name,
                            description = description,
                            costPoints = costPoints,
                            valueCents = valueCents,
                            kind = kind,
                            active = active,
                            stockLimit = stockLimit,
                            featured = featured,
                            sortOrder = sortOrder,
                        )
                    )
                },
                enabled = validation.ok,
                modifier = Modifier.testTag(CatalogAdminTestTags.FORM_SUBMIT),
            ) { Text(if (isEdit) "Save" else "Create") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

internal fun formatCents(cents: Long): String {
    val dollars = cents / 100.0
    return "$" + "%,.2f".format(dollars)
}

internal fun catalogAdminErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}
