@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.adminroot

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.data.adminroot.AdminTierAnalyticsDto
import com.testlogon.android.data.adminroot.AdminTierDto
import com.testlogon.android.data.adminroot.AdminTierForm
import com.testlogon.android.data.adminroot.AdminTiersRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.text.NumberFormat
import java.util.Locale
import javax.inject.Inject

object AdminTiersTags {
    const val SCREEN = "admin_tiers_screen"
    const val FORBIDDEN = "admin_tiers_forbidden"
    const val RETRY = "admin_tiers_retry"
    const val FAB = "admin_tiers_fab"
    const val ROW = "admin_tiers_row"
}

private val moneyFmt: NumberFormat = NumberFormat.getCurrencyInstance(Locale.US)
internal fun tierCents(v: Int): String = moneyFmt.format(v / 100.0)
internal fun tierCents(v: Long): String = moneyFmt.format(v / 100.0)

sealed interface AdminTiersUiState {
    data object Loading : AdminTiersUiState
    data class Content(
        val tiers: List<AdminTierDto>,
        val analytics: AdminTierAnalyticsDto,
        val isRefreshing: Boolean = false,
        val actionError: String? = null,
    ) : AdminTiersUiState
    data object Forbidden : AdminTiersUiState
    data class Error(val type: AdminRootErrorType) : AdminTiersUiState
}

@HiltViewModel
class AdminTiersViewModel @Inject constructor(
    private val repo: AdminTiersRepository,
) : ViewModel() {

    private val _state = MutableStateFlow<AdminTiersUiState>(AdminTiersUiState.Loading)
    val state: StateFlow<AdminTiersUiState> = _state.asStateFlow()

    init { load(reset = true) }

    fun retry() = load(reset = true)

    fun refresh() {
        (_state.value as? AdminTiersUiState.Content)?.let { _state.value = it.copy(isRefreshing = true) }
        load(reset = false)
    }

    fun create(form: AdminTierForm) = mutate { repo.create(form) }
    fun update(tierId: String, form: AdminTierForm) = mutate { repo.update(tierId, form) }
    fun archive(tierId: String) = mutate { repo.archive(tierId) }
    fun unarchive(tierId: String) = mutate { repo.unarchive(tierId) }
    fun delete(tierId: String) = mutate { repo.delete(tierId) }

    private fun mutate(op: suspend () -> ApiResult<*>) {
        viewModelScope.launch {
            when (val r = op()) {
                is ApiResult.Success -> load(reset = false)
                else -> {
                    val msg = if (r.isForbidden()) "Admin access required." else adminRootErrorMessage(r.adminRootErrorType())
                    (_state.value as? AdminTiersUiState.Content)?.let { _state.value = it.copy(actionError = msg) }
                }
            }
        }
    }

    private fun load(reset: Boolean) {
        if (reset) _state.value = AdminTiersUiState.Loading
        viewModelScope.launch {
            when (val r = repo.load()) {
                is ApiResult.Success -> _state.value = AdminTiersUiState.Content(r.data.tiers, r.data.analytics)
                else -> if (r.isForbidden()) {
                    _state.value = AdminTiersUiState.Forbidden
                } else {
                    _state.value = AdminTiersUiState.Error(r.adminRootErrorType())
                }
            }
        }
    }
}

@Composable
fun AdminTiersRoute(onBack: () -> Unit, viewModel: AdminTiersViewModel = hiltViewModel()) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminTiersScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::retry,
        onRefresh = viewModel::refresh,
        onCreate = viewModel::create,
        onUpdate = viewModel::update,
        onArchive = viewModel::archive,
        onUnarchive = viewModel::unarchive,
        onDelete = viewModel::delete,
    )
}

@Composable
fun AdminTiersScreen(
    state: AdminTiersUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onRefresh: () -> Unit,
    onCreate: (AdminTierForm) -> Unit,
    onUpdate: (String, AdminTierForm) -> Unit,
    onArchive: (String) -> Unit,
    onUnarchive: (String) -> Unit,
    onDelete: (String) -> Unit,
) {
    var showCreate by remember { mutableStateOf(false) }
    var editTier by remember { mutableStateOf<AdminTierDto?>(null) }
    val branch = when (state) {
        AdminTiersUiState.Loading -> AdminRootBranch.Loading
        AdminTiersUiState.Forbidden -> AdminRootBranch.Forbidden
        is AdminTiersUiState.Error -> AdminRootBranch.Error(state.type)
        is AdminTiersUiState.Content -> AdminRootBranch.Content(state.isRefreshing)
    }
    AdminRootScaffold(
        title = "Subscription tiers",
        branch = branch,
        onBack = onBack,
        onRefresh = onRefresh,
        onRetry = onRetry,
        screenTag = AdminTiersTags.SCREEN,
        forbiddenTag = AdminTiersTags.FORBIDDEN,
        retryTag = AdminTiersTags.RETRY,
        forbiddenBody = "You need admin access to manage subscription tiers.",
        actions = {
            if (state is AdminTiersUiState.Content) {
                FloatingActionButton(
                    onClick = { showCreate = true },
                    modifier = Modifier.padding(end = 8.dp).testTag(AdminTiersTags.FAB),
                ) { Icon(Icons.Filled.Add, contentDescription = "New tier") }
            }
        },
    ) {
        val content = state as AdminTiersUiState.Content
        LazyColumn(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            content.actionError?.let { item { Text(it, color = MaterialTheme.colorScheme.error) } }
            item {
                AdminRootSectionCard(title = "Overview") {
                    AdminRootStatRow("Total subscribers", content.analytics.totalSubscribers.toString())
                    AdminRootStatRow("Total revenue", tierCents(content.analytics.totalRevenueCents))
                    AdminRootStatRow("Tiers", content.tiers.size.toString())
                }
            }
            if (content.tiers.isEmpty()) {
                item { Text("No tiers yet. Tap + to create one.", color = MaterialTheme.colorScheme.onSurfaceVariant) }
            }
            items(content.tiers, key = { it.tierId }) { t ->
                val archived = t.status == "archived" || t.archivedAt != null
                AdminRootSectionCard(title = t.name.ifBlank { t.tierId }) {
                    AdminRootStatRow("Price", "${tierCents(t.priceCents)} / ${t.billingCycle}")
                    AdminRootStatRow("Access", t.accessLevel)
                    AdminRootStatRow("Subscribers", t.subscriberCount.toString())
                    AdminRootStatRow("Status", t.status)
                    if (t.description.isNotBlank()) AdminRootStatRow("Description", t.description)
                    if (t.benefits.isNotEmpty()) AdminRootStatRow("Benefits", t.benefits.joinToString(", "))
                    Row(
                        horizontalArrangement = Arrangement.spacedBy(4.dp),
                        modifier = Modifier.fillMaxWidth().testTag(AdminTiersTags.ROW),
                    ) {
                        TextButton(onClick = { editTier = t }) { Text("Edit") }
                        if (archived) {
                            TextButton(onClick = { onUnarchive(t.tierId) }) { Text("Unarchive") }
                        } else {
                            TextButton(onClick = { onArchive(t.tierId) }) { Text("Archive") }
                        }
                        TextButton(onClick = { onDelete(t.tierId) }) { Text("Delete") }
                    }
                }
            }
        }
    }
    if (showCreate) {
        TierEditDialog(
            existing = null,
            onDismiss = { showCreate = false },
            onConfirm = { form -> onCreate(form); showCreate = false },
        )
    }
    editTier?.let { t ->
        TierEditDialog(
            existing = t,
            onDismiss = { editTier = null },
            onConfirm = { form -> onUpdate(t.tierId, form); editTier = null },
        )
    }
}

@Composable
private fun TierEditDialog(
    existing: AdminTierDto?,
    onDismiss: () -> Unit,
    onConfirm: (AdminTierForm) -> Unit,
) {
    var name by remember { mutableStateOf(existing?.name ?: "") }
    var priceDollars by remember { mutableStateOf(existing?.let { (it.priceCents / 100.0).toString() } ?: "") }
    var cycle by remember { mutableStateOf(existing?.billingCycle ?: "monthly") }
    var access by remember { mutableStateOf(existing?.accessLevel ?: "basic") }
    var description by remember { mutableStateOf(existing?.description ?: "") }
    var benefits by remember { mutableStateOf(existing?.benefits?.joinToString(", ") ?: "") }

    val cents = priceDollars.toDoubleOrNull()?.let { Math.round(it * 100).toInt() } ?: -1
    val valid = name.isNotBlank() && cents in 100..100_000

    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (existing == null) "New tier" else "Edit tier") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                OutlinedTextField(value = name, onValueChange = { name = it }, label = { Text("Name") }, singleLine = true)
                OutlinedTextField(
                    value = priceDollars,
                    onValueChange = { priceDollars = it },
                    label = { Text("Price (USD, $1-$1000)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
                    singleLine = true,
                )
                OptionDropdown("Billing cycle", cycle, listOf("monthly", "quarterly", "yearly")) { cycle = it }
                OptionDropdown("Access level", access, listOf("basic", "premium", "vip")) { access = it }
                OutlinedTextField(value = description, onValueChange = { description = it }, label = { Text("Description") })
                OutlinedTextField(value = benefits, onValueChange = { benefits = it }, label = { Text("Benefits (comma-separated)") })
            }
        },
        confirmButton = {
            Button(
                onClick = {
                    onConfirm(
                        AdminTierForm(
                            name = name.trim(),
                            priceCents = cents,
                            billingCycle = cycle,
                            description = description.trim(),
                            benefits = benefits.split(",").map { it.trim() }.filter { it.isNotBlank() },
                            accessLevel = access,
                        ),
                    )
                },
                enabled = valid,
            ) { Text("Save") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancel") } },
    )
}

@Composable
private fun OptionDropdown(label: String, value: String, options: List<String>, onValue: (String) -> Unit) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(expanded = expanded, onExpandedChange = { expanded = it }) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier.menuAnchor().fillMaxWidth(),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { opt ->
                DropdownMenuItem(text = { Text(opt) }, onClick = { onValue(opt); expanded = false })
            }
        }
    }
}
