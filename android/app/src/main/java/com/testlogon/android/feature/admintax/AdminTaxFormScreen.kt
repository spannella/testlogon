@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.admintax

import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.admintax.AdminForm1099Dto
import com.testlogon.android.feature.adminops.adminOpsErrorMessage
import com.testlogon.android.feature.adminops.cents

object AdminTaxTestTags {
    const val SCREEN = "admin_tax_screen"
    const val FORBIDDEN = "admin_tax_forbidden"
    const val ERROR_RETRY = "admin_tax_error_retry"
    const val GENERATE = "admin_tax_generate"
    const val BATCH = "admin_tax_batch"
    fun year(y: Int) = "admin_tax_year_$y"
    fun form(id: String) = "admin_tax_form_$id"
}

@Composable
fun AdminTaxFormRoute(
    onBack: () -> Unit,
    viewModel: AdminTaxFormViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    AdminTaxFormScreen(
        state = state,
        years = viewModel.years,
        onBack = onBack,
        onSetYear = viewModel::setYear,
        onRefresh = viewModel::refresh,
        onRetry = viewModel::retry,
        onGenerate = viewModel::generateForUser,
        onCorrect = viewModel::correctForUser,
        onBatch = viewModel::batchGenerate,
        onMessageShown = viewModel::clearActionMessage,
    )
}

@Composable
fun AdminTaxFormScreen(
    state: AdminTaxUiState,
    years: List<Int>,
    onBack: () -> Unit,
    onSetYear: (Int) -> Unit,
    onRefresh: () -> Unit,
    onRetry: () -> Unit,
    onGenerate: (String) -> Unit,
    onCorrect: (String) -> Unit,
    onBatch: () -> Unit,
    onMessageShown: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbar = remember { SnackbarHostState() }
    var showBatchConfirm by remember { mutableStateOf(false) }

    val message = (state as? AdminTaxUiState.Content)?.actionMessage
    val transient = (state as? AdminTaxUiState.Content)?.transientError
    LaunchedEffect(message, transient) {
        val text = message ?: transient?.let { adminOpsErrorMessage(it) }
        if (text != null) {
            snackbar.showSnackbar(text)
            onMessageShown()
        }
    }
    LaunchedEffect(message) { if (message != null) showBatchConfirm = false }

    val activeYear = (state as? AdminTaxUiState.Content)?.year

    Scaffold(
        modifier = modifier.testTag(AdminTaxTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("1099 forms") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        snackbarHost = { SnackbarHost(snackbar) },
    ) { padding ->
        Column(Modifier.fillMaxSize().padding(padding)) {
            YearRow(years = years, active = activeYear, onSetYear = onSetYear)
            val isRefreshing = (state as? AdminTaxUiState.Content)?.isRefreshing == true
            PullToRefreshBox(
                isRefreshing = isRefreshing,
                onRefresh = onRefresh,
                modifier = Modifier.fillMaxSize(),
            ) {
                when (state) {
                    is AdminTaxUiState.Loading -> LoadingState()
                    is AdminTaxUiState.Forbidden -> EmptyState(
                        modifier = Modifier.testTag(AdminTaxTestTags.FORBIDDEN),
                        title = "Not authorised",
                        body = "You need platform-admin access to manage 1099 forms.",
                        imageVector = Icons.Outlined.Lock,
                        actionLabel = "Back",
                        onAction = onBack,
                    )
                    is AdminTaxUiState.Error -> ErrorState(
                        modifier = Modifier.testTag(AdminTaxTestTags.ERROR_RETRY),
                        message = adminOpsErrorMessage(state.type),
                        onRetry = onRetry,
                    )
                    is AdminTaxUiState.Content -> ManagerBody(
                        year = state.year,
                        forms = state.forms,
                        actionInFlight = state.actionInFlight,
                        onGenerate = onGenerate,
                        onCorrect = onCorrect,
                        onBatchClick = { showBatchConfirm = true },
                    )
                }
            }
        }
    }

    if (showBatchConfirm && state is AdminTaxUiState.Content) {
        BatchConfirmDialog(
            year = state.year,
            actionInFlight = state.actionInFlight,
            onDismiss = { if (!state.actionInFlight) showBatchConfirm = false },
            onConfirm = onBatch,
        )
    }
}

@Composable
private fun YearRow(years: List<Int>, active: Int?, onSetYear: (Int) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 16.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        years.forEach { y ->
            FilterChip(
                selected = active == y,
                onClick = { onSetYear(y) },
                label = { Text(y.toString()) },
                modifier = Modifier.testTag(AdminTaxTestTags.year(y)),
            )
        }
    }
}

@Composable
private fun ManagerBody(
    year: Int,
    forms: List<AdminForm1099Dto>,
    actionInFlight: Boolean,
    onGenerate: (String) -> Unit,
    onCorrect: (String) -> Unit,
    onBatchClick: () -> Unit,
) {
    var userSub by remember { mutableStateOf("") }
    Column(
        modifier = Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Generate for a creator", style = MaterialTheme.typography.titleSmall,
                    fontWeight = FontWeight.SemiBold)
                OutlinedTextField(
                    value = userSub,
                    onValueChange = { userSub = it },
                    label = { Text("Creator user_sub / email") },
                    modifier = Modifier.fillMaxWidth(),
                    singleLine = true,
                    enabled = !actionInFlight,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    Button(
                        onClick = { onGenerate(userSub) },
                        enabled = !actionInFlight && userSub.isNotBlank(),
                        modifier = Modifier.testTag(AdminTaxTestTags.GENERATE),
                    ) { Text("Generate $year") }
                }
            }
        }

        OutlinedButton(
            onClick = onBatchClick,
            enabled = !actionInFlight,
            modifier = Modifier.fillMaxWidth().testTag(AdminTaxTestTags.BATCH),
        ) { Text("Batch-generate all qualifying for $year") }

        Text("Filed forms · $year", style = MaterialTheme.typography.titleMedium)
        if (forms.isEmpty()) {
            Text("No 1099 forms for $year yet.", style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant)
        } else {
            forms.forEach { f -> FormCard(f, actionInFlight, onCorrect) }
        }
    }
}

@Composable
private fun FormCard(f: AdminForm1099Dto, actionInFlight: Boolean, onCorrect: (String) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().testTag(AdminTaxTestTags.form(f.formId.ifBlank { f.userSub }))) {
        Column(Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
            Text(f.userSub.ifBlank { f.formId }, style = MaterialTheme.typography.titleSmall,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            Text(
                text = "${cents(f.totalEarningsCents)} · ${f.status}" +
                    if (f.correctionCount > 0) " · corr ${f.correctionCount}" else "",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Text(
                text = if (f.qualifies) "Qualifies" else "Below threshold",
                style = MaterialTheme.typography.labelMedium,
                color = if (f.qualifies) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 4.dp),
                horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
            ) {
                OutlinedButton(onClick = { onCorrect(f.userSub) }, enabled = !actionInFlight && f.userSub.isNotBlank()) {
                    Text("Correct")
                }
            }
        }
    }
}

@Composable
private fun BatchConfirmDialog(
    year: Int,
    actionInFlight: Boolean,
    onDismiss: () -> Unit,
    onConfirm: () -> Unit,
) {
    Dialog(onDismissRequest = onDismiss) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(Modifier.padding(20.dp), verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Batch-generate 1099s", style = MaterialTheme.typography.titleMedium)
                Text(
                    text = "This generates 1099-NEC forms for every qualifying creator for $year. Continue?",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(8.dp, Alignment.End),
                ) {
                    TextButton(onClick = onDismiss, enabled = !actionInFlight) { Text("Cancel") }
                    Button(onClick = onConfirm, enabled = !actionInFlight) { Text("Generate all") }
                }
            }
        }
    }
}
