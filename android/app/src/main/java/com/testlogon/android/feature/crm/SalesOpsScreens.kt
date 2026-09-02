@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.crm

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.SavedStateHandle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.crm.CrmSalesMath
import com.testlogon.android.data.crm.ForecastMath
import com.testlogon.android.data.crm.ForecastWorksheet
import com.testlogon.android.data.crm.OppContactRole
import com.testlogon.android.data.crm.PipelineReport
import com.testlogon.android.data.crm.SalesQuota
import com.testlogon.android.data.crm.SalesRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

// ══════════════════════════════════════════════════════════════════════════
//  Shared helpers
// ══════════════════════════════════════════════════════════════════════════

/** "1,234.56" / "1234" -> cents; null on garbage. */
internal fun parseDollarsToCentsOrNull(raw: String): Long? {
    val cleaned = raw.trim().replace(",", "").removePrefix("$")
    if (cleaned.isBlank()) return null
    val value = cleaned.toDoubleOrNull() ?: return null
    if (value < 0) return null
    return Math.round(value * 100.0)
}

private fun centsToDollarField(cents: Long): String =
    if (cents <= 0L) "" else (cents / 100.0).toString()

// ══════════════════════════════════════════════════════════════════════════
//  OPP-005 — Forecast worksheet
// ══════════════════════════════════════════════════════════════════════════

object CrmForecastTestTags {
    const val SCREEN = "crm_forecast_screen"
    const val CONTENT = "crm_forecast_content"
    const val SAVE = "crm_forecast_save"
}

data class ForecastUiState(
    val phase: Phase = Phase.Loading,
    val periodKey: String = "",
    val committed: String = "",
    val bestCase: String = "",
    val pipeline: String = "",
    val notes: String = "",
    val closedCents: Long = 0,
    val quotaCents: Long = 0,
    val moduleDisabled: Boolean = false,
    val saving: Boolean = false,
    val message: String? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val rollup: ForecastMath.ForecastRollup
        get() = ForecastMath.rollup(
            committedCents = parseDollarsToCentsOrNull(committed) ?: 0L,
            bestCaseCents = parseDollarsToCentsOrNull(bestCase) ?: 0L,
            pipelineCents = parseDollarsToCentsOrNull(pipeline) ?: 0L,
            closedCents = closedCents,
            quotaCents = quotaCents,
        )
}

/**
 * CRM-AND-OPP — the rep forecast worksheet (GET/PUT /ui/sales/forecast/{period}). The period key is
 * defaulted to the current YYYY-MM if not supplied. Committed / best-case / pipeline are rep-entered;
 * closed / quota / attainment are server-computed and shown read-only. 404 (no worksheet yet) degrades
 * to an empty, editable worksheet; 503 (module off) shows a banner.
 */
@HiltViewModel
class ForecastViewModel @Inject constructor(
    private val repository: SalesRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val periodKey: String =
        savedStateHandle.get<String>(ARG_PERIOD_KEY)?.takeIf { it.isNotBlank() } ?: defaultPeriodKey()

    private val _uiState = MutableStateFlow(ForecastUiState(periodKey = periodKey))
    val uiState: StateFlow<ForecastUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = ForecastUiState.Phase.Loading) }
        viewModelScope.launch {
            when (val r = repository.getForecast(periodKey)) {
                is ApiResult.Success -> _uiState.update {
                    val w = r.data.worksheet
                    it.copy(
                        phase = ForecastUiState.Phase.Content,
                        committed = w?.let { centsToDollarField(it.committedCents) } ?: it.committed,
                        bestCase = w?.let { centsToDollarField(it.bestCaseCents) } ?: it.bestCase,
                        pipeline = w?.let { centsToDollarField(it.pipelineCents) } ?: it.pipeline,
                        notes = w?.notes ?: it.notes,
                        closedCents = w?.closedCents ?: 0L,
                        quotaCents = w?.quotaCents ?: 0L,
                        moduleDisabled = r.data.moduleDisabled,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = ForecastUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = ForecastUiState.Phase.Error, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    fun onCommittedChange(v: String) = _uiState.update { it.copy(committed = v) }
    fun onBestCaseChange(v: String) = _uiState.update { it.copy(bestCase = v) }
    fun onPipelineChange(v: String) = _uiState.update { it.copy(pipeline = v) }
    fun onNotesChange(v: String) = _uiState.update { it.copy(notes = v) }

    fun save() {
        val s = _uiState.value
        _uiState.update { it.copy(saving = true, message = null) }
        viewModelScope.launch {
            val result = repository.upsertForecast(
                periodKey = periodKey,
                committedCents = parseDollarsToCentsOrNull(s.committed) ?: 0L,
                bestCaseCents = parseDollarsToCentsOrNull(s.bestCase) ?: 0L,
                pipelineCents = parseDollarsToCentsOrNull(s.pipeline) ?: 0L,
                notes = s.notes,
            )
            when (result) {
                is ApiResult.Success -> _uiState.update {
                    val w = result.data
                    it.copy(
                        saving = false,
                        closedCents = w.closedCents,
                        quotaCents = w.quotaCents,
                        message = "Forecast saved.",
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(saving = false, message = result.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(saving = false, message = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearMessage() = _uiState.update { it.copy(message = null) }

    companion object {
        const val ARG_PERIOD_KEY = "periodKey"

        /** Current period as YYYY-MM using pure arithmetic (no java.time to keep it deterministic-ish). */
        private fun defaultPeriodKey(): String {
            val millis = System.currentTimeMillis()
            val days = millis / 86_400_000L
            // Days since 1970-01-01; approximate year/month via civil-from-days.
            var z = days + 719_468
            val era = (if (z >= 0) z else z - 146_096) / 146_097
            val doe = z - era * 146_097
            val yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365
            val y = yoe + era * 400
            val doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
            val mp = (5 * doy + 2) / 153
            val m = if (mp < 10) mp + 3 else mp - 9
            val year = if (m <= 2) y + 1 else y
            return "%04d-%02d".format(year, m)
        }
    }
}

@Composable
fun ForecastRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ForecastViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ForecastScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onCommittedChange = viewModel::onCommittedChange,
        onBestCaseChange = viewModel::onBestCaseChange,
        onPipelineChange = viewModel::onPipelineChange,
        onNotesChange = viewModel::onNotesChange,
        onSave = viewModel::save,
        onClearMessage = viewModel::clearMessage,
        modifier = modifier,
    )
}

@Composable
fun ForecastScreen(
    state: ForecastUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onCommittedChange: (String) -> Unit,
    onBestCaseChange: (String) -> Unit,
    onPipelineChange: (String) -> Unit,
    onNotesChange: (String) -> Unit,
    onSave: () -> Unit,
    onClearMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            onClearMessage()
        }
    }

    Scaffold(
        modifier = modifier.testTag(CrmForecastTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Forecast · ${state.periodKey}") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            ForecastUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            ForecastUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load the forecast.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            ForecastUiState.Phase.Content -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
                    .testTag(CrmForecastTestTags.CONTENT),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                if (state.moduleDisabled) {
                    InfoBanner("The sales pipeline is not enabled for this account.")
                }

                val r = state.rollup
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Quota attainment", style = MaterialTheme.typography.titleMedium)
                        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                            KpiCell(CrmSalesMath.formatCents(r.closedCents), "Closed")
                            KpiCell(CrmSalesMath.formatCents(r.quotaCents), "Quota")
                            KpiCell("${r.attainmentPct}%", "Attainment")
                        }
                        LinearProgressIndicator(
                            progress = { (r.attainmentPct.coerceIn(0, 100)) / 100f },
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            "Gap to quota: ${CrmSalesMath.formatCents(r.gapToQuotaCents)} · " +
                                "Commit total: ${CrmSalesMath.formatCents(r.commitTotalCents)}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                DollarField(state.committed, onCommittedChange, "Committed")
                DollarField(state.bestCase, onBestCaseChange, "Best case")
                DollarField(state.pipeline, onPipelineChange, "Pipeline")
                OutlinedTextField(
                    value = state.notes,
                    onValueChange = onNotesChange,
                    label = { Text("Notes") },
                    modifier = Modifier.fillMaxWidth(),
                )

                Button(
                    onClick = onSave,
                    enabled = !state.saving && !state.moduleDisabled,
                    modifier = Modifier.fillMaxWidth().testTag(CrmForecastTestTags.SAVE),
                ) { Text(if (state.saving) "Saving…" else "Save forecast") }
            }
        }
    }
}

@Composable
private fun DollarField(value: String, onChange: (String) -> Unit, label: String) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
        prefix = { Text("$") },
        modifier = Modifier.fillMaxWidth(),
    )
}

@Composable
private fun KpiCell(value: String, label: String) {
    Column {
        Text(value, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
        Text(label, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  OPP-006 — Pipeline report (per-rep + admin)
// ══════════════════════════════════════════════════════════════════════════

object CrmPipelineReportTestTags {
    const val SCREEN = "crm_pipeline_report_screen"
    const val CONTENT = "crm_pipeline_report_content"
}

data class PipelineReportUiState(
    val phase: Phase = Phase.Loading,
    val admin: Boolean = false,
    val report: PipelineReport? = null,
    val moduleDisabled: Boolean = false,
    val forbidden: Boolean = false,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-OPP — pipeline funnel report (GET /ui/sales/reports/pipeline, or the admin cross-user variant
 * /ui/admin/sales/reports/pipeline when [admin] is set). Admin variant 403s for non-admins → a
 * "forbidden" empty state; 404/503 → module banner.
 */
@HiltViewModel
class PipelineReportViewModel @Inject constructor(
    private val repository: SalesRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val admin: Boolean =
        savedStateHandle.get<String>(ARG_ADMIN)?.equals("true", ignoreCase = true) == true

    private val _uiState = MutableStateFlow(PipelineReportUiState(admin = admin))
    val uiState: StateFlow<PipelineReportUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = PipelineReportUiState.Phase.Loading, forbidden = false) }
        viewModelScope.launch {
            val r = if (admin) repository.adminPipelineReport() else repository.pipelineReport()
            when (r) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = PipelineReportUiState.Phase.Content,
                        report = r.data.report,
                        moduleDisabled = r.data.moduleDisabled,
                        forbidden = r.data.forbidden,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = PipelineReportUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = PipelineReportUiState.Phase.Error, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    companion object {
        const val ARG_ADMIN = "admin"
    }
}

@Composable
fun PipelineReportRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: PipelineReportViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    PipelineReportScreen(state = state, onBack = onBack, onRetry = viewModel::onRetry, modifier = modifier)
}

@Composable
fun PipelineReportScreen(
    state: PipelineReportUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(CrmPipelineReportTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(if (state.admin) "Pipeline report · Team" else "Pipeline report") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.phase == PipelineReportUiState.Phase.Loading ->
                LoadingState(modifier = Modifier.padding(padding))
            state.phase == PipelineReportUiState.Phase.Error ->
                ErrorState(
                    message = state.errorMessage ?: "Couldn't load the report.",
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )
            state.forbidden ->
                EmptyState(
                    title = "Admin access required",
                    body = "The team pipeline report is only available to administrators.",
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )
            state.moduleDisabled || state.report == null ->
                EmptyState(
                    title = "Pipeline unavailable",
                    body = "The sales pipeline is not enabled for this account.",
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )
            else -> {
                val report = state.report
                Column(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(padding)
                        .verticalScroll(rememberScrollState())
                        .padding(16.dp)
                        .testTag(CrmPipelineReportTestTags.CONTENT),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Row(
                            modifier = Modifier.fillMaxWidth().padding(16.dp),
                            horizontalArrangement = Arrangement.SpaceBetween,
                        ) {
                            KpiCell(CrmSalesMath.formatCents(report.totalAmountCents), "Total")
                            KpiCell(CrmSalesMath.formatCents(report.totalWeightedCents), "Weighted")
                            KpiCell("${ForecastMath.openCount(report.stages)}", "Open")
                        }
                    }

                    val maxCount = report.stages.maxOfOrNull { maxOf(0, it.count) } ?: 0
                    report.stages.forEach { row ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Column(
                                modifier = Modifier.padding(16.dp),
                                verticalArrangement = Arrangement.spacedBy(6.dp),
                            ) {
                                Row(
                                    modifier = Modifier.fillMaxWidth(),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Text(row.label, style = MaterialTheme.typography.titleSmall, fontWeight = FontWeight.Bold)
                                    Text("${row.count}", style = MaterialTheme.typography.titleSmall)
                                }
                                LinearProgressIndicator(
                                    progress = { if (maxCount <= 0) 0f else row.count.coerceAtLeast(0).toFloat() / maxCount },
                                    modifier = Modifier.fillMaxWidth(),
                                )
                                Text(
                                    "${CrmSalesMath.formatCents(row.totalAmountCents)} · " +
                                        "weighted ${CrmSalesMath.formatCents(row.weightedAmountCents)}",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  OPP-004 — Opportunity contact roles
// ══════════════════════════════════════════════════════════════════════════

object CrmContactRolesTestTags {
    const val SCREEN = "crm_contact_roles_screen"
    const val CONTENT = "crm_contact_roles_content"
    const val ADD = "crm_contact_roles_add"
}

/** Mirror of CONTACT_ROLES in opportunities.ts. */
val CONTACT_ROLE_CHOICES: List<String> = listOf(
    "decision_maker", "evaluator", "influencer", "champion",
    "end_user", "executive_sponsor", "technical_buyer", "other",
)

data class ContactRolesUiState(
    val phase: Phase = Phase.Loading,
    val oppId: String = "",
    val roles: List<OppContactRole> = emptyList(),
    val moduleDisabled: Boolean = false,
    val submitting: Boolean = false,
    val message: String? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }
}

/**
 * CRM-AND-OPP — opportunity contact-roles (POST/GET/DELETE /ui/sales/opportunities/{id}/contacts).
 * 404/503 degrades to an empty non-error list.
 */
@HiltViewModel
class ContactRolesViewModel @Inject constructor(
    private val repository: SalesRepository,
    savedStateHandle: SavedStateHandle,
) : ViewModel() {

    private val oppId: String = savedStateHandle.get<String>(ARG_OPP_ID).orEmpty()

    private val _uiState = MutableStateFlow(ContactRolesUiState(oppId = oppId))
    val uiState: StateFlow<ContactRolesUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = ContactRolesUiState.Phase.Loading) }
        viewModelScope.launch {
            when (val r = repository.listContactRoles(oppId)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = ContactRolesUiState.Phase.Content,
                        roles = r.data,
                        moduleDisabled = r.data.isEmpty() && it.moduleDisabled,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = ContactRolesUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = ContactRolesUiState.Phase.Error, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    fun add(contactRef: String, contactRole: String) {
        if (contactRef.isBlank()) {
            _uiState.update { it.copy(message = "Contact reference is required.") }
            return
        }
        _uiState.update { it.copy(submitting = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.addContactRole(oppId, contactRef.trim(), contactRole)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(submitting = false, message = "Contact linked.") }
                    load()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, message = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, message = "You're offline. Try again.")
                }
            }
        }
    }

    fun remove(contactRef: String) {
        _uiState.update { it.copy(message = null) }
        viewModelScope.launch {
            when (val r = repository.removeContactRole(oppId, contactRef)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(message = "Contact removed.") }
                    load()
                }
                is ApiResult.Failure -> _uiState.update { it.copy(message = r.error.message) }
                is ApiResult.NetworkError -> _uiState.update { it.copy(message = "You're offline. Try again.") }
            }
        }
    }

    fun clearMessage() = _uiState.update { it.copy(message = null) }

    companion object {
        const val ARG_OPP_ID = "oppId"
    }
}

@Composable
fun ContactRolesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ContactRolesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ContactRolesScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onAdd = viewModel::add,
        onRemove = viewModel::remove,
        onClearMessage = viewModel::clearMessage,
        modifier = modifier,
    )
}

@Composable
fun ContactRolesScreen(
    state: ContactRolesUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onAdd: (contactRef: String, role: String) -> Unit,
    onRemove: (contactRef: String) -> Unit,
    onClearMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            onClearMessage()
        }
    }
    var ref by remember { mutableStateOf("") }
    var role by remember { mutableStateOf(CONTACT_ROLE_CHOICES.first()) }

    Scaffold(
        modifier = modifier.testTag(CrmContactRolesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Contact roles") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when (state.phase) {
            ContactRolesUiState.Phase.Loading -> LoadingState(modifier = Modifier.padding(padding))
            ContactRolesUiState.Phase.Error -> ErrorState(
                message = state.errorMessage ?: "Couldn't load contact roles.",
                onRetry = onRetry,
                modifier = Modifier.padding(padding),
            )
            ContactRolesUiState.Phase.Content -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
                    .testTag(CrmContactRolesTestTags.CONTENT),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Link a contact", style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            value = ref,
                            onValueChange = { ref = it },
                            label = { Text("Contact reference (party id / email)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        RoleChooser(selected = role, onSelect = { role = it })
                        Button(
                            onClick = { onAdd(ref, role); ref = "" },
                            enabled = !state.submitting,
                            modifier = Modifier.fillMaxWidth().testTag(CrmContactRolesTestTags.ADD),
                        ) {
                            Icon(Icons.Filled.Add, contentDescription = null)
                            Text(if (state.submitting) " Linking…" else " Link contact")
                        }
                    }
                }

                Text("Linked contacts (${state.roles.size})", style = MaterialTheme.typography.titleMedium)
                if (state.roles.isEmpty()) {
                    Text(
                        "No contacts linked yet.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    state.roles.forEach { r ->
                        Card(modifier = Modifier.fillMaxWidth()) {
                            Row(
                                modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp, vertical = 8.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(r.contactRef, style = MaterialTheme.typography.bodyLarge, fontWeight = FontWeight.Medium)
                                    Text(r.roleLabel, style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
                                }
                                IconButton(onClick = { onRemove(r.contactRef) }) {
                                    Icon(Icons.Filled.Delete, contentDescription = "Remove contact")
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
private fun RoleChooser(selected: String, onSelect: (String) -> Unit) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text("Role", style = MaterialTheme.typography.labelMedium)
        FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            CONTACT_ROLE_CHOICES.forEach { key ->
                androidx.compose.material3.FilterChip(
                    selected = key == selected,
                    onClick = { onSelect(key) },
                    label = {
                        Text(
                            key.split('_').joinToString(" ") { p -> p.replaceFirstChar { it.uppercaseChar() } },
                        )
                    },
                )
            }
        }
    }
}

// ══════════════════════════════════════════════════════════════════════════
//  OPP-005 — Admin quota view
// ══════════════════════════════════════════════════════════════════════════

object CrmQuotaTestTags {
    const val SCREEN = "crm_quota_screen"
    const val CONTENT = "crm_quota_content"
    const val SET = "crm_quota_set"
}

val QUOTA_PERIOD_TYPES: List<String> = listOf("monthly", "quarterly", "annual")

data class QuotaUiState(
    val phase: Phase = Phase.Idle,
    val userSub: String = "",
    val periodType: String = "monthly",
    val periodKey: String = "",
    val target: String = "",
    val quotas: List<SalesQuota> = emptyList(),
    val moduleDisabled: Boolean = false,
    val forbidden: Boolean = false,
    val submitting: Boolean = false,
    val message: String? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Idle, Loading, Content, Error }
}

/**
 * CRM-AND-OPP — admin quota view/set (POST /ui/admin/sales/quotas, GET /ui/admin/sales/quotas/{sub}).
 * Server 403 for non-admins → a "forbidden" state (mirrors the ScoringRules admin idiom). The admin
 * enters a target user_sub to look up / set quotas for.
 */
@HiltViewModel
class QuotaViewModel @Inject constructor(
    private val repository: SalesRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(QuotaUiState())
    val uiState: StateFlow<QuotaUiState> = _uiState.asStateFlow()

    fun onUserSubChange(v: String) = _uiState.update { it.copy(userSub = v) }
    fun onPeriodTypeChange(v: String) = _uiState.update { it.copy(periodType = v) }
    fun onPeriodKeyChange(v: String) = _uiState.update { it.copy(periodKey = v) }
    fun onTargetChange(v: String) = _uiState.update { it.copy(target = v) }

    fun lookup() {
        val sub = _uiState.value.userSub.trim()
        if (sub.isBlank()) {
            _uiState.update { it.copy(message = "Enter a user id to look up.") }
            return
        }
        _uiState.update { it.copy(phase = QuotaUiState.Phase.Loading, forbidden = false) }
        viewModelScope.launch {
            when (val r = repository.listUserQuotas(sub)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(
                        phase = QuotaUiState.Phase.Content,
                        quotas = r.data.quotas,
                        moduleDisabled = r.data.moduleDisabled,
                        forbidden = r.data.forbidden,
                        errorMessage = null,
                    )
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(phase = QuotaUiState.Phase.Error, errorMessage = r.error.message)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = QuotaUiState.Phase.Error, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    fun setQuota() {
        val s = _uiState.value
        val cents = parseDollarsToCentsOrNull(s.target)
        if (s.userSub.isBlank() || s.periodKey.isBlank() || cents == null) {
            _uiState.update { it.copy(message = "User, period key and a valid target are required.") }
            return
        }
        _uiState.update { it.copy(submitting = true, message = null) }
        viewModelScope.launch {
            when (val r = repository.setQuota(s.userSub.trim(), s.periodType, s.periodKey.trim(), cents)) {
                is ApiResult.Success -> {
                    _uiState.update { it.copy(submitting = false, message = "Quota set.") }
                    lookup()
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(submitting = false, message = r.error.message, forbidden = r.error.status == 403)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(submitting = false, message = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearMessage() = _uiState.update { it.copy(message = null) }
}

@Composable
fun QuotaRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: QuotaViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    QuotaScreen(
        state = state,
        onBack = onBack,
        onUserSubChange = viewModel::onUserSubChange,
        onPeriodTypeChange = viewModel::onPeriodTypeChange,
        onPeriodKeyChange = viewModel::onPeriodKeyChange,
        onTargetChange = viewModel::onTargetChange,
        onLookup = viewModel::lookup,
        onSet = viewModel::setQuota,
        onClearMessage = viewModel::clearMessage,
        modifier = modifier,
    )
}

@Composable
fun QuotaScreen(
    state: QuotaUiState,
    onBack: () -> Unit,
    onUserSubChange: (String) -> Unit,
    onPeriodTypeChange: (String) -> Unit,
    onPeriodKeyChange: (String) -> Unit,
    onTargetChange: (String) -> Unit,
    onLookup: () -> Unit,
    onSet: () -> Unit,
    onClearMessage: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val snackbarHostState = remember { SnackbarHostState() }
    LaunchedEffect(state.message) {
        state.message?.let {
            snackbarHostState.showSnackbar(it)
            onClearMessage()
        }
    }

    Scaffold(
        modifier = modifier.testTag(CrmQuotaTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Sales quotas") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp)
                .testTag(CrmQuotaTestTags.CONTENT),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            if (state.forbidden) {
                EmptyState(
                    title = "Admin access required",
                    body = "Sales quotas can only be viewed or set by an administrator.",
                    modifier = Modifier.fillMaxWidth(),
                )
            }
            if (state.moduleDisabled) {
                InfoBanner("The sales pipeline is not enabled for this account.")
            }

            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Rep quota", style = MaterialTheme.typography.titleMedium)
                    OutlinedTextField(
                        value = state.userSub,
                        onValueChange = onUserSubChange,
                        label = { Text("User id (sub)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedButton(onClick = onLookup, modifier = Modifier.fillMaxWidth()) {
                        Text("Look up quotas")
                    }

                    FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        QUOTA_PERIOD_TYPES.forEach { pt ->
                            androidx.compose.material3.FilterChip(
                                selected = pt == state.periodType,
                                onClick = { onPeriodTypeChange(pt) },
                                label = { Text(pt.replaceFirstChar { it.uppercaseChar() }) },
                            )
                        }
                    }
                    OutlinedTextField(
                        value = state.periodKey,
                        onValueChange = onPeriodKeyChange,
                        label = { Text("Period key (e.g. 2026-Q3 / 2026-09 / 2026)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = state.target,
                        onValueChange = onTargetChange,
                        label = { Text("Target amount") },
                        singleLine = true,
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                        prefix = { Text("$") },
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Button(
                        onClick = onSet,
                        enabled = !state.submitting,
                        modifier = Modifier.fillMaxWidth().testTag(CrmQuotaTestTags.SET),
                    ) { Text(if (state.submitting) "Saving…" else "Set quota") }
                }
            }

            when (state.phase) {
                QuotaUiState.Phase.Loading -> Box(modifier = Modifier.fillMaxWidth()) { LoadingState() }
                QuotaUiState.Phase.Error -> ErrorState(
                    message = state.errorMessage ?: "Couldn't load quotas.",
                    onRetry = onLookup,
                )
                QuotaUiState.Phase.Content -> {
                    Text("Quotas (${state.quotas.size})", style = MaterialTheme.typography.titleMedium)
                    if (state.quotas.isEmpty() && !state.forbidden) {
                        Text(
                            "No quotas set for this user.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    } else {
                        state.quotas.forEach { q ->
                            Card(modifier = Modifier.fillMaxWidth()) {
                                Row(
                                    modifier = Modifier.fillMaxWidth().padding(16.dp),
                                    horizontalArrangement = Arrangement.SpaceBetween,
                                ) {
                                    Column {
                                        Text("${q.periodType.replaceFirstChar { it.uppercaseChar() }} · ${q.periodKey}", fontWeight = FontWeight.Medium)
                                        Text(
                                            "Set by ${q.setBySub}",
                                            style = MaterialTheme.typography.labelSmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                        )
                                    }
                                    Text(CrmSalesMath.formatCents(q.targetAmountCents), fontWeight = FontWeight.SemiBold)
                                }
                            }
                        }
                    }
                }
                QuotaUiState.Phase.Idle -> Unit
            }
        }
    }
}
