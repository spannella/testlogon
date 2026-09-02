@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.crm

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
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
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
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.ViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewModelScope
import com.testlogon.android.core.model.ApiResult
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.crm.LeadHygieneMath
import com.testlogon.android.data.crm.LeadScoreRule
import com.testlogon.android.data.crm.LeadsRepository
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import javax.inject.Inject

object CrmScoringRulesTestTags {
    const val SCREEN = "crm_scoring_rules_screen"
    const val CONTENT = "crm_scoring_rules_content"
    const val SAVE = "crm_scoring_rules_save"
}

data class ScoringRulesUiState(
    val phase: Phase = Phase.Loading,
    val rules: List<LeadScoreRule> = emptyList(),
    val maxScore: Int = 100,
    val sources: Map<String, Int> = emptyMap(),
    val forbidden: Boolean = false,
    val moduleDisabled: Boolean = false,
    val saving: Boolean = false,
    val message: String? = null,
    val errorMessage: String? = null,
) {
    enum class Phase { Loading, Content, Error }

    val maxAchievable: Int
        get() = LeadHygieneMath.maxAchievablePoints(rules.map { it.points }, maxScore)
}

/**
 * CRM-AND-LED — admin scoring-rules editor (/ui/leads/admin/scoring-rules) + source summary
 * (/ui/leads/sources/summary). Admin-gated: the server returns 403 for non-admins, surfaced as a
 * [ScoringRulesUiState.forbidden] state (defence-in-depth, mirrors the SupportAdmin idiom). 404
 * (module off) degrades to a non-error banner.
 */
@HiltViewModel
class ScoringRulesViewModel @Inject constructor(
    private val repository: LeadsRepository,
) : ViewModel() {

    private val _uiState = MutableStateFlow(ScoringRulesUiState())
    val uiState: StateFlow<ScoringRulesUiState> = _uiState.asStateFlow()

    init { load() }

    fun onRetry() = load()

    private fun load() {
        _uiState.update { it.copy(phase = ScoringRulesUiState.Phase.Loading, forbidden = false) }
        viewModelScope.launch {
            when (val r = repository.getScoringRules()) {
                is ApiResult.Success -> {
                    val sources = (repository.sourceSummary() as? ApiResult.Success)?.data ?: emptyMap()
                    _uiState.update {
                        it.copy(
                            phase = ScoringRulesUiState.Phase.Content,
                            rules = r.data.rules,
                            maxScore = r.data.maxScore,
                            sources = sources,
                            forbidden = false,
                            moduleDisabled = false,
                            errorMessage = null,
                        )
                    }
                }
                is ApiResult.Failure -> {
                    val status = r.error.status
                    _uiState.update {
                        it.copy(
                            phase = ScoringRulesUiState.Phase.Content.takeIf { status == 403 || status == 404 }
                                ?: ScoringRulesUiState.Phase.Error,
                            forbidden = status == 403,
                            moduleDisabled = status == 404,
                            errorMessage = if (status == 403 || status == 404) null else r.error.message,
                        )
                    }
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(phase = ScoringRulesUiState.Phase.Error, errorMessage = "You're offline. Try again.")
                }
            }
        }
    }

    fun setMaxScore(value: Int) = _uiState.update { it.copy(maxScore = value.coerceAtLeast(0)) }

    fun addRule() = _uiState.update {
        it.copy(rules = it.rules + LeadScoreRule(field = "", operator = "equals", value = "", points = 0))
    }

    fun updateRule(index: Int, rule: LeadScoreRule) = _uiState.update {
        it.copy(rules = it.rules.toMutableList().also { l -> if (index in l.indices) l[index] = rule })
    }

    fun removeRule(index: Int) = _uiState.update {
        it.copy(rules = it.rules.toMutableList().also { l -> if (index in l.indices) l.removeAt(index) })
    }

    fun save() {
        _uiState.update { it.copy(saving = true, message = null) }
        viewModelScope.launch {
            val s = _uiState.value
            when (val r = repository.updateScoringRules(s.rules, s.maxScore)) {
                is ApiResult.Success -> _uiState.update {
                    it.copy(saving = false, rules = r.data.rules, maxScore = r.data.maxScore, message = "Scoring rules saved.")
                }
                is ApiResult.Failure -> _uiState.update {
                    it.copy(saving = false, message = r.error.message, forbidden = r.error.status == 403)
                }
                is ApiResult.NetworkError -> _uiState.update {
                    it.copy(saving = false, message = "You're offline. Try again.")
                }
            }
        }
    }

    fun clearMessage() = _uiState.update { it.copy(message = null) }
}

@Composable
fun ScoringRulesRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ScoringRulesViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ScoringRulesScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onSetMaxScore = viewModel::setMaxScore,
        onAddRule = viewModel::addRule,
        onUpdateRule = viewModel::updateRule,
        onRemoveRule = viewModel::removeRule,
        onSave = viewModel::save,
        onClearMessage = viewModel::clearMessage,
        modifier = modifier,
    )
}

@Composable
fun ScoringRulesScreen(
    state: ScoringRulesUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onSetMaxScore: (Int) -> Unit,
    onAddRule: () -> Unit,
    onUpdateRule: (Int, LeadScoreRule) -> Unit,
    onRemoveRule: (Int) -> Unit,
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
        modifier = modifier.testTag(CrmScoringRulesTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbarHostState) },
        topBar = {
            TopAppBar(
                title = { Text("Lead scoring rules") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.phase == ScoringRulesUiState.Phase.Loading ->
                LoadingState(modifier = Modifier.padding(padding))
            state.phase == ScoringRulesUiState.Phase.Error ->
                ErrorState(
                    message = state.errorMessage ?: "Couldn't load scoring rules.",
                    onRetry = onRetry,
                    modifier = Modifier.padding(padding),
                )
            state.forbidden ->
                EmptyState(
                    title = "Admin access required",
                    body = "Lead scoring rules can only be edited by an administrator.",
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )
            state.moduleDisabled ->
                EmptyState(
                    title = "Leads unavailable",
                    body = "The Leads module is not enabled for this account.",
                    modifier = Modifier.padding(padding).fillMaxSize(),
                )
            else -> Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .verticalScroll(rememberScrollState())
                    .padding(16.dp)
                    .testTag(CrmScoringRulesTestTags.CONTENT),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
                        Text("Scoring", style = MaterialTheme.typography.titleMedium)
                        OutlinedTextField(
                            value = state.maxScore.toString(),
                            onValueChange = { onSetMaxScore(it.filter(Char::isDigit).toIntOrNull() ?: 0) },
                            label = { Text("Max score") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        Text(
                            "Max achievable from current rules: ${state.maxAchievable}",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }

                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text("Rules (${state.rules.size})", style = MaterialTheme.typography.titleMedium)
                    OutlinedButton(onClick = onAddRule) {
                        Icon(Icons.Filled.Add, contentDescription = null)
                        Text(" Add")
                    }
                }

                if (state.rules.isEmpty()) {
                    Text(
                        "No rules yet. Add a rule to award points when a lead field matches.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                } else {
                    state.rules.forEachIndexed { index, rule ->
                        RuleCard(
                            rule = rule,
                            onChange = { onUpdateRule(index, it) },
                            onRemove = { onRemoveRule(index) },
                        )
                    }
                }

                if (state.sources.isNotEmpty()) {
                    Card(modifier = Modifier.fillMaxWidth()) {
                        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(4.dp)) {
                            Text("Lead sources", style = MaterialTheme.typography.titleMedium)
                            state.sources.entries.sortedByDescending { it.value }.forEach { (src, count) ->
                                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                                    Text(src.replace('_', ' '), style = MaterialTheme.typography.bodyMedium)
                                    Text(count.toString(), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Medium)
                                }
                            }
                        }
                    }
                }

                Button(
                    onClick = onSave,
                    enabled = !state.saving,
                    modifier = Modifier.fillMaxWidth().testTag(CrmScoringRulesTestTags.SAVE),
                ) { Text(if (state.saving) "Saving…" else "Save rules") }
            }
        }
    }
}

@Composable
private fun RuleCard(
    rule: LeadScoreRule,
    onChange: (LeadScoreRule) -> Unit,
    onRemove: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                OutlinedTextField(
                    value = rule.field,
                    onValueChange = { onChange(rule.copy(field = it)) },
                    label = { Text("Field") },
                    singleLine = true,
                    modifier = Modifier.weight(1f),
                )
                IconButton(onClick = onRemove) {
                    Icon(Icons.Filled.Delete, contentDescription = "Remove rule")
                }
            }
            OutlinedTextField(
                value = rule.operator,
                onValueChange = { onChange(rule.copy(operator = it)) },
                label = { Text("Operator (e.g. equals, contains)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = rule.value,
                onValueChange = { onChange(rule.copy(value = it)) },
                label = { Text("Value") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = rule.points.toString(),
                onValueChange = { v ->
                    val neg = v.startsWith("-")
                    val digits = v.filter(Char::isDigit).toIntOrNull() ?: 0
                    onChange(rule.copy(points = if (neg) -digits else digits))
                },
                label = { Text("Points") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
        }
    }
}
