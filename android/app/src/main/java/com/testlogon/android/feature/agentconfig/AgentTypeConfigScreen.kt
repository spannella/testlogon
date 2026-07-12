@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.agentconfig

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.HorizontalDivider
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
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.data.agentconfig.AgentField
import com.testlogon.android.data.agentconfig.FieldSpec

/** Stable testTags for the parametrized agent-type config screen. */
object AgentConfigTestTags {
    const val SCREEN = "agent_config_screen"
    const val CONTENT = "agent_config_content"
    const val FORBIDDEN = "agent_config_forbidden"
    const val ERROR = "agent_config_error"
    const val SAVE = "agent_config_save"
    const val VALIDATE = "agent_config_validate"
    fun field(key: String) = "agent_config_field_$key"
}

@Composable
fun AgentTypeConfigRoute(
    onBack: () -> Unit,
    onSessionExpired: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: AgentTypeConfigViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbar = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        viewModel.effects.collect { eff ->
            when (eff) {
                is AgentConfigEffect.ShowMessage -> snackbar.showSnackbar(eff.text)
            }
        }
    }
    LaunchedEffect(state.phase) {
        if (state.phase == AgentConfigUiState.Phase.SessionExpired) onSessionExpired()
    }

    AgentTypeConfigScreen(
        state = state,
        snackbar = snackbar,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onTextChange = viewModel::onTextChange,
        onBoolChange = viewModel::onBoolChange,
        onValidate = viewModel::onValidate,
        onSave = viewModel::onSave,
        modifier = modifier,
    )
}

@Composable
fun AgentTypeConfigScreen(
    state: AgentConfigUiState,
    snackbar: SnackbarHostState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onTextChange: (String, String) -> Unit,
    onBoolChange: (String, Boolean) -> Unit,
    onValidate: () -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AgentConfigTestTags.SCREEN),
        snackbarHost = { SnackbarHost(snackbar) },
        topBar = {
            TopAppBar(
                title = { Text("${state.type.title} · ${state.typeId}") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Box(Modifier.fillMaxSize().padding(padding)) {
            when (state.phase) {
                AgentConfigUiState.Phase.Loading ->
                    LoadingState(message = "Loading configuration…")

                AgentConfigUiState.Phase.Forbidden ->
                    ForbiddenState(modifier = Modifier.testTag(AgentConfigTestTags.FORBIDDEN))

                AgentConfigUiState.Phase.SessionExpired ->
                    LoadingState(message = "Session expired…")

                AgentConfigUiState.Phase.Offline ->
                    ErrorState(
                        message = state.errorMessage ?: "Offline",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AgentConfigTestTags.ERROR),
                    )

                AgentConfigUiState.Phase.Error ->
                    ErrorState(
                        message = state.errorMessage ?: "Something went wrong",
                        onRetry = onRetry,
                        modifier = Modifier.testTag(AgentConfigTestTags.ERROR),
                    )

                AgentConfigUiState.Phase.Content -> ConfigFormContent(
                    state = state,
                    onTextChange = onTextChange,
                    onBoolChange = onBoolChange,
                    onValidate = onValidate,
                    onSave = onSave,
                )
            }
        }
    }
}

@Composable
private fun ForbiddenState(modifier: Modifier = Modifier) {
    Column(
        modifier = modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(Icons.Outlined.Lock, contentDescription = null)
        Text(
            "Operators only",
            style = MaterialTheme.typography.titleMedium,
            modifier = Modifier.padding(top = 12.dp),
        )
        Text(
            "This agent configuration is restricted to operator / admin accounts.",
            style = MaterialTheme.typography.bodyMedium,
            modifier = Modifier.padding(top = 6.dp),
        )
    }
}

@Composable
private fun ConfigFormContent(
    state: AgentConfigUiState,
    onTextChange: (String, String) -> Unit,
    onBoolChange: (String, Boolean) -> Unit,
    onValidate: () -> Unit,
    onSave: () -> Unit,
) {
    val form = state.form ?: return
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag(AgentConfigTestTags.CONTENT),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        if (state.validationErrors.isNotEmpty()) {
            item {
                Column {
                    Text(
                        "Validation issues",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.error,
                    )
                    state.validationErrors.forEach {
                        Text("• $it", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.error)
                    }
                    HorizontalDivider(Modifier.padding(top = 8.dp))
                }
            }
        }

        items(state.type.fields, key = { it.key }) { spec ->
            FieldEditor(
                spec = spec,
                value = form.values[spec.key] ?: "",
                bool = form.bools[spec.key] ?: false,
                onTextChange = onTextChange,
                onBoolChange = onBoolChange,
            )
        }

        item {
            Row(
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp),
                horizontalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                OutlinedButton(
                    onClick = onValidate,
                    modifier = Modifier.testTag(AgentConfigTestTags.VALIDATE),
                ) { Text("Validate") }
                Button(
                    onClick = onSave,
                    enabled = !state.isSaving,
                    modifier = Modifier.testTag(AgentConfigTestTags.SAVE),
                ) {
                    if (state.isSaving) {
                        CircularProgressIndicator(modifier = Modifier.padding(end = 8.dp), strokeWidth = 2.dp)
                    }
                    Text("Save")
                }
            }
        }
    }
}

@Composable
private fun FieldEditor(
    spec: FieldSpec,
    value: String,
    bool: Boolean,
    onTextChange: (String, String) -> Unit,
    onBoolChange: (String, Boolean) -> Unit,
) {
    when (spec.type) {
        AgentField.BOOL -> Row(
            modifier = Modifier.fillMaxWidth().testTag(AgentConfigTestTags.field(spec.key)),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(spec.label, style = MaterialTheme.typography.bodyLarge)
            Switch(checked = bool, onCheckedChange = { onBoolChange(spec.key, it) })
        }

        AgentField.ENUM -> EnumField(spec, value, onTextChange)

        AgentField.MULTILINE, AgentField.STRING_LIST -> OutlinedTextField(
            value = value,
            onValueChange = { onTextChange(spec.key, it) },
            label = { Text(spec.label) },
            supportingText = spec.helper?.let { { Text(it) } },
            minLines = 3,
            modifier = Modifier.fillMaxWidth().testTag(AgentConfigTestTags.field(spec.key)),
        )

        AgentField.NUMBER_INT, AgentField.NUMBER_DOUBLE -> OutlinedTextField(
            value = value,
            onValueChange = { onTextChange(spec.key, it) },
            label = { Text(spec.label) },
            singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number, imeAction = ImeAction.Next),
            modifier = Modifier.fillMaxWidth().testTag(AgentConfigTestTags.field(spec.key)),
        )

        AgentField.TEXT -> OutlinedTextField(
            value = value,
            onValueChange = { onTextChange(spec.key, it) },
            label = { Text(spec.label) },
            supportingText = spec.helper?.let { { Text(it) } },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(AgentConfigTestTags.field(spec.key)),
        )
    }
}

@Composable
private fun EnumField(
    spec: FieldSpec,
    value: String,
    onTextChange: (String, String) -> Unit,
) {
    var expanded by rememberSaveable(spec.key) { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = Modifier.fillMaxWidth(),
    ) {
        OutlinedTextField(
            value = value,
            onValueChange = {},
            readOnly = true,
            label = { Text(spec.label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor()
                .testTag(AgentConfigTestTags.field(spec.key)),
        )
        ExposedDropdownMenu(
            expanded = expanded,
            onDismissRequest = { expanded = false },
        ) {
            spec.options.forEach { option ->
                DropdownMenuItem(
                    text = { Text(option) },
                    onClick = {
                        onTextChange(spec.key, option)
                        expanded = false
                    },
                )
            }
        }
    }
}
