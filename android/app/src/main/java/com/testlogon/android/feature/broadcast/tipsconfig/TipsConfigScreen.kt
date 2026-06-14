@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.tipsconfig

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner

/** AND-315 — stable testTags for the host tip-config editor. */
object TipsConfigTestTags {
    const val SCREEN = "tips_config_screen"
    const val ENABLED = "tips_enabled"
    const val MIN = "tips_min"
    const val MAX = "tips_max"
    const val SAVE = "tips_save"
}

/**
 * AND-315 — tip-config entry. Collects [TipsConfigViewModel] state and delegates to the stateless
 * [TipsConfigScreen]. Reached from the host control surface (BroadcastTipsConfigDest). There is NO poll loop
 * on this surface (the config is loaded once on init), so no DisposableEffect lifecycle wiring is needed.
 */
@Composable
fun TipsConfigRoute(
    onBack: () -> Unit,
    viewModel: TipsConfigViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    TipsConfigScreen(
        state = state,
        onEnabledChange = viewModel::onEnabledChange,
        onMinChange = viewModel::onMinChange,
        onMaxChange = viewModel::onMaxChange,
        onSave = viewModel::onSave,
        onRetry = viewModel::onRetry,
        onBack = onBack,
    )
}

/**
 * AND-315 — stateless tip-config editor (SMALL scope): an "allow tips" Switch + min / max dollar fields with
 * per-field validation errors + a sticky Save. Loading / Error / Offline reuse the core-ui state composables.
 */
@Composable
fun TipsConfigScreen(
    state: TipsConfigUiState,
    onEnabledChange: (Boolean) -> Unit,
    onMinChange: (String) -> Unit,
    onMaxChange: (String) -> Unit,
    onSave: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(TipsConfigTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.tips_config_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.tips_config_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when (state) {
            is TipsConfigUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            is TipsConfigUiState.Saving -> LoadingState(
                modifier = Modifier.padding(padding),
                message = stringResource(R.string.tips_config_saving),
            )
            is TipsConfigUiState.Error -> ErrorState(
                message = state.message,
                onRetry = onRetry,
                title = stringResource(R.string.tips_config_error_title),
                modifier = Modifier.padding(padding),
            )
            is TipsConfigUiState.Offline -> Column(modifier = Modifier.padding(padding).fillMaxWidth()) {
                OfflineBanner(onRetry = onRetry)
            }
            is TipsConfigUiState.Editing -> EditingForm(
                state = state,
                padding = padding,
                onEnabledChange = onEnabledChange,
                onMinChange = onMinChange,
                onMaxChange = onMaxChange,
                onSave = onSave,
            )
        }
    }
}

@Composable
private fun EditingForm(
    state: TipsConfigUiState.Editing,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onEnabledChange: (Boolean) -> Unit,
    onMinChange: (String) -> Unit,
    onMaxChange: (String) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        val enabledCd = stringResource(R.string.tips_config_enabled_cd)
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = stringResource(R.string.tips_config_enabled_label),
                style = MaterialTheme.typography.titleMedium,
            )
            Switch(
                checked = state.enabled,
                onCheckedChange = onEnabledChange,
                modifier = Modifier
                    .heightIn(min = 48.dp)
                    .testTag(TipsConfigTestTags.ENABLED)
                    .semantics { contentDescription = enabledCd },
            )
        }

        Text(
            text = stringResource(R.string.tips_config_bounds_hint),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )

        AmountField(
            value = state.minDollars,
            onValueChange = onMinChange,
            label = stringResource(R.string.tips_config_min_label),
            enabled = state.enabled,
            error = state.fieldErrors[TipField.MIN]?.let { stringResource(errorRes(it)) },
            tag = TipsConfigTestTags.MIN,
        )

        AmountField(
            value = state.maxDollars,
            onValueChange = onMaxChange,
            label = stringResource(R.string.tips_config_max_label),
            enabled = state.enabled,
            error = state.fieldErrors[TipField.MAX]?.let { stringResource(errorRes(it)) },
            tag = TipsConfigTestTags.MAX,
        )

        state.saveError?.let { message ->
            Text(
                text = message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        val saveCd = stringResource(R.string.tips_config_save_cd)
        Button(
            onClick = onSave,
            enabled = state.canSave,
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 48.dp)
                .testTag(TipsConfigTestTags.SAVE)
                .semantics { contentDescription = saveCd },
        ) {
            Text(stringResource(R.string.tips_config_save))
        }
    }
}

@Composable
private fun AmountField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    enabled: Boolean,
    error: String?,
    tag: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        OutlinedTextField(
            value = value,
            onValueChange = onValueChange,
            label = { Text(label) },
            enabled = enabled,
            isError = error != null,
            singleLine = true,
            prefix = { Text(stringResource(R.string.tips_config_amount_prefix)) },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier
                .fillMaxWidth()
                .testTag(tag),
        )
        if (error != null) {
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun errorRes(error: TipFieldError): Int = when (error) {
    TipFieldError.REQUIRED -> R.string.tips_config_error_required
    TipFieldError.OUT_OF_RANGE -> R.string.tips_config_error_out_of_range
    TipFieldError.MIN_GREATER_THAN_MAX -> R.string.tips_config_error_min_gt_max
}
