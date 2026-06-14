@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.host.ads

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Remove
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
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
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.OfflineBanner

/** AND-316 — stable testTags for the host ad-break / ad-config surface. */
object AdControlTestTags {
    const val SCREEN = "ad_control_screen"
    const val PRE_ROLL = "ad_pre_roll"
    const val DURATION = "ad_duration"
    const val SKIP_AFTER = "ad_skip_after"
    const val SAVE = "ad_save"
    const val TRIGGER = "ad_trigger"
    const val COUNTDOWN = "ad_countdown"
    const val END = "ad_end"
    const val TOTAL_BREAKS = "ad_total_breaks"
}

/**
 * AND-316 — ads entry. Collects [AdControlViewModel] state and delegates to the stateless [AdControlScreen].
 * Reached from the host control surface (BroadcastAdsDest). The config is loaded once on init and the only
 * lifecycle-bound work is the active-break countdown ticker, which the ViewModel arms/cancels itself — so no
 * DisposableEffect poll wiring is needed here.
 */
@Composable
fun AdControlRoute(
    onBack: () -> Unit,
    viewModel: AdControlViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdControlScreen(
        state = state,
        onPreRollToggled = viewModel::onPreRollToggled,
        onDurationChanged = viewModel::onDurationChanged,
        onSkipAfterChanged = viewModel::onSkipAfterChanged,
        onSave = viewModel::saveConfig,
        onTrigger = viewModel::triggerAdBreak,
        onEnd = viewModel::endAdBreak,
        onRetry = viewModel::onRetry,
        onBack = onBack,
    )
}

/**
 * AND-316 — stateless host ads surface: an ad-config card (pre-roll Switch + duration / skip-after steppers
 * with inline validation + a Save button) and an ad-break card that shows EITHER a "Trigger ad break" button
 * or, while active, a countdown chip + "End early" button. Loading / error / offline reuse the core-ui shell.
 */
@Composable
fun AdControlScreen(
    state: AdControlUiState,
    onPreRollToggled: (Boolean) -> Unit,
    onDurationChanged: (Int) -> Unit,
    onSkipAfterChanged: (Int) -> Unit,
    onSave: () -> Unit,
    onTrigger: () -> Unit,
    onEnd: () -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(AdControlTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.ads_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.ads_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        when {
            state.loading -> LoadingState(modifier = Modifier.padding(padding))
            state.offline && !state.hasConfig -> Column(
                modifier = Modifier.padding(padding).fillMaxWidth(),
            ) {
                OfflineBanner(onRetry = onRetry)
            }
            state.error != null && !state.hasConfig -> ErrorState(
                message = state.error,
                onRetry = onRetry,
                title = stringResource(R.string.ads_error_title),
                modifier = Modifier.padding(padding),
            )
            else -> AdContent(
                state = state,
                padding = padding,
                onPreRollToggled = onPreRollToggled,
                onDurationChanged = onDurationChanged,
                onSkipAfterChanged = onSkipAfterChanged,
                onSave = onSave,
                onTrigger = onTrigger,
                onEnd = onEnd,
            )
        }
    }
}

@Composable
private fun AdContent(
    state: AdControlUiState,
    padding: androidx.compose.foundation.layout.PaddingValues,
    onPreRollToggled: (Boolean) -> Unit,
    onDurationChanged: (Int) -> Unit,
    onSkipAfterChanged: (Int) -> Unit,
    onSave: () -> Unit,
    onTrigger: () -> Unit,
    onEnd: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(padding)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        AdConfigCard(
            form = state.config,
            enabled = !state.mutationInFlight,
            onPreRollToggled = onPreRollToggled,
            onDurationChanged = onDurationChanged,
            onSkipAfterChanged = onSkipAfterChanged,
            onSave = onSave,
        )

        AdBreakCard(
            state = state,
            onTrigger = onTrigger,
            onEnd = onEnd,
        )

        state.error?.let { message ->
            Text(
                text = message,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodyMedium,
            )
        }

        if (state.offline) {
            OfflineBanner(onRetry = {})
        }

        Text(
            modifier = Modifier.testTag(AdControlTestTags.TOTAL_BREAKS),
            text = stringResource(R.string.ad_break_total, state.totalAdBreaks),
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }
}

@Composable
private fun AdConfigCard(
    form: AdConfigForm,
    enabled: Boolean,
    onPreRollToggled: (Boolean) -> Unit,
    onDurationChanged: (Int) -> Unit,
    onSkipAfterChanged: (Int) -> Unit,
    onSave: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            Text(
                text = stringResource(R.string.ads_config_title),
                style = MaterialTheme.typography.titleMedium,
            )

            val preRollCd = stringResource(R.string.ads_pre_roll_cd)
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = stringResource(R.string.ads_pre_roll_label),
                    style = MaterialTheme.typography.bodyLarge,
                )
                Switch(
                    checked = form.preRollEnabled,
                    onCheckedChange = onPreRollToggled,
                    enabled = enabled,
                    modifier = Modifier
                        .heightIn(min = 48.dp)
                        .testTag(AdControlTestTags.PRE_ROLL)
                        .semantics { contentDescription = preRollCd },
                )
            }

            StepperField(
                label = stringResource(R.string.ads_duration_label),
                hint = stringResource(R.string.ads_duration_hint),
                cd = stringResource(R.string.ads_duration_cd),
                value = form.midRollDurationSeconds,
                isError = !form.durationValid,
                error = stringResource(R.string.ads_duration_error),
                enabled = enabled,
                onChange = onDurationChanged,
                tag = AdControlTestTags.DURATION,
            )

            StepperField(
                label = stringResource(R.string.ads_skip_after_label),
                hint = stringResource(R.string.ads_skip_after_hint),
                cd = stringResource(R.string.ads_skip_after_cd),
                value = form.skipAfterSeconds,
                isError = !form.skipValid,
                error = stringResource(R.string.ads_skip_after_error),
                enabled = enabled,
                onChange = onSkipAfterChanged,
                tag = AdControlTestTags.SKIP_AFTER,
            )

            val saveCd = stringResource(R.string.ads_save_cd)
            Button(
                onClick = onSave,
                enabled = enabled && form.canSave,
                modifier = Modifier
                    .fillMaxWidth()
                    .heightIn(min = 48.dp)
                    .testTag(AdControlTestTags.SAVE)
                    .semantics { contentDescription = saveCd },
            ) {
                Text(stringResource(R.string.ads_save))
            }
        }
    }
}

/**
 * A labelled numeric stepper (minus / value / plus). Editing the Int directly keeps the value type aligned
 * with the ViewModel's [AdControlViewModel.onDurationChanged] / [AdControlViewModel.onSkipAfterChanged]
 * Int-typed callbacks, so there is no string parsing on this surface.
 */
@Composable
private fun StepperField(
    label: String,
    hint: String,
    cd: String,
    value: Int,
    isError: Boolean,
    error: String,
    enabled: Boolean,
    onChange: (Int) -> Unit,
    tag: String,
) {
    Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
        Text(text = label, style = MaterialTheme.typography.bodyMedium)
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .testTag(tag)
                .semantics { contentDescription = cd },
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            IconButton(
                onClick = { onChange(value - 1) },
                enabled = enabled,
                modifier = Modifier.size(48.dp),
            ) {
                Icon(
                    Icons.Filled.Remove,
                    contentDescription = stringResource(R.string.ad_break_end),
                )
            }
            Text(
                text = value.toString(),
                style = MaterialTheme.typography.titleLarge,
                color = if (isError) {
                    MaterialTheme.colorScheme.error
                } else {
                    MaterialTheme.colorScheme.onSurface
                },
            )
            IconButton(
                onClick = { onChange(value + 1) },
                enabled = enabled,
                modifier = Modifier.size(48.dp),
            ) {
                Icon(
                    Icons.Filled.Add,
                    contentDescription = stringResource(R.string.ad_break_trigger),
                )
            }
        }
        Text(
            text = hint,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (isError) {
            Text(
                text = error,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun AdBreakCard(
    state: AdControlUiState,
    onTrigger: () -> Unit,
    onEnd: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.ad_break_title),
                style = MaterialTheme.typography.titleMedium,
            )

            if (state.adBreakActive) {
                val countdownCd = stringResource(R.string.ad_break_countdown_cd, state.remainingSeconds)
                AssistChip(
                    onClick = {},
                    modifier = Modifier
                        .testTag(AdControlTestTags.COUNTDOWN)
                        .semantics {
                            contentDescription = countdownCd
                            liveRegion = LiveRegionMode.Polite
                        },
                    label = { Text(stringResource(R.string.ad_break_countdown, state.remainingSeconds)) },
                )

                val endCd = stringResource(R.string.ad_break_end_cd)
                OutlinedButton(
                    onClick = onEnd,
                    enabled = state.adBreakActive && !state.mutationInFlight,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(AdControlTestTags.END)
                        .semantics { contentDescription = endCd },
                ) {
                    ButtonContent(loading = state.mutationInFlight) {
                        Text(stringResource(R.string.ad_break_end))
                    }
                }
            } else {
                Text(
                    text = stringResource(R.string.ad_break_inactive_hint),
                    style = MaterialTheme.typography.bodyMedium,
                )

                val triggerCd = stringResource(R.string.ad_break_trigger_cd)
                FilledTonalButton(
                    onClick = onTrigger,
                    enabled = !state.adBreakActive && !state.mutationInFlight,
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .testTag(AdControlTestTags.TRIGGER)
                        .semantics { contentDescription = triggerCd },
                ) {
                    ButtonContent(loading = state.mutationInFlight) {
                        Text(stringResource(R.string.ad_break_trigger))
                    }
                }
            }
        }
    }
}

/** Swaps a button's label for a small spinner while a mutation is in flight. */
@Composable
private fun ButtonContent(loading: Boolean, content: @Composable () -> Unit) {
    if (loading) {
        CircularProgressIndicator(modifier = Modifier.size(20.dp))
    } else {
        content()
    }
}
