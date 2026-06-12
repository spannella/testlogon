@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.inputs

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Videocam
import androidx.compose.material.icons.outlined.Person
import androidx.compose.material.icons.outlined.Videocam
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AssistChipDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilledTonalButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.core.ui.state.StaleBanner
import com.testlogon.android.data.broadcast.BroadcastInput
import com.testlogon.android.data.broadcast.InputType

/** AND-310 — stable testTags for the inputs-management surface. */
object InputsTestTags {
    const val SCREEN = "inputs_screen"
    const val LIST = "inputs_list"
    const val TOGGLE = "inputs_toggle"
    const val MAKE_LIVE = "inputs_make_live"
    const val PROGRAM_BADGE = "inputs_program_badge"
    const val EMPTY = "inputs_empty"
    const val ERROR = "inputs_error"
    const val STALE_BANNER = "inputs_stale_banner"
    const val PENDING = "inputs_pending"

    /** Stable per-row tag: inputs_row_<inputId>. */
    fun row(inputId: String): String = "inputs_row_$inputId"
}

/**
 * AND-310 — inputs-management entry. Collects [InputsViewModel] state and delegates to the stateless
 * [InputsScreen]. Reached from the host control surface (BroadcastInputsDest).
 */
@Composable
fun InputsRoute(
    onBack: () -> Unit,
    viewModel: InputsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    // Drive the live-refresh poll loop only while this surface is composed (AND-310 FR-5).
    DisposableEffect(viewModel) {
        viewModel.startPolling()
        onDispose { viewModel.stopPolling() }
    }
    InputsScreen(
        state = state,
        onToggleActive = viewModel::onToggleActive,
        onMakeLive = viewModel::onMakeLive,
        onRetry = viewModel::onRetry,
        onBack = onBack,
    )
}

/**
 * AND-310 — stateless inputs list. Each row shows a type icon, label, a live/offline status chip
 * (text + icon, not colour-only), a Switch (active; DISABLED for the program row with explanatory
 * semantics), and a "Make live" button gated by [InputRow.canMakeLive]. The program row shows a LIVE badge.
 * Pending rows show inline progress and are non-interactive. Loading / Empty / Error states reuse core-ui.
 */
@Composable
fun InputsScreen(
    state: InputsUiState,
    onToggleActive: (String, Boolean) -> Unit,
    onMakeLive: (String) -> Unit,
    onRetry: () -> Unit,
    onBack: () -> Unit,
) {
    Scaffold(
        modifier = Modifier.testTag(InputsTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.inputs_title)) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(
                            Icons.AutoMirrored.Filled.ArrowBack,
                            contentDescription = stringResource(R.string.inputs_back_cd),
                        )
                    }
                },
            )
        },
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is InputsUiState.Loading -> LoadingState()

                is InputsUiState.Error -> ErrorState(
                    message = state.message,
                    onRetry = onRetry,
                    title = stringResource(R.string.inputs_error_title),
                    modifier = Modifier.testTag(InputsTestTags.ERROR),
                )

                is InputsUiState.Empty -> Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isStale) {
                        StaleBanner(
                            stale = true,
                            refreshing = false,
                            onRetry = onRetry,
                            modifier = Modifier.testTag(InputsTestTags.STALE_BANNER),
                        )
                    }
                    EmptyState(
                        title = stringResource(R.string.inputs_empty_title),
                        body = stringResource(R.string.inputs_empty_body),
                        modifier = Modifier.testTag(InputsTestTags.EMPTY),
                    )
                }

                is InputsUiState.Content -> Column(modifier = Modifier.fillMaxSize()) {
                    if (state.isStale) {
                        StaleBanner(
                            stale = true,
                            refreshing = false,
                            onRetry = onRetry,
                            modifier = Modifier.testTag(InputsTestTags.STALE_BANNER),
                        )
                    }
                    LazyColumn(
                        modifier = Modifier
                            .fillMaxSize()
                            .testTag(InputsTestTags.LIST)
                            .semantics { liveRegion = LiveRegionMode.Polite },
                        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp),
                    ) {
                        items(state.inputs, key = { it.input.inputId }) { rowState ->
                            InputRowItem(
                                row = rowState,
                                pending = state.pendingIds.contains(rowState.input.inputId),
                                onToggleActive = onToggleActive,
                                onMakeLive = onMakeLive,
                            )
                        }
                    }
                }
            }
        }
    }
}

/**
 * AND-310 — a single input row. Leading type icon, label + status chip, trailing Switch / Make-live, and a
 * LIVE badge on the program row. While [pending] the row shows a progress indicator and is non-interactive.
 */
@Composable
fun InputRowItem(
    row: InputRow,
    pending: Boolean,
    onToggleActive: (String, Boolean) -> Unit,
    onMakeLive: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val input = row.input
    val label = input.label?.takeIf { it.isNotBlank() } ?: stringResource(R.string.inputs_unnamed)
    Surface(
        tonalElevation = 1.dp,
        modifier = modifier
            .fillMaxWidth()
            .testTag(InputsTestTags.row(input.inputId)),
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(min = 56.dp)
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Icon(
                imageVector = iconFor(input.inputTypeEnum),
                contentDescription = stringResource(typeLabelRes(input.inputTypeEnum)),
                modifier = Modifier.size(28.dp),
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                Text(text = label, style = MaterialTheme.typography.titleSmall)
                StatusChip(isLive = input.isLive)
            }

            if (input.isProgram) {
                ProgramBadge()
            }

            if (pending) {
                val pendingCd = stringResource(R.string.inputs_pending_cd, label)
                CircularProgressIndicator(
                    strokeWidth = 2.dp,
                    modifier = Modifier
                        .size(24.dp)
                        .testTag(InputsTestTags.PENDING)
                        .semantics { contentDescription = pendingCd },
                )
            } else {
                if (row.canMakeLive) {
                    val makeLiveCd = stringResource(R.string.inputs_make_live_cd, label)
                    FilledTonalButton(
                        onClick = { onMakeLive(input.inputId) },
                        modifier = Modifier
                            .heightIn(min = 48.dp)
                            .testTag(InputsTestTags.MAKE_LIVE)
                            .semantics { contentDescription = makeLiveCd },
                    ) {
                        Text(stringResource(R.string.inputs_make_live))
                    }
                }

                val toggleCd = if (input.isProgram) {
                    stringResource(R.string.inputs_toggle_program_disabled_cd)
                } else if (input.isLive) {
                    stringResource(R.string.inputs_toggle_inactive_cd, label)
                } else {
                    stringResource(R.string.inputs_toggle_active_cd, label)
                }
                Switch(
                    checked = input.isLive,
                    onCheckedChange = { onToggleActive(input.inputId, it) },
                    // The program row cannot be deactivated; disable its switch with explanatory semantics.
                    enabled = row.canDeactivate || !input.isLive,
                    modifier = Modifier
                        .testTag(InputsTestTags.TOGGLE)
                        .semantics { contentDescription = toggleCd },
                )
            }
        }
    }
}

/** Status chip conveyed by text + icon (not colour alone). */
@Composable
private fun StatusChip(isLive: Boolean) {
    val labelRes = if (isLive) R.string.inputs_status_live else R.string.inputs_status_offline
    val icon = if (isLive) Icons.Filled.Videocam else Icons.Outlined.Videocam
    AssistChip(
        onClick = {},
        enabled = false,
        label = { Text(stringResource(labelRes)) },
        leadingIcon = {
            Icon(icon, contentDescription = null, modifier = Modifier.size(AssistChipDefaults.IconSize))
        },
    )
}

/** The LIVE program badge (state described for screen readers). */
@Composable
private fun ProgramBadge() {
    val badgeCd = stringResource(R.string.inputs_program_badge_cd)
    Surface(
        color = MaterialTheme.colorScheme.errorContainer,
        contentColor = MaterialTheme.colorScheme.onErrorContainer,
        modifier = Modifier
            .testTag(InputsTestTags.PROGRAM_BADGE)
            .semantics { stateDescription = badgeCd },
    ) {
        Text(
            text = stringResource(R.string.inputs_program_badge),
            style = MaterialTheme.typography.labelMedium,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
        )
    }
}

private fun iconFor(type: InputType): ImageVector = when (type) {
    InputType.PRIMARY -> Icons.Filled.Videocam
    InputType.GUEST -> Icons.Outlined.Person
    InputType.SCREEN -> Icons.Outlined.Videocam
    InputType.UNKNOWN -> Icons.Outlined.Videocam
}

private fun typeLabelRes(type: InputType): Int = when (type) {
    InputType.PRIMARY -> R.string.inputs_type_primary
    InputType.GUEST -> R.string.inputs_type_guest
    InputType.SCREEN -> R.string.inputs_type_screen
    InputType.UNKNOWN -> R.string.inputs_type_unknown
}
