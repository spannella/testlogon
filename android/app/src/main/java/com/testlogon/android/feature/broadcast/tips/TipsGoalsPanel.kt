@file:OptIn(ExperimentalLayoutApi::class, ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.broadcast.tips

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.CheckCircle
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.platform.LocalContext
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.broadcast.tips.Goal
import com.testlogon.android.data.broadcast.tips.TipsSummary
import com.testlogon.android.feature.catalog.formatPrice

/** AND-282 — stable testTags for the tips + goals surface. */
object TipsTestTags {
    const val SUMMARY = "bcast_tips_summary"
    const val TIP_ACTION = "bcast_tip_action"
    const val SHEET = "bcast_tip_sheet"
    const val SHEET_SUBMIT = "bcast_tip_submit"
    const val GOAL_ROW = "bcast_goal_row"
}

/**
 * AND-282 — host that owns the assisted-inject [TipsGoalsViewModel] keyed by [sessionId], collects its
 * [TipsEffect]s into a snackbar, and renders [TipsGoalsSection]. Composed into the AND-280 viewer.
 */
@Composable
fun TipsGoalsPanel(
    sessionId: String,
    modifier: Modifier = Modifier,
    viewModel: TipsGoalsViewModel = hiltViewModel<TipsGoalsViewModel, TipsGoalsViewModel.Factory>(
        key = "tips_goals_$sessionId",
        creationCallback = { factory -> factory.create(sessionId) },
    ),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val snackbarHostState = remember { SnackbarHostState() }
    val resources = LocalContext.current.resources

    LaunchedEffect(viewModel) {
        viewModel.effects.collect { effect ->
            val message = when (effect) {
                TipsEffect.TipSent -> resources.getString(R.string.bcast_tip_sent)
                TipsEffect.PaymentsUnavailable -> resources.getString(R.string.bcast_tip_payments_unavailable)
                is TipsEffect.TipFailed -> effect.message ?: resources.getString(R.string.bcast_tip_failed)
            }
            snackbarHostState.showSnackbar(message)
        }
    }

    Column(modifier = modifier.fillMaxWidth()) {
        TipsGoalsSection(
            summary = state.summary,
            goals = state.goals,
            tipInFlight = state.tipInFlight,
            onSubmitTip = { amountCents, text -> viewModel.submitTip(amountCents, text) },
        )
        SnackbarHost(hostState = snackbarHostState)
    }
}

/**
 * AND-282 — the tips summary band + goals list + a Tip action that opens the composer sheet. Composed
 * into the AND-280 viewer overlay/tab. Amounts are formatted from cents via the reused AND-205
 * [formatPrice]. The composer is a Material 3 [ModalBottomSheet].
 */
@Composable
fun TipsGoalsSection(
    summary: TipsSummary?,
    goals: List<Goal>,
    tipInFlight: Boolean,
    onSubmitTip: (amountCents: Long, text: String?) -> Unit,
    modifier: Modifier = Modifier,
) {
    var sheetOpen by rememberSaveable { mutableStateOf(false) }
    val currency = summary?.currency ?: "USD"

    Column(modifier = modifier.fillMaxWidth().padding(8.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            TipsSummaryBar(summary = summary, modifier = Modifier.weight(1f))
            Button(
                onClick = { sheetOpen = true },
                modifier = Modifier.testTag(TipsTestTags.TIP_ACTION),
            ) {
                Text(stringResource(R.string.bcast_tip_action))
            }
        }
        if (goals.isNotEmpty()) {
            GoalList(goals = goals, currency = currency, modifier = Modifier.padding(top = 8.dp))
        }
    }

    if (sheetOpen) {
        TipComposerSheet(
            inFlight = tipInFlight,
            currency = currency,
            onSubmit = { amountCents, text ->
                onSubmitTip(amountCents, text)
            },
            onDismiss = { sheetOpen = false },
        )
    }
}

@Composable
fun TipsSummaryBar(summary: TipsSummary?, modifier: Modifier = Modifier) {
    val text = if (summary == null) {
        stringResource(R.string.bcast_tips_summary_empty)
    } else {
        stringResource(
            R.string.bcast_tips_summary,
            formatPrice(summary.totalCents, summary.currency),
            summary.tipCount,
        )
    }
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        modifier = modifier.testTag(TipsTestTags.SUMMARY),
    )
}

@Composable
fun GoalList(goals: List<Goal>, currency: String, modifier: Modifier = Modifier) {
    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        for (goal in goals) {
            GoalRow(goal = goal, currency = currency)
        }
    }
}

@Composable
fun GoalRow(goal: Goal, currency: String, modifier: Modifier = Modifier) {
    val amounts = stringResource(
        R.string.bcast_goal_amounts,
        formatPrice(goal.currentCents, currency),
        formatPrice(goal.targetCents, currency),
    )
    val stateDesc = stringResource(
        R.string.bcast_goal_state_cd,
        goal.label,
        goal.percent,
        formatPrice(goal.currentCents, currency),
        formatPrice(goal.targetCents, currency),
    )
    Column(
        modifier = modifier
            .fillMaxWidth()
            .testTag(TipsTestTags.GOAL_ROW)
            .semantics { stateDescription = stateDesc },
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Text(text = goal.label, style = MaterialTheme.typography.labelLarge)
            if (goal.isReached) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Icon(
                        Icons.Filled.CheckCircle,
                        contentDescription = null,
                        tint = MaterialTheme.colorScheme.primary,
                    )
                    Text(
                        text = stringResource(R.string.bcast_goal_reached),
                        style = MaterialTheme.typography.labelMedium,
                        color = MaterialTheme.colorScheme.primary,
                        modifier = Modifier.padding(start = 4.dp),
                    )
                }
            } else {
                Text(
                    text = stringResource(R.string.bcast_goal_percent, goal.percent),
                    style = MaterialTheme.typography.labelMedium,
                )
            }
        }
        LinearProgressIndicator(
            progress = { goal.fraction },
            modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        )
        Text(text = amounts, style = MaterialTheme.typography.bodySmall)
    }
}

/**
 * AND-282 — the tip composer bottom sheet. Presets are shown in dollars; the submitted value is cents.
 * Submit is disabled while in-flight or until an in-bounds amount is selected/entered. A
 * payment-method picker is out of scope here — the BillingAuthorizer owns method selection (the stub
 * surfaces "payments unavailable" without charging).
 */
@Composable
fun TipComposerSheet(
    inFlight: Boolean,
    currency: String,
    onSubmit: (amountCents: Long, text: String?) -> Unit,
    onDismiss: () -> Unit,
) {
    var selectedCents by rememberSaveable { mutableStateOf<Long?>(null) }
    var customInput by rememberSaveable { mutableStateOf("") }
    var note by rememberSaveable { mutableStateOf("") }

    val customCents = remember(customInput) { parseDollarsToCents(customInput) }
    val amountCents = customCents ?: selectedCents
    val valid = amountCents != null &&
        amountCents in TipsGoalsViewModel.MIN_TIP_CENTS..TipsGoalsViewModel.MAX_TIP_CENTS

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(TipsTestTags.SHEET)) {
        Column(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp),
        ) {
            Text(
                text = stringResource(R.string.bcast_tip_sheet_title),
                style = MaterialTheme.typography.titleMedium,
            )
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for (preset in TipsGoalsViewModel.PRESET_CENTS) {
                    FilterChip(
                        selected = selectedCents == preset && customInput.isBlank(),
                        onClick = {
                            selectedCents = preset
                            customInput = ""
                        },
                        label = { Text(formatPrice(preset, currency)) },
                    )
                }
            }
            OutlinedTextField(
                value = customInput,
                onValueChange = {
                    customInput = it
                    if (it.isNotBlank()) selectedCents = null
                },
                label = { Text(stringResource(R.string.bcast_tip_custom_amount)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            OutlinedTextField(
                value = note,
                onValueChange = { if (it.length <= MAX_NOTE_LEN) note = it },
                label = { Text(stringResource(R.string.bcast_tip_note)) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                OutlinedButton(onClick = onDismiss, enabled = !inFlight) {
                    Text(stringResource(R.string.bcast_tip_cancel))
                }
                Button(
                    onClick = { amountCents?.let { onSubmit(it, note.takeIf(String::isNotBlank)) } },
                    enabled = valid && !inFlight,
                    modifier = Modifier.weight(1f).testTag(TipsTestTags.SHEET_SUBMIT),
                ) {
                    if (inFlight) {
                        Box(contentAlignment = Alignment.Center) {
                            CircularProgressIndicator(modifier = Modifier.padding(2.dp))
                        }
                    } else {
                        Text(stringResource(R.string.bcast_tip_send))
                    }
                }
            }
            TextButton(onClick = onDismiss) { Text(stringResource(R.string.bcast_tip_dismiss)) }
        }
    }
}

/** Parses a dollars string (e.g. "12.50") into integer cents, or null when blank/invalid. */
internal fun parseDollarsToCents(input: String): Long? {
    val trimmed = input.trim()
    if (trimmed.isEmpty()) return null
    val dollars = trimmed.toDoubleOrNull() ?: return null
    if (dollars <= 0.0) return null
    return Math.round(dollars * 100.0)
}

private const val MAX_NOTE_LEN = 280
