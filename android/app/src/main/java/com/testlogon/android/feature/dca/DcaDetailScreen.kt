@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.dca

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Divider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.dca.DcaPlan
import com.testlogon.android.data.dca.DcaRun
import com.testlogon.android.data.dca.DcaStatus

/**
 * DCA plan DETAIL: the plan summary, an upcoming-runs preview (computed by the pure [DcaSchedule]),
 * pause / resume / cancel + a run-now request, and the run history. Honest about the server-side runner:
 * history degrades on 404 to a "pending backend runner" state and run-now reports that the server executes
 * recurring buys rather than faking a fill.
 */
@Composable
fun DcaDetailRoute(
    onBack: () -> Unit,
    viewModel: DcaDetailViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Plan detail") },
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
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
        ) {
            when {
                state.loading -> {
                    Row(Modifier.fillMaxWidth().padding(24.dp), horizontalArrangement = Arrangement.Center) { CircularProgressIndicator() }
                }
                state.notFound -> {
                    Text("This plan couldn't be found.", style = MaterialTheme.typography.titleMedium)
                    Text(
                        "It may have been cancelled, or the server-side recurring-buy runner may still be rolling out.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.testTag("dca_detail_notfound"),
                    )
                    Spacer(Modifier.height(8.dp))
                    OutlinedButton(onClick = viewModel::refresh) { Text("Retry") }
                }
                else -> {
                    val plan = state.plan
                    if (plan != null) PlanDetailBody(plan, state, viewModel)
                }
            }

            state.errorMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("dca_detail_error"))
            }
            state.successMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("dca_detail_success"))
            }
        }
    }
}

@Composable
private fun PlanDetailBody(plan: DcaPlan, state: DcaDetailUiState, viewModel: DcaDetailViewModel) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(plan.target.label, style = MaterialTheme.typography.headlineSmall, fontWeight = FontWeight.Bold)
            Text("${DcaFormat.targetKindLabel(plan.target.kind)} · ${DcaFormat.statusLabel(plan.status)}", style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Spacer(Modifier.height(10.dp))
            DetailRow("Amount", DcaFormat.formatCentsUsd(plan.amountCents))
            DetailRow("Cadence", DcaFormat.frequencyLabel(plan.frequency, plan.dayOfWeek, plan.dayOfMonth))
            DetailRow("Funding", "USD cash balance")
            DetailRow("Starts", DcaFormat.formatDate(plan.startTs))
            plan.endTs?.let { DetailRow("Ends", DcaFormat.formatDate(it)) }
            DetailRow("Next buy", plan.nextRunTs?.let { DcaFormat.formatDate(it) } ?: "—")
            DetailRow("Spent", "${DcaFormat.formatCentsUsd(plan.spentCents)} · ${plan.buysCount} buys")
            DcaSchedule.budgetRemainingCents(plan)?.let { remaining ->
                DetailRow("Budget left", "${DcaFormat.formatCentsUsd(remaining)} (~${DcaSchedule.estimatedRunsRemaining(plan) ?: 0} buys)")
                DcaSchedule.budgetProgress(plan)?.let { p ->
                    Spacer(Modifier.height(4.dp))
                    LinearProgressIndicator(progress = { p }, modifier = Modifier.fillMaxWidth())
                }
            }
        }
    }

    // ---- upcoming preview ----
    val upcoming = DcaSchedule.upcomingRuns(plan, System.currentTimeMillis(), 5)
    if (upcoming.isNotEmpty()) {
        Spacer(Modifier.height(16.dp))
        Text("Upcoming runs", style = MaterialTheme.typography.titleMedium)
        upcoming.forEachIndexed { i, ms ->
            Text("${i + 1}. ${DcaFormat.formatDateWithDow(ms)}", style = MaterialTheme.typography.bodyMedium, modifier = Modifier.padding(vertical = 2.dp).testTag("dca_upcoming_$i"))
        }
    }

    // ---- actions ----
    Spacer(Modifier.height(16.dp))
    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
        when (plan.status) {
            DcaStatus.ACTIVE -> {
                OutlinedButton(onClick = viewModel::pause, enabled = !state.acting, modifier = Modifier.testTag("dca_detail_pause")) { Text("Pause") }
                OutlinedButton(onClick = viewModel::cancel, enabled = !state.acting) { Text("Cancel") }
            }
            DcaStatus.PAUSED -> {
                OutlinedButton(onClick = viewModel::resume, enabled = !state.acting, modifier = Modifier.testTag("dca_detail_resume")) { Text("Resume") }
                OutlinedButton(onClick = viewModel::cancel, enabled = !state.acting) { Text("Cancel") }
            }
            else -> Unit
        }
    }
    if (plan.isMutable) {
        Spacer(Modifier.height(8.dp))
        Button(onClick = viewModel::runNow, enabled = !state.acting, modifier = Modifier.fillMaxWidth().testTag("dca_run_now")) {
            if (state.acting) CircularProgressIndicator(modifier = Modifier.height(18.dp), strokeWidth = 2.dp) else Text("Run now")
        }
        Text(
            "Recurring buys run on the server on schedule; \"Run now\" only requests an immediate run.",
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
    }

    // ---- history ----
    Spacer(Modifier.height(20.dp))
    Divider()
    Spacer(Modifier.height(12.dp))
    Text("History", style = MaterialTheme.typography.titleMedium)
    if (state.runs.isEmpty()) {
        Text(
            if (state.historyPendingBackend) "No runs yet. Executed buys will appear here once the server runner runs this plan." else "No runs yet.",
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag("dca_history_empty"),
        )
    } else {
        state.runs.forEach { run -> RunRow(run) }
    }
    Spacer(Modifier.height(24.dp))
}

@Composable
private fun RunRow(run: DcaRun) {
    Column(Modifier.fillMaxWidth().padding(vertical = 6.dp)) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text(DcaFormat.formatDate(run.ts), style = MaterialTheme.typography.bodyMedium)
            Text(DcaFormat.formatCentsUsd(run.amountCents), style = MaterialTheme.typography.bodyMedium, fontWeight = FontWeight.Bold)
        }
        val detail = buildString {
            run.filledQty?.let { append("Qty $it") }
            run.priceCents?.let {
                if (isNotEmpty()) append(" @ ")
                append(DcaFormat.formatCentsUsd(it))
            }
            if (isNotEmpty()) append(" · ")
            append(run.status)
            run.note?.let { append(" — ").also { _ -> append(it) } }
        }
        Text(detail, style = MaterialTheme.typography.labelSmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Divider(Modifier.padding(top = 6.dp))
    }
}

@Composable
private fun DetailRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 3.dp), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
        Text(label, style = MaterialTheme.typography.bodyMedium, color = MaterialTheme.colorScheme.onSurfaceVariant)
        Text(value, style = MaterialTheme.typography.bodyMedium)
    }
}
