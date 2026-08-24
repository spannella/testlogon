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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExtendedFloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import com.testlogon.android.data.dca.DcaStatus

/**
 * The DCA / RECURRING-BUYS plans list. Lists each plan's target / amount / cadence / next-run / budget
 * progress / status with pause / resume / cancel, opens a plan's detail, and launches the create flow. A
 * banner is explicit that once scheduled, recurring buys run SERVER-SIDE. Loading degrades on 404 to an
 * honest "pending backend runner" empty state.
 */
@Composable
fun DcaPlansRoute(
    onBack: () -> Unit,
    onCreate: () -> Unit,
    onOpenPlan: (String) -> Unit,
    viewModel: DcaPlansViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("Recurring buys") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = onCreate,
                icon = { Icon(Icons.Filled.Add, contentDescription = null) },
                text = { Text("New plan") },
                modifier = Modifier.testTag("dca_create_fab"),
            )
        },
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
        ) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(14.dp)) {
                    Text("Dollar-cost averaging", style = MaterialTheme.typography.titleSmall)
                    Text(
                        "Schedule recurring buys funded from your USD cash balance. Once scheduled, buys run automatically on the server — you don't need the app open.",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }

            state.errorMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("dca_error"))
                Spacer(Modifier.height(4.dp))
                OutlinedButton(onClick = viewModel::refresh) { Text("Retry") }
            }
            state.successMessage?.let {
                Spacer(Modifier.height(12.dp))
                Text(it, color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium, modifier = Modifier.testTag("dca_success"))
            }

            Spacer(Modifier.height(12.dp))

            when {
                state.loading -> {
                    Row(Modifier.fillMaxWidth().padding(24.dp), horizontalArrangement = Arrangement.Center) {
                        CircularProgressIndicator()
                    }
                }
                state.isEmpty -> {
                    Column(Modifier.fillMaxWidth().padding(top = 24.dp), horizontalAlignment = Alignment.CenterHorizontally) {
                        Text("No recurring buys yet", style = MaterialTheme.typography.titleMedium)
                        Text(
                            if (state.emptyPendingBackend) {
                                "Create a plan to start dollar-cost averaging. (The recurring-buy runner is server-side and may still be rolling out.)"
                            } else {
                                "Create a plan to start dollar-cost averaging."
                            },
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 4.dp).testTag("dca_empty"),
                        )
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = onCreate) { Text("Create a plan") }
                    }
                }
                else -> {
                    LazyColumn(verticalArrangement = Arrangement.spacedBy(10.dp)) {
                        items(state.plans, key = { it.planId }) { plan ->
                            DcaPlanCard(
                                plan = plan,
                                acting = state.actingPlanId == plan.planId,
                                onOpen = { onOpenPlan(plan.planId) },
                                onPause = { viewModel.pause(plan.planId) },
                                onResume = { viewModel.resume(plan.planId) },
                                onCancel = { viewModel.cancel(plan.planId) },
                            )
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun DcaPlanCard(
    plan: DcaPlan,
    acting: Boolean,
    onOpen: () -> Unit,
    onPause: () -> Unit,
    onResume: () -> Unit,
    onCancel: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth().testTag("dca_plan_${plan.planId}")) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                Column(Modifier.weight(1f)) {
                    Text(plan.target.label, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.Bold)
                    Text(
                        "${DcaFormat.targetKindLabel(plan.target.kind)} · ${DcaFormat.formatCentsUsd(plan.amountCents)} ${DcaFormat.frequencyLabel(plan.frequency, plan.dayOfWeek, plan.dayOfMonth).lowercase()}",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
                AssistChip(onClick = onOpen, label = { Text(DcaFormat.statusLabel(plan.status)) })
            }

            Spacer(Modifier.height(6.dp))
            Text(
                "Next buy: ${plan.nextRunTs?.let { DcaFormat.formatDate(it) } ?: "—"}",
                style = MaterialTheme.typography.bodyMedium,
            )
            Text(
                "Spent ${DcaFormat.formatCentsUsd(plan.spentCents)} · ${plan.buysCount} buys",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )

            DcaSchedule.budgetProgress(plan)?.let { p ->
                Spacer(Modifier.height(6.dp))
                LinearProgressIndicator(progress = { p }, modifier = Modifier.fillMaxWidth())
                Text(
                    "${DcaFormat.formatCentsUsd(plan.spentCents)} of ${DcaFormat.formatCentsUsd(plan.totalBudgetCents ?: 0L)} budget",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }

            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                TextButton(onClick = onOpen, modifier = Modifier.testTag("dca_open_${plan.planId}")) { Text("Details") }
                when (plan.status) {
                    DcaStatus.ACTIVE -> {
                        OutlinedButton(onClick = onPause, enabled = !acting) { Text("Pause") }
                        OutlinedButton(onClick = onCancel, enabled = !acting) { Text("Cancel") }
                    }
                    DcaStatus.PAUSED -> {
                        OutlinedButton(onClick = onResume, enabled = !acting) { Text("Resume") }
                        OutlinedButton(onClick = onCancel, enabled = !acting) { Text("Cancel") }
                    }
                    else -> Unit
                }
            }
        }
    }
}
