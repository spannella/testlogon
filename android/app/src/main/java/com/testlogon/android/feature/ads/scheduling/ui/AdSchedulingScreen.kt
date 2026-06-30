@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.ads.scheduling.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.AssistChip
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.model.syndicates.formatCents
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState

/** Stable testTags for the ad scheduling editor. */
object AdSchedulingTestTags {
    const val SCREEN = "ad_scheduling_screen"
    const val GRID = "ad_scheduling_grid"
    const val EMPTY = "ad_scheduling_empty"
    const val ERROR_RETRY = "ad_scheduling_error_retry"
    const val TIMEZONE = "ad_scheduling_timezone"
    const val SAVE = "ad_scheduling_save"

    fun cell(day: String, hour: Int): String = "ad_sched_cell_${day}_$hour"
}

@Composable
fun AdSchedulingRoute(
    onBack: () -> Unit,
    viewModel: AdSchedulingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    AdSchedulingScreen(
        state = state,
        onBack = onBack,
        onRetry = viewModel::onRetry,
        onToggleHour = viewModel::toggleHour,
        onToggleDay = viewModel::toggleDay,
        onApplyTemplate = viewModel::applyTemplate,
        onTimezone = viewModel::setTimezone,
        onSave = viewModel::save,
    )
}

@Composable
fun AdSchedulingScreen(
    state: AdSchedulingUiState,
    onBack: () -> Unit,
    onRetry: () -> Unit,
    onToggleHour: (String, Int) -> Unit,
    onToggleDay: (String) -> Unit,
    onApplyTemplate: (String) -> Unit,
    onTimezone: (String) -> Unit,
    onSave: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(AdSchedulingTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Ad scheduling") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back")
                    }
                },
            )
        },
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            when (state) {
                is AdSchedulingUiState.Loading -> LoadingState()
                is AdSchedulingUiState.NoCampaign -> EmptyState(
                    title = "No campaign to schedule",
                    body = "Create an ad account and a campaign first, then set up dayparting.",
                    modifier = Modifier.testTag(AdSchedulingTestTags.EMPTY),
                )
                is AdSchedulingUiState.Error -> ErrorState(
                    message = state.error.message,
                    onRetry = onRetry,
                    modifier = Modifier.testTag(AdSchedulingTestTags.ERROR_RETRY),
                )
                is AdSchedulingUiState.Content -> ScheduleContent(
                    state, onToggleHour, onToggleDay, onApplyTemplate, onTimezone, onSave,
                )
            }
        }
    }
}

@Composable
private fun ScheduleContent(
    state: AdSchedulingUiState.Content,
    onToggleHour: (String, Int) -> Unit,
    onToggleDay: (String) -> Unit,
    onApplyTemplate: (String) -> Unit,
    onTimezone: (String) -> Unit,
    onSave: () -> Unit,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Text("Campaign: ${state.campaignName}", style = MaterialTheme.typography.titleMedium)

        SummaryRow(state)

        OutlinedTextField(
            value = state.timezone,
            onValueChange = onTimezone,
            label = { Text("Timezone (IANA, e.g. America/New_York)") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag(AdSchedulingTestTags.TIMEZONE),
        )

        if (state.templateNames.isNotEmpty()) {
            Column(verticalArrangement = Arrangement.spacedBy(4.dp)) {
                Text("Templates", style = MaterialTheme.typography.titleSmall)
                FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    state.templateNames.forEach { name ->
                        AssistChip(onClick = { onApplyTemplate(name) }, label = { Text(name) })
                    }
                }
            }
        }

        Text("Dayparting (hour of day, ${state.timezone})", style = MaterialTheme.typography.titleSmall)
        DaypartingGrid(state, onToggleHour, onToggleDay)

        if (state.flights.isNotEmpty()) {
            Text("Flights", style = MaterialTheme.typography.titleSmall)
            state.flights.forEach { flight ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(2.dp)) {
                        Text(flight.name, style = MaterialTheme.typography.titleSmall)
                        Text(
                            "${flight.startDate} -> ${flight.endDate}  ·  ${formatCents(flight.dailyBudgetCents)}/day",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                        )
                    }
                }
            }
        }

        if (state.actionError != null) {
            Text(state.actionError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodyMedium)
        }
        if (state.saved) {
            Text("Schedule saved.", color = MaterialTheme.colorScheme.primary, style = MaterialTheme.typography.bodyMedium)
        }

        Button(
            onClick = onSave,
            enabled = !state.saving,
            modifier = Modifier.fillMaxWidth().testTag(AdSchedulingTestTags.SAVE),
        ) {
            if (state.saving) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            } else {
                Text("Save schedule")
            }
        }
    }
}

@Composable
private fun SummaryRow(state: AdSchedulingUiState.Content) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth().padding(16.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
        ) {
            Column {
                Text("Eligible now", style = MaterialTheme.typography.labelMedium)
                Text(
                    when (state.eligibleNow) {
                        true -> "Yes"
                        false -> "No"
                        null -> "—"
                    },
                    style = MaterialTheme.typography.titleMedium,
                )
            }
            Column(horizontalAlignment = Alignment.End) {
                Text("Hourly budget", style = MaterialTheme.typography.labelMedium)
                Text(
                    state.hourlyBudgetCents?.let { formatCents(it) } ?: "—",
                    style = MaterialTheme.typography.titleMedium,
                )
            }
        }
    }
}

@Composable
private fun DaypartingGrid(
    state: AdSchedulingUiState.Content,
    onToggleHour: (String, Int) -> Unit,
    onToggleDay: (String) -> Unit,
) {
    Column(
        modifier = Modifier
            .horizontalScroll(rememberScrollState())
            .testTag(AdSchedulingTestTags.GRID),
    ) {
        // Header row: hour labels.
        Row {
            Box(modifier = Modifier.width(44.dp))
            (0..23).forEach { hour ->
                Box(
                    modifier = Modifier.size(width = 22.dp, height = 18.dp),
                    contentAlignment = Alignment.Center,
                ) {
                    Text(
                        text = hour.toString(),
                        fontSize = 8.sp,
                        textAlign = TextAlign.Center,
                    )
                }
            }
        }
        DAY_ORDER.forEach { day ->
            val active = state.schedule[day].orEmpty()
            Row(verticalAlignment = Alignment.CenterVertically) {
                TextButton(
                    onClick = { onToggleDay(day) },
                    modifier = Modifier.width(44.dp),
                ) {
                    Text(day.take(3).replaceFirstChar { it.uppercase() }, fontSize = 9.sp)
                }
                (0..23).forEach { hour ->
                    val on = hour in active
                    Box(
                        modifier = Modifier
                            .padding(1.dp)
                            .size(20.dp)
                            .clip(RoundedCornerShape(3.dp))
                            .background(
                                if (on) MaterialTheme.colorScheme.primary
                                else MaterialTheme.colorScheme.surfaceVariant,
                            )
                            .clickable { onToggleHour(day, hour) }
                            .testTag(AdSchedulingTestTags.cell(day, hour)),
                    )
                }
            }
        }
    }
}
