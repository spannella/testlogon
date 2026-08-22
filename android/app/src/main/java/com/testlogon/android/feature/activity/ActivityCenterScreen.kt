@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.activity

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.DoneAll
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * The consolidated ACTIVITY CENTER: a durable, filterable, day-grouped timeline of account events
 * (trades / funding / liquidations / risk / money / system), aggregated client-side from the shipped
 * exchange feeds. Distinct from transient toasts; degrades per-source on 404 with an honest empty
 * state. [onOpenRoute] deep-links a tapped event to the relevant screen.
 */
@Composable
fun ActivityCenterRoute(
    onBack: () -> Unit,
    onOpenRoute: (String) -> Unit = {},
    viewModel: ActivityCenterViewModel = hiltViewModel(),
) {
    val state by viewModel.state.collectAsStateWithLifecycle()
    val unread by viewModel.unreadCount.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            ActivityHeader(
                unread = unread,
                onBack = onBack,
                onMarkAllRead = viewModel::markAllRead,
                onRefresh = viewModel::refresh,
            )
            CategoryChips(selected = state.selected, onSelect = viewModel::selectCategory)
            if (state.degradedSources.isNotEmpty()) {
                Text(
                    "Some feeds unavailable: " + state.degradedSources.joinToString(", "),
                    color = MarketColors.TextSecondary,
                    fontSize = 11.sp,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp),
                )
            }
            Box(modifier = Modifier.fillMaxSize()) {
                when {
                    state.days.isEmpty() && state.loading -> EmptyState("Loading activity...", "")
                    state.days.isEmpty() && state.total == 0 -> EmptyState(
                        "No activity yet",
                        "Your fills, funding, liquidations, risk and market events will appear here.",
                    )
                    state.days.isEmpty() -> EmptyState("Nothing in this filter", "Try a different category.")
                    else -> LazyColumn(
                        modifier = Modifier.fillMaxSize().testTag("activity_center_list"),
                        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        state.days.forEach { day ->
                            item(key = "day-" + day.dayKey) { DayHeader(day.dayKey) }
                            items(count = day.events.size, key = { day.events[it].id }) { i ->
                                val e = day.events[i]
                                ActivityCard(
                                    event = e,
                                    lastSeen = false,
                                    onClick = { e.route?.let(onOpenRoute) },
                                )
                            }
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun ActivityHeader(
    unread: Int,
    onBack: () -> Unit,
    onMarkAllRead: () -> Unit,
    onRefresh: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 4.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
        }
        Column(modifier = Modifier.weight(1f)) {
            Text("Activity", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            Text(
                if (unread > 0) "$unread new" else "up to date",
                color = if (unread > 0) MarketColors.Accent else MarketColors.TextSecondary,
                fontSize = 12.sp,
            )
        }
        IconButton(onClick = onRefresh, modifier = Modifier.testTag("activity_refresh")) {
            Icon(Icons.Filled.Refresh, contentDescription = "Refresh", tint = MarketColors.TextSecondary)
        }
        IconButton(onClick = onMarkAllRead, modifier = Modifier.testTag("activity_mark_read")) {
            Icon(Icons.Filled.DoneAll, contentDescription = "Mark all read", tint = MarketColors.TextSecondary)
        }
    }
}

private data class ChipSpec(val label: String, val category: ActivityCategory?)

private val CHIPS = listOf(
    ChipSpec("All", null),
    ChipSpec("Trades", ActivityCategory.TRADE),
    ChipSpec("Funding", ActivityCategory.FUNDING),
    ChipSpec("Liquidations", ActivityCategory.LIQUIDATION),
    ChipSpec("Risk", ActivityCategory.RISK),
    ChipSpec("Money", ActivityCategory.MONEY),
    ChipSpec("System", ActivityCategory.SYSTEM),
)

@Composable
private fun CategoryChips(selected: ActivityCategory?, onSelect: (ActivityCategory?) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .horizontalScroll(rememberScrollState())
            .padding(horizontal = 12.dp, vertical = 4.dp),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        CHIPS.forEach { chip ->
            val active = chip.category == selected
            Text(
                chip.label,
                color = if (active) MarketColors.Bg else MarketColors.TextSecondary,
                fontSize = 12.sp,
                fontWeight = if (active) FontWeight.Bold else FontWeight.Normal,
                modifier = Modifier
                    .clip(RoundedCornerShape(16.dp))
                    .background(if (active) MarketColors.Accent else MarketColors.Surface)
                    .border(1.dp, MarketColors.Border, RoundedCornerShape(16.dp))
                    .clickable { onSelect(chip.category) }
                    .testTag("chip_" + (chip.category?.name ?: "ALL"))
                    .padding(horizontal = 14.dp, vertical = 7.dp),
            )
        }
    }
}

@Composable
private fun DayHeader(dayKey: Long) {
    Text(
        DAY_FMT.format(Date(dayKey)),
        color = MarketColors.TextSecondary,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        fontFamily = FontFamily.Monospace,
        modifier = Modifier.padding(start = 4.dp, top = 6.dp, bottom = 2.dp),
    )
}

@Composable
private fun ActivityCard(event: ActivityEvent, lastSeen: Boolean, onClick: () -> Unit) {
    val accent = severityColor(event.severity)
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(12.dp))
            .clickable(onClick = onClick)
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Box(modifier = Modifier.size(8.dp).clip(CircleShape).background(accent))
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    event.kind,
                    color = accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.width(8.dp))
                Text(
                    event.title,
                    color = MarketColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 14.sp,
                )
            }
            event.subtitle?.let {
                Spacer(Modifier.size(3.dp))
                Text(it, color = MarketColors.TextSecondary, fontSize = 13.sp)
            }
        }
    }
}

@Composable
private fun EmptyState(title: String, body: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Text(title, color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
        if (body.isNotEmpty()) {
            Spacer(Modifier.size(6.dp))
            Text(body, color = MarketColors.TextSecondary, fontSize = 13.sp)
        }
    }
}

private fun severityColor(severity: ActivitySeverity): Color = when (severity) {
    ActivitySeverity.SUCCESS -> MarketColors.Up
    ActivitySeverity.WARNING -> MarketColors.Accent
    ActivitySeverity.CRITICAL -> MarketColors.Down
    ActivitySeverity.INFO -> MarketColors.TextSecondary
}

private val DAY_FMT = SimpleDateFormat("EEE, MMM d yyyy", Locale.US)
