@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets.trade

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
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
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.ui.MarketColors

/** Route wrapper: the Active-Algos monitor (reached from More -> Studio). Up/Back pops the back stack. */
@Composable
fun ActiveAlgosRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: ActiveAlgosViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    ActiveAlgosScreen(
        state = state,
        onBack = onBack,
        onPause = viewModel::pause,
        onResume = viewModel::resume,
        onCancel = viewModel::cancel,
        onClearFinished = viewModel::clearFinished,
        modifier = modifier,
    )
}

@Composable
private fun ActiveAlgosScreen(
    state: ActiveAlgosUiState,
    onBack: () -> Unit,
    onPause: (String) -> Unit,
    onResume: (String) -> Unit,
    onCancel: (String) -> Unit,
    onClearFinished: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag("active_algos_screen"),
        containerColor = MarketColors.Bg,
        topBar = {
            TopAppBar(
                title = { Text("Active Algos", color = MarketColors.TextPrimary) },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MarketColors.Surface),
            )
        },
    ) { pad ->
        Column(Modifier.fillMaxSize().padding(pad).padding(horizontal = 12.dp)) {
            Spacer(Modifier.height(8.dp))
            Box(
                Modifier.fillMaxWidth()
                    .clip(RoundedCornerShape(8.dp))
                    .background(Color(0x1FF0B90B))
                    .border(1.dp, Color(0xFFF0B90B), RoundedCornerShape(8.dp))
                    .padding(10.dp),
            ) {
                Text(
                    "Client-side algos run only while the app is open. If the app is closed, running algos pause and can be resumed or cancelled here.",
                    color = Color(0xFFF0B90B),
                    fontSize = 11.sp,
                )
            }
            Spacer(Modifier.height(10.dp))

            if (state.hasFinished) {
                Text(
                    "Clear finished",
                    color = MarketColors.Accent,
                    fontWeight = FontWeight.Bold,
                    fontSize = 12.sp,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .clickable(onClick = onClearFinished)
                        .testTag("algos_clear_finished")
                        .padding(vertical = 4.dp),
                )
                Spacer(Modifier.height(6.dp))
            }

            if (state.algos.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text("No algos yet. Start a TWAP or Iceberg from the trade ticket.", color = MarketColors.TextFaint, fontSize = 13.sp)
                }
            } else {
                LazyColumn(contentPadding = PaddingValues(vertical = 4.dp)) {
                    items(state.algos, key = { it.id }) { algo ->
                        AlgoCard(algo, state.nowMs, onPause, onResume, onCancel)
                        Spacer(Modifier.height(10.dp))
                    }
                }
            }
        }
    }
}

@Composable
private fun AlgoCard(
    algo: AlgoOrder,
    nowMs: Long,
    onPause: (String) -> Unit,
    onResume: (String) -> Unit,
    onCancel: (String) -> Unit,
) {
    val sideColor = if (algo.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down
    Column(
        Modifier.fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(12.dp)
            .testTag("algo_card"),
    ) {
        Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(
                "${algo.kind.name} · ${if (algo.side == OrderSide.BUY) "Buy" else "Sell"} ${algo.symbolLabel}",
                color = sideColor, fontWeight = FontWeight.Bold, fontSize = 14.sp,
            )
            StatusPill(algo)
        }
        if (algo.paperMode) {
            Spacer(Modifier.height(2.dp))
            Text("PAPER", color = Color(0xFFF0B90B), fontSize = 10.sp, fontWeight = FontWeight.Bold)
        }
        Spacer(Modifier.height(8.dp))
        LinearProgressIndicator(
            progress = { algo.progress },
            modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)),
            color = MarketColors.Accent,
            trackColor = MarketColors.SurfaceAlt,
        )
        Spacer(Modifier.height(6.dp))
        InfoRow("Placed", "${algo.placedQty} / ${algo.totalQty}")
        InfoRow("Children", "${algo.childrenDone} / ${algo.childrenTotal}")
        when (algo.kind) {
            AlgoKind.TWAP -> InfoRow("Interval", "${algo.sliceIntervalMs / 1000}s")
            AlgoKind.ICEBERG -> InfoRow("Visible clip", algo.visibleQty.toString())
        }
        InfoRow("Price", algo.limitPrice?.toString() ?: "Market")
        if (algo.status == AlgoStatus.RUNNING) {
            val remaining = algo.nextFireAtMs?.let { ((it - nowMs).coerceAtLeast(0L) / 1000L) }
            InfoRow("Next child in", remaining?.let { "${it}s" } ?: "--")
        }
        algo.message?.let {
            Spacer(Modifier.height(4.dp))
            Text(it, color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        if (!algo.isTerminal) {
            Spacer(Modifier.height(10.dp))
            Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                if (algo.status == AlgoStatus.RUNNING) {
                    ActionButton("Pause", MarketColors.Border, "algo_pause", Modifier.weight(1f)) { onPause(algo.id) }
                } else {
                    ActionButton("Resume", MarketColors.Accent, "algo_resume", Modifier.weight(1f)) { onResume(algo.id) }
                }
                ActionButton("Cancel", MarketColors.Down, "algo_cancel", Modifier.weight(1f)) { onCancel(algo.id) }
            }
        }
    }
}

@Composable
private fun StatusPill(algo: AlgoOrder) {
    val (label, color) = when (algo.status) {
        AlgoStatus.RUNNING -> "Running" to MarketColors.Up
        AlgoStatus.PAUSED -> "Paused" to Color(0xFFF0B90B)
        AlgoStatus.DONE -> "Done" to MarketColors.TextSecondary
        AlgoStatus.CANCELLED -> "Cancelled" to MarketColors.Down
    }
    Text(
        label, color = color, fontSize = 11.sp, fontWeight = FontWeight.Bold,
        modifier = Modifier.clip(RoundedCornerShape(6.dp)).border(1.dp, color, RoundedCornerShape(6.dp)).padding(horizontal = 8.dp, vertical = 3.dp),
    )
}

@Composable
private fun InfoRow(label: String, value: String) {
    Row(Modifier.fillMaxWidth().padding(vertical = 1.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 12.sp)
        Text(value, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
    }
}

@Composable
private fun ActionButton(text: String, color: Color, tag: String, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .border(1.dp, color, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .testTag(tag)
            .padding(vertical = 9.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = color, fontWeight = FontWeight.Bold, fontSize = 12.sp)
    }
}
