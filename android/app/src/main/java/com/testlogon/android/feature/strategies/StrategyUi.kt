@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.strategies

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.strategies.RebalanceRule
import com.testlogon.android.data.strategies.RedemptionType
import com.testlogon.android.data.strategies.StrategyKind
import com.testlogon.android.data.strategies.StrategyStatus

/** Human label for a strategy lifecycle status. */
fun StrategyStatus.label(): String = when (this) {
    StrategyStatus.DRAFT -> "Draft"
    StrategyStatus.PAPER -> "Paper"
    StrategyStatus.PUBLISHED -> "Published"
    StrategyStatus.CLOSED -> "Closed"
    StrategyStatus.UNKNOWN -> "—"
}

fun StrategyKind.label(): String = when (this) {
    StrategyKind.BASKET -> "Basket"
    StrategyKind.RULE -> "Rule"
    StrategyKind.UNKNOWN -> "—"
}

fun RebalanceRule.label(): String = when (this) {
    RebalanceRule.NONE -> "No rebalance"
    RebalanceRule.DAILY -> "Daily"
    RebalanceRule.WEEKLY -> "Weekly"
    RebalanceRule.MONTHLY -> "Monthly"
    RebalanceRule.THRESHOLD -> "On threshold"
    RebalanceRule.UNKNOWN -> "—"
}

fun RedemptionType.label(): String = when (this) {
    RedemptionType.INSTANT -> "Instant (at NAV)"
    RedemptionType.NOTICE -> "Notice period"
    RedemptionType.UNKNOWN -> "—"
}

/**
 * A short human name for a symbol id, using the same catalogue the markets surface seeds
 * (1=BTCUSDC, 2=ETHUSDC, 3=SOLUSDC). Falls back to "#id" for anything else so a drifted/extra symbol
 * still renders honestly.
 */
fun symbolName(symbolId: Int): String = when (symbolId) {
    1 -> "BTCUSDC"
    2 -> "ETHUSDC"
    3 -> "SOLUSDC"
    else -> "#$symbolId"
}

/** A label/value row used across the strategy detail sections and confirm dialogs. */
@Composable
fun StrategyKeyValueRow(label: String, value: String, emphasize: Boolean = false) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp),
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1f),
        )
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = FontFamily.Monospace,
            fontWeight = if (emphasize) FontWeight.Bold else FontWeight.Normal,
            color = if (emphasize) MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurface,
        )
    }
}

/** A small pill that renders a status string. */
@Composable
fun StrategyStatusPill(text: String) {
    Surface(
        color = MaterialTheme.colorScheme.secondaryContainer,
        contentColor = MaterialTheme.colorScheme.onSecondaryContainer,
        shape = MaterialTheme.shapes.small,
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

/**
 * A minimal equity-curve sparkline drawn from a [curve] of levels (base ~1.0). Line-only, no axes;
 * used for the backtest / paper-run preview. Renders nothing meaningful for a <2-point curve.
 */
@Composable
fun EquitySparkline(
    curve: List<Double>,
    modifier: Modifier = Modifier,
    lineColor: Color = MaterialTheme.colorScheme.primary,
) {
    Canvas(modifier = modifier.fillMaxWidth().height(120.dp).padding(vertical = 8.dp)) {
        if (curve.size < 2) return@Canvas
        val min = curve.min()
        val max = curve.max()
        val range = (max - min).takeIf { it > 0.0 } ?: 1.0
        val w = size.width
        val h = size.height
        val dx = w / (curve.size - 1)
        val path = Path()
        curve.forEachIndexed { i, v ->
            val x = dx * i
            val y = h - ((v - min) / range).toFloat() * h
            if (i == 0) path.moveTo(x, y) else path.lineTo(x, y)
        }
        drawPath(path = path, color = lineColor, style = androidx.compose.ui.graphics.drawscope.Stroke(width = 4f))
        // Baseline marker at the first level.
        val baseY = h - ((curve.first() - min) / range).toFloat() * h
        drawLine(
            color = lineColor.copy(alpha = 0.25f),
            start = Offset(0f, baseY),
            end = Offset(w, baseY),
            strokeWidth = 2f,
        )
    }
}
