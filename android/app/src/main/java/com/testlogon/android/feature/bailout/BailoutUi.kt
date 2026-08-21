@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.bailout

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.bailout.BailoutStatus
import com.testlogon.android.data.bailout.HealthZone
import com.testlogon.android.data.bailout.PositionSide

fun PositionSide.label(): String = when (this) {
    PositionSide.LONG -> "LONG"
    PositionSide.SHORT -> "SHORT"
    PositionSide.UNKNOWN -> "—"
}

fun BailoutStatus.label(): String = when (this) {
    BailoutStatus.OPEN -> "Open"
    BailoutStatus.CLEARED -> "Cleared"
    BailoutStatus.CANCELLED -> "Cancelled"
    BailoutStatus.LIQUIDATED -> "Liquidated"
    BailoutStatus.UNKNOWN -> "—"
}

fun HealthZone.label(): String = when (this) {
    HealthZone.HEALTHY -> "Healthy"
    HealthZone.DISTRESS -> "Distress"
    HealthZone.LIQUIDATION -> "Liquidation"
}

/** Zone colour, independent of app theme (green safe / amber distress / red liquidation). */
val HealthZone.color: Color
    get() = when (this) {
        HealthZone.HEALTHY -> Color(0xFF2E7D32)
        HealthZone.DISTRESS -> Color(0xFFF9A825)
        HealthZone.LIQUIDATION -> Color(0xFFC62828)
    }

/** A label/value row used across the bailout sections and confirm dialogs. */
@Composable
fun BailoutKeyValueRow(label: String, value: String, emphasize: Boolean = false) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 3.dp)) {
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

@Composable
fun BailoutSectionCard(title: String, content: @Composable () -> Unit) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(Modifier.padding(16.dp)) {
            Text(title, style = MaterialTheme.typography.titleMedium, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(10.dp))
            content()
        }
    }
}

@Composable
fun BailoutStatusPill(text: String, tint: Color = MaterialTheme.colorScheme.secondaryContainer) {
    Surface(color = tint, shape = MaterialTheme.shapes.small) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelMedium,
            fontWeight = FontWeight.SemiBold,
            color = Color.White,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 2.dp),
        )
    }
}

/**
 * A 3-zone health meter: a horizontal bar with a HEALTHY / DISTRESS / LIQUIDATION gradient of fixed
 * proportions, a marker at the current buffer, and the volatility-scaled danger line. [bufferBps] is
 * the distance-to-liquidation (0 == at liq); [dangerBps] is where the distress band starts. The bar is
 * drawn 0..capBps left-to-right where 0 == liquidation (right-most danger) and capBps == safe.
 */
@Composable
fun HealthMeter(
    zone: HealthZone,
    bufferBps: Int,
    dangerBps: Int,
    capBps: Int = 5_000,
) {
    val cap = capBps.coerceAtLeast(1)
    val bufferFrac = (bufferBps.coerceIn(0, cap)).toFloat() / cap
    val dangerFrac = (dangerBps.coerceIn(0, cap)).toFloat() / cap

    Column(Modifier.fillMaxWidth()) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            BailoutStatusPill(zone.label(), tint = zone.color)
            Spacer(Modifier.width(8.dp))
            Text(
                "Buffer ${BailoutMath.formatBps(bufferBps)} · danger line ${BailoutMath.formatBps(dangerBps)}",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        Spacer(Modifier.height(8.dp))
        // The bar: left (0) = liquidation edge, right = safe. Distress zone spans 0..dangerFrac.
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .height(14.dp)
                .background(HealthZone.HEALTHY.color.copy(alpha = 0.25f), RoundedCornerShape(7.dp)),
        ) {
            // Distress band (from the liquidation edge up to the danger line).
            Box(
                modifier = Modifier
                    .fillMaxHeight()
                    .fillMaxWidth(dangerFrac)
                    .background(HealthZone.DISTRESS.color.copy(alpha = 0.5f), RoundedCornerShape(7.dp)),
            )
            // Current-buffer marker.
            Box(
                modifier = Modifier
                    .fillMaxWidth(bufferFrac)
                    .fillMaxHeight(),
            ) {
                Box(
                    modifier = Modifier
                        .align(Alignment.CenterEnd)
                        .width(3.dp)
                        .fillMaxHeight()
                        .background(zone.color),
                )
            }
        }
        Spacer(Modifier.height(4.dp))
        Row(modifier = Modifier.fillMaxWidth()) {
            Text("Liquidation", style = MaterialTheme.typography.labelSmall, color = HealthZone.LIQUIDATION.color)
            Spacer(Modifier.weight(1f))
            Text("Safe", style = MaterialTheme.typography.labelSmall, color = HealthZone.HEALTHY.color)
        }
    }
}

/** Compact holder id for rescuer / owner rows (keeps rows readable). */
fun shortSub(sub: String): String =
    if (sub.length <= 10) sub.ifBlank { "—" } else sub.take(6) + "…" + sub.takeLast(4)
