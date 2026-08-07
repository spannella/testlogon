@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets

import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.ErrorState
import com.testlogon.android.core.ui.state.LoadingState
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface
import kotlin.math.abs

/**
 * Markets (VIEW-ONLY) list route. Premium dark trading-terminal styling: token badges, sparklines,
 * mono prices, and a green/red % change pill. A row taps through to per-symbol detail.
 */
@Composable
fun MarketsRoute(
    onBack: () -> Unit,
    onOpenSymbol: (symbolId: Int) -> Unit,
    viewModel: MarketsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            MarketsHeader(onBack = onBack, count = state.rows.size)
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    MarketsUiState.Phase.Loading -> LoadingState(message = "Loading markets")
                    MarketsUiState.Phase.Empty -> EmptyState(
                        title = "No markets",
                        body = "No instruments are available right now.",
                    )
                    MarketsUiState.Phase.Error -> ErrorState(
                        message = state.errorMessage ?: "Something went wrong.",
                        onRetry = viewModel::onRetry,
                    )
                    MarketsUiState.Phase.Content -> MarketsList(
                        rows = state.rows,
                        onOpenSymbol = onOpenSymbol,
                    )
                }
            }
        }
    }
}

@Composable
private fun MarketsHeader(onBack: () -> Unit, count: Int) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 4.dp, end = 16.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = "Back",
                tint = MarketColors.TextPrimary,
            )
        }
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = "Markets",
                color = MarketColors.TextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 22.sp,
            )
            Text(
                text = if (count > 0) "$count instruments  LIVE" else "live",
                color = MarketColors.TextSecondary,
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun MarketsList(
    rows: List<MarketRow>,
    onOpenSymbol: (Int) -> Unit,
) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("markets_list"),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        items(rows, key = { it.instrument.symbolId }) { row ->
            MarketRowCard(row = row, onClick = { onOpenSymbol(row.instrument.symbolId) })
        }
    }
}

@Composable
private fun MarketRowCard(row: MarketRow, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("market_row_${row.instrument.symbolId}")
            .clip(RoundedCornerShape(14.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(14.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 12.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        val base = baseMonogram(row.instrument.symbol)
        TokenBadge(monogram = base, symbol = row.instrument.symbol)
        Spacer(Modifier.width(12.dp))
        Column(modifier = Modifier.width(88.dp)) {
            Text(
                text = row.instrument.symbol,
                color = MarketColors.TextPrimary,
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
                maxLines = 1,
            )
            Text(
                text = if (row.instrument.isPerpetual) "Perp" else "Spot",
                color = MarketColors.TextSecondary,
                fontSize = 11.sp,
            )
        }
        Spacer(Modifier.width(8.dp))
        Sparkline(
            points = row.spark,
            up = (row.changePct ?: 0.0) >= 0.0,
            modifier = Modifier.weight(1f).height(34.dp),
        )
        Spacer(Modifier.width(10.dp))
        Column(horizontalAlignment = Alignment.End) {
            Text(
                text = row.lastPrice?.let { formatPrice(it) } ?: "--",
                color = MarketColors.TextPrimary,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                fontSize = 15.sp,
            )
            Spacer(Modifier.height(4.dp))
            ChangePill(pct = row.changePct)
        }
    }
}

@Composable
private fun TokenBadge(monogram: String, symbol: String) {
    val (c1, c2) = badgeColors(symbol)
    Box(
        modifier = Modifier
            .size(40.dp)
            .clip(CircleShape)
            .background(Brush.linearGradient(listOf(c1, c2))),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = monogram,
            color = Color.White,
            fontWeight = FontWeight.Bold,
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
        )
    }
}

@Composable
private fun ChangePill(pct: Double?) {
    val value = pct ?: 0.0
    val up = value >= 0.0
    val bg = when {
        pct == null -> MarketColors.SurfaceAlt
        up -> MarketColors.UpPill
        else -> MarketColors.DownPill
    }
    val fg = when {
        pct == null -> MarketColors.TextSecondary
        up -> MarketColors.Up
        else -> MarketColors.Down
    }
    val label = if (pct == null) "--" else (if (up) "+" else "") + String.format("%.2f%%", value)
    Box(
        modifier = Modifier
            .width(72.dp)
            .clip(RoundedCornerShape(6.dp))
            .background(bg)
            .padding(vertical = 3.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = label,
            color = fg,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            fontSize = 12.sp,
        )
    }
}

@Composable
private fun Sparkline(points: List<Float>, up: Boolean, modifier: Modifier = Modifier) {
    val color = if (up) MarketColors.Up else MarketColors.Down
    Canvas(modifier = modifier) {
        val n = points.size
        if (n < 2) {
            // Flat faint baseline when no data yet.
            val y = size.height / 2f
            drawLine(MarketColors.Border, Offset(0f, y), Offset(size.width, y), strokeWidth = 1.5f)
            return@Canvas
        }
        val min = points.min()
        val max = points.max()
        val range = (max - min).let { if (it == 0f) 1f else it }
        val dx = size.width / (n - 1)
        fun px(i: Int) = dx * i
        fun py(v: Float) = size.height * (1f - (v - min) / range)
        val line = Path().apply {
            moveTo(px(0), py(points[0]))
            for (i in 1 until n) lineTo(px(i), py(points[i]))
        }
        val fill = Path().apply {
            addPath(line)
            lineTo(px(n - 1), size.height)
            lineTo(px(0), size.height)
            close()
        }
        drawPath(fill, Brush.verticalGradient(listOf(color.copy(alpha = 0.22f), Color.Transparent)))
        drawPath(line, color = color, style = Stroke(width = 2f, cap = StrokeCap.Round))
    }
}

/** Leading token symbol from the pair name (e.g. BTCUSDC -> BTC). */
private fun baseMonogram(symbol: String): String {
    val quotes = listOf("USDC", "USDT", "USD", "BTC", "ETH")
    for (q in quotes) if (symbol.length > q.length && symbol.endsWith(q)) return symbol.dropLast(q.length)
    return symbol.take(3)
}

/** Deterministic distinct gradient per symbol so each token reads as a distinct hue. */
private fun badgeColors(symbol: String): Pair<Color, Color> {
    // Canonical hues for well-known bases so each token reads distinctly; hash fallback otherwise.
    when (baseMonogram(symbol).uppercase()) {
        "BTC" -> return Color(0xFFF7931A) to Color(0xFFFFC062) // orange
        "ETH" -> return Color(0xFF627EEA) to Color(0xFF9AB0FF) // indigo
        "SOL" -> return Color(0xFF14F195) to Color(0xFF9945FF) // teal->purple
    }
    val palettes = listOf(
        Color(0xFFE84142) to Color(0xFFFF7A7B), // red
        Color(0xFF8247E5) to Color(0xFFB68CFF), // purple
        Color(0xFF00B4D8) to Color(0xFF62E0FF), // cyan
        Color(0xFFF0B90B) to Color(0xFFFFD65A), // gold
        Color(0xFF2775CA) to Color(0xFF6FA8FF), // blue
    )
    val h = abs(symbol.hashCode())
    return palettes[h % palettes.size]
}

/** Locale-agnostic grouped price format (no currency symbol; instruments are already quote-named). */
internal fun formatPrice(value: Double): String {
    val whole = value == value.toLong().toDouble()
    return if (whole) String.format("%,d", value.toLong()) else String.format("%,.2f", value)
}
