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
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Text
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Notifications
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Star
import androidx.compose.material.icons.filled.StarBorder
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
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
    onOpenAlerts: () -> Unit = {},
    onOpenSearch: () -> Unit = {},
    viewModel: MarketsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val unreadAlerts by viewModel.unreadAlerts.collectAsStateWithLifecycle()
    val autoOpenSymbolId by viewModel.autoOpenSymbolId.collectAsStateWithLifecycle()
    // One-shot: when a saved default market resolves to a loaded symbol, open its detail once per
    // process via the same nav lambda used for row taps, then clear it so the list stays reachable.
    LaunchedEffect(autoOpenSymbolId) {
        autoOpenSymbolId?.let { id ->
            viewModel.consumeAutoOpen()
            onOpenSymbol(id)
        }
    }
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            MarketsHeader(
                onBack = onBack,
                count = state.rows.size,
                unreadAlerts = unreadAlerts,
                onOpenAlerts = onOpenAlerts,
                onOpenSearch = onOpenSearch,
            )
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
                        favorites = state.favorites,
                        onOpenSymbol = onOpenSymbol,
                        onToggleFavorite = viewModel::toggleFavorite,
                    )
                }
            }
        }
    }
}

@Composable
private fun MarketsHeader(
    onBack: () -> Unit,
    count: Int,
    unreadAlerts: Int = 0,
    onOpenAlerts: () -> Unit = {},
    onOpenSearch: () -> Unit = {},
) {
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
        IconButton(onClick = onOpenSearch, modifier = Modifier.testTag("markets_search")) {
            Icon(
                Icons.Filled.Search,
                contentDescription = "Search",
                tint = MarketColors.TextPrimary,
            )
        }
        IconButton(onClick = onOpenAlerts, modifier = Modifier.testTag("markets_alerts_bell")) {
            BadgedBox(
                badge = {
                    if (unreadAlerts > 0) {
                        Badge(containerColor = MarketColors.Down, contentColor = MarketColors.TextPrimary) {
                            Text(if (unreadAlerts > 99) "99+" else unreadAlerts.toString(), fontSize = 9.sp)
                        }
                    }
                },
            ) {
                Icon(
                    Icons.Filled.Notifications,
                    contentDescription = "Trading alerts",
                    tint = MarketColors.TextPrimary,
                )
            }
        }
    }
}

/** Which slice of the market list is shown: everything, or just the starred watchlist. */
private enum class MarketsFilter { All, Watchlist }

@Composable
private fun MarketsList(
    rows: List<MarketRow>,
    favorites: Set<Int>,
    onOpenSymbol: (Int) -> Unit,
    onToggleFavorite: (Int) -> Unit,
) {
    var query by remember { mutableStateOf("") }
    var filter by remember { mutableStateOf(MarketsFilter.All) }
    // Apply the watchlist tab, then the search text, then float starred instruments to the top
    // (stable within each group so the starred order is deterministic across quote ticks).
    val displayed = remember(rows, favorites, query, filter) {
        rows.filter { filter == MarketsFilter.All || favorites.contains(it.instrument.symbolId) }
            .filter { query.isBlank() || it.instrument.symbol.contains(query.trim(), ignoreCase = true) }
            .sortedByDescending { favorites.contains(it.instrument.symbolId) }
    }
    Column(modifier = Modifier.fillMaxSize()) {
        MarketSearchField(query = query, onQuery = { query = it })
        MarketsFilterTabs(
            filter = filter,
            allCount = rows.size,
            watchCount = favorites.size,
            onSelect = { filter = it },
        )
        if (displayed.isEmpty()) {
            MarketsEmpty(filter = filter, query = query)
            return@Column
        }
        LazyColumn(
            modifier = Modifier.fillMaxSize().testTag("markets_list"),
            contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            items(displayed, key = { it.instrument.symbolId }) { row ->
                MarketRowCard(
                    row = row,
                    favorite = favorites.contains(row.instrument.symbolId),
                    onClick = { onOpenSymbol(row.instrument.symbolId) },
                    onToggleFavorite = { onToggleFavorite(row.instrument.symbolId) },
                )
            }
        }
    }
}

@Composable
private fun MarketsFilterTabs(
    filter: MarketsFilter,
    allCount: Int,
    watchCount: Int,
    onSelect: (MarketsFilter) -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .testTag("markets_filter_tabs"),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        MarketFilterChip(
            label = "All",
            count = allCount,
            selected = filter == MarketsFilter.All,
            onClick = { onSelect(MarketsFilter.All) },
            tag = "filter_all",
        )
        MarketFilterChip(
            label = "Watchlist",
            count = watchCount,
            selected = filter == MarketsFilter.Watchlist,
            onClick = { onSelect(MarketsFilter.Watchlist) },
            tag = "filter_watchlist",
        )
    }
}

@Composable
private fun MarketFilterChip(
    label: String,
    count: Int,
    selected: Boolean,
    onClick: () -> Unit,
    tag: String,
) {
    val bg = if (selected) MarketColors.Accent.copy(alpha = 0.16f) else MarketColors.Surface
    val border = if (selected) MarketColors.Accent else MarketColors.Border
    val fg = if (selected) MarketColors.Accent else MarketColors.TextSecondary
    Row(
        modifier = Modifier
            .clip(RoundedCornerShape(999.dp))
            .background(bg)
            .border(1.dp, border, RoundedCornerShape(999.dp))
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 7.dp)
            .testTag(tag),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        if (label == "Watchlist") {
            Icon(
                Icons.Filled.Star,
                contentDescription = null,
                tint = fg,
                modifier = Modifier.size(14.dp),
            )
            Spacer(Modifier.width(5.dp))
        }
        Text(text = label, color = fg, fontSize = 13.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.width(5.dp))
        Text(text = count.toString(), color = fg.copy(alpha = 0.7f), fontSize = 12.sp)
    }
}

@Composable
private fun MarketsEmpty(filter: MarketsFilter, query: String) {
    Box(modifier = Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
        val text = when {
            query.isNotBlank() -> "No markets match \"$query\"."
            filter == MarketsFilter.Watchlist ->
                "Your watchlist is empty. Tap the star on any market to add it."
            else -> "No markets available."
        }
        Column(horizontalAlignment = Alignment.CenterHorizontally, modifier = Modifier.padding(24.dp)) {
            if (filter == MarketsFilter.Watchlist && query.isBlank()) {
                Icon(
                    Icons.Filled.StarBorder,
                    contentDescription = null,
                    tint = MarketColors.TextFaint,
                    modifier = Modifier.size(40.dp),
                )
                Spacer(Modifier.height(10.dp))
            }
            Text(
                text = text,
                color = MarketColors.TextSecondary,
                fontSize = 13.sp,
                textAlign = TextAlign.Center,
                modifier = Modifier.testTag("markets_empty"),
            )
        }
    }
}

@Composable
private fun MarketSearchField(query: String, onQuery: (String) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(horizontal = 12.dp, vertical = 10.dp)
            .testTag("markets_search"),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(Icons.Filled.Search, contentDescription = null, tint = MarketColors.TextSecondary, modifier = Modifier.size(18.dp))
        Spacer(Modifier.width(8.dp))
        Box(modifier = Modifier.weight(1f)) {
            if (query.isEmpty()) {
                Text("Search markets", color = MarketColors.TextFaint, fontSize = 14.sp)
            }
            BasicTextField(
                value = query,
                onValueChange = onQuery,
                singleLine = true,
                textStyle = TextStyle(color = MarketColors.TextPrimary, fontSize = 14.sp),
                cursorBrush = SolidColor(MarketColors.Accent),
                modifier = Modifier.fillMaxWidth(),
            )
        }
        if (query.isNotEmpty()) {
            Icon(
                Icons.Filled.Close,
                contentDescription = "Clear",
                tint = MarketColors.TextSecondary,
                modifier = Modifier.size(18.dp).clickable { onQuery("") },
            )
        }
    }
}

@Composable
private fun MarketRowCard(
    row: MarketRow,
    favorite: Boolean,
    onClick: () -> Unit,
    onToggleFavorite: () -> Unit,
) {
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
        Spacer(Modifier.width(4.dp))
        Icon(
            imageVector = if (favorite) Icons.Filled.Star else Icons.Filled.StarBorder,
            contentDescription = if (favorite) "Remove from watchlist" else "Add to watchlist",
            tint = if (favorite) MarketColors.Accent else MarketColors.TextFaint,
            modifier = Modifier
                .size(24.dp)
                .clip(CircleShape)
                .clickable(onClick = onToggleFavorite)
                .testTag("fav_${row.instrument.symbolId}")
                .padding(2.dp),
        )
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
