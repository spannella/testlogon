@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.blotter

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import kotlin.math.abs

/** Stable testTags for the Trading Blotter screen. */
object TradingBlotterTestTags {
    const val SCREEN = "trading_blotter_screen"
    const val TABS = "trading_blotter_tabs"
}

// Color-coding palette (kept local; parity with the web blotter's semantics).
private val BuyColor = Color(0xFF2E7D32)
private val SellColor = Color(0xFFC62828)
private val PosColor = Color(0xFF2E7D32)
private val NegColor = Color(0xFFC62828)

/** Route-level Trading Blotter entry (reached from the More → Studio hub). */
@Composable
fun TradingBlotterRoute(
    onBack: () -> Unit,
    modifier: Modifier = Modifier,
    viewModel: TradingBlotterViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    TradingBlotterScreen(
        state = state,
        onBack = onBack,
        onTabSelected = viewModel::onTabSelected,
        onSortColumn = viewModel::onSortColumn,
        modifier = modifier,
    )
}

@Composable
fun TradingBlotterScreen(
    state: BlotterUiState,
    onBack: () -> Unit,
    onTabSelected: (BlotterTab) -> Unit,
    onSortColumn: (BlotterSortColumn) -> Unit,
    modifier: Modifier = Modifier,
) {
    Scaffold(
        modifier = modifier.testTag(TradingBlotterTestTags.SCREEN),
        topBar = {
            TopAppBar(
                title = { Text("Trading Blotter") },
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
                .padding(padding),
        ) {
            BlotterTabRow(selected = state.tab, onTabSelected = onTabSelected)
            HorizontalDivider()
            when (state.tab) {
                BlotterTab.ORDERS -> OrdersTable(state, onSortColumn)
                BlotterTab.FILLS -> FillsTable(state, onSortColumn)
                BlotterTab.POSITIONS -> PositionsTable(state.positions)
            }
        }
    }
}

@Composable
private fun BlotterTabRow(
    selected: BlotterTab,
    onTabSelected: (BlotterTab) -> Unit,
) {
    val tabs = BlotterTab.entries
    SingleChoiceSegmentedButtonRow(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 8.dp)
            .testTag(TradingBlotterTestTags.TABS),
    ) {
        tabs.forEachIndexed { index, tab ->
            SegmentedButton(
                selected = selected == tab,
                onClick = { onTabSelected(tab) },
                shape = SegmentedButtonDefaults.itemShape(index = index, count = tabs.size),
                modifier = Modifier.testTag("trading_blotter_tab_${tab.name.lowercase()}"),
            ) {
                Text(tab.label)
            }
        }
    }
}

// ---- Dense table primitives -------------------------------------------------

/** A dense monospace value cell (already weighted by the caller via [modifier]). */
@Composable
private fun ValueCell(
    text: String,
    modifier: Modifier = Modifier,
    align: TextAlign = TextAlign.Start,
    color: Color = MaterialTheme.colorScheme.onSurface,
) {
    Text(
        text = text,
        modifier = modifier,
        color = color,
        fontSize = 12.sp,
        fontFamily = FontFamily.Monospace,
        textAlign = align,
        maxLines = 1,
        overflow = TextOverflow.Ellipsis,
    )
}

/** A tappable, sortable header cell that shows the sort arrow when it is the active column. */
@Composable
private fun RowScope.SortableHeader(
    label: String,
    weight: Float,
    column: BlotterSortColumn,
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
    align: TextAlign = TextAlign.Start,
) {
    val active = state.sortColumn == column
    Row(
        modifier = Modifier
            .weight(weight)
            .testTag("trading_blotter_header_${column.name.lowercase()}")
            .clickable { onSortColumn(column) },
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = if (align == TextAlign.End) Arrangement.End else Arrangement.Start,
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            fontWeight = FontWeight.SemiBold,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        if (active) {
            Icon(
                imageVector = if (state.sortDir == BlotterSortDir.ASC) {
                    Icons.Filled.ArrowUpward
                } else {
                    Icons.Filled.ArrowDownward
                },
                contentDescription = null,
                tint = MaterialTheme.colorScheme.primary,
                modifier = Modifier.padding(start = 2.dp),
            )
        }
    }
}

/** A non-sortable header cell (positions table). */
@Composable
private fun StaticHeader(
    label: String,
    modifier: Modifier = Modifier,
    align: TextAlign = TextAlign.Start,
) {
    Text(
        text = label,
        modifier = modifier,
        fontSize = 11.sp,
        fontWeight = FontWeight.SemiBold,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        textAlign = align,
    )
}

private fun sideColor(side: BlotterSide): Color = if (side == BlotterSide.BUY) BuyColor else SellColor

@Composable
private fun StatusBadge(status: BlotterStatus, modifier: Modifier = Modifier) {
    val fg = when (status) {
        BlotterStatus.LIVE -> Color(0xFF1565C0)
        BlotterStatus.PARTIAL -> Color(0xFFEF6C00)
        BlotterStatus.FILLED -> Color(0xFF2E7D32)
        BlotterStatus.CANCELLED -> Color(0xFF616161)
    }
    Surface(
        color = fg.copy(alpha = 0.16f),
        shape = MaterialTheme.shapes.small,
        modifier = modifier,
    ) {
        Text(
            text = status.label,
            color = fg,
            fontSize = 10.sp,
            fontWeight = FontWeight.SemiBold,
            fontFamily = FontFamily.Monospace,
            maxLines = 1,
            modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
        )
    }
}

private fun fmtPx(px: Double, sym: String): String =
    if (sym == "PMKT-2028") "%.4f".format(px) else "%,.2f".format(px)

private fun fmtQty(q: Double, sym: String): String =
    if (sym == "PMKT-2028") "%,.0f".format(q) else "%.3f".format(q)

private val rowDivider: Color
    @Composable get() = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f)

// ---- Orders -----------------------------------------------------------------

@Composable
private fun OrdersTable(
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
) {
    val divider = rowDivider
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            SortableHeader("Sym", 2.2f, BlotterSortColumn.SYM, state, onSortColumn)
            SortableHeader("Side", 1f, BlotterSortColumn.SIDE, state, onSortColumn)
            SortableHeader("Px", 2f, BlotterSortColumn.PX, state, onSortColumn, TextAlign.End)
            SortableHeader("Qty", 1.8f, BlotterSortColumn.QTY, state, onSortColumn, TextAlign.End)
            SortableHeader("Cum", 1.8f, BlotterSortColumn.CUM, state, onSortColumn, TextAlign.End)
            SortableHeader("Status", 2f, BlotterSortColumn.STATUS, state, onSortColumn)
        }
        HorizontalDivider()
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(state.orders, key = { it.clord }) { o ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    ValueCell(o.sym, Modifier.weight(2.2f))
                    ValueCell(o.side.code, Modifier.weight(1f), color = sideColor(o.side))
                    ValueCell(fmtPx(o.px, o.sym), Modifier.weight(2f), TextAlign.End)
                    ValueCell(fmtQty(o.qty, o.sym), Modifier.weight(1.8f), TextAlign.End)
                    ValueCell(fmtQty(o.cumQty, o.sym), Modifier.weight(1.8f), TextAlign.End)
                    Box(modifier = Modifier.weight(2f)) { StatusBadge(o.status) }
                }
                HorizontalDivider(color = divider)
            }
        }
    }
}

// ---- Fills ------------------------------------------------------------------

@Composable
private fun FillsTable(
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
) {
    val divider = rowDivider
    val fills = state.fills
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            SortableHeader("Sym", 2.2f, BlotterSortColumn.SYM, state, onSortColumn)
            SortableHeader("Side", 1f, BlotterSortColumn.SIDE, state, onSortColumn)
            SortableHeader("Px", 2f, BlotterSortColumn.PX, state, onSortColumn, TextAlign.End)
            SortableHeader("Qty", 1.8f, BlotterSortColumn.CUM, state, onSortColumn, TextAlign.End)
            SortableHeader("AvgPx", 2f, BlotterSortColumn.AVG_PX, state, onSortColumn, TextAlign.End)
            SortableHeader("Status", 2f, BlotterSortColumn.STATUS, state, onSortColumn)
        }
        HorizontalDivider()
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(fills, key = { it.clord }) { o ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    ValueCell(o.sym, Modifier.weight(2.2f))
                    ValueCell(o.side.code, Modifier.weight(1f), color = sideColor(o.side))
                    ValueCell(fmtPx(o.px, o.sym), Modifier.weight(2f), TextAlign.End)
                    ValueCell(fmtQty(o.cumQty, o.sym), Modifier.weight(1.8f), TextAlign.End)
                    ValueCell(fmtPx(o.avgPx, o.sym), Modifier.weight(2f), TextAlign.End)
                    Box(modifier = Modifier.weight(2f)) { StatusBadge(o.status) }
                }
                HorizontalDivider(color = divider)
            }
        }
    }
}

// ---- Positions --------------------------------------------------------------

@Composable
private fun PositionsTable(positions: List<BlotterPosition>) {
    val divider = rowDivider
    Column(modifier = Modifier.fillMaxSize()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            StaticHeader("Sym", Modifier.weight(2.2f))
            StaticHeader("Net", Modifier.weight(2f), TextAlign.End)
            StaticHeader("AvgCost", Modifier.weight(2.4f), TextAlign.End)
            StaticHeader("Mark", Modifier.weight(2.4f), TextAlign.End)
            StaticHeader("uPnL", Modifier.weight(2.4f), TextAlign.End)
        }
        HorizontalDivider()
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(positions, key = { it.sym }) { p ->
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 8.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    ValueCell(p.sym, Modifier.weight(2.2f))
                    ValueCell(
                        fmtQty(p.net, p.sym),
                        Modifier.weight(2f),
                        TextAlign.End,
                        color = if (p.net >= 0) PosColor else NegColor,
                    )
                    ValueCell(fmtPx(p.avgCost, p.sym), Modifier.weight(2.4f), TextAlign.End)
                    ValueCell(fmtPx(p.mark, p.sym), Modifier.weight(2.4f), TextAlign.End)
                    ValueCell(
                        (if (p.uPnl >= 0) "+" else "-") + "%,.2f".format(abs(p.uPnl)),
                        Modifier.weight(2.4f),
                        TextAlign.End,
                        color = if (p.uPnl >= 0) PosColor else NegColor,
                    )
                }
                HorizontalDivider(color = divider)
            }
        }
    }
}
