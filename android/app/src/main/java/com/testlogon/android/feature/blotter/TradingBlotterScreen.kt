@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.blotter

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.Clear
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Segment
import androidx.compose.material.icons.filled.ViewColumn
import androidx.compose.material3.Badge
import androidx.compose.material3.BadgedBox
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
    const val ACTION_FILTER = "trading_blotter_action_filter"
    const val ACTION_GROUP = "trading_blotter_action_group"
    const val ACTION_COLUMNS = "trading_blotter_action_columns"
    const val ACTION_CLEAR = "trading_blotter_action_clear"
    const val SEARCH = "trading_blotter_search"
    const val FILTER_SHEET = "trading_blotter_filter_sheet"
    const val COLUMNS_SHEET = "trading_blotter_columns_sheet"
    const val GROUP_SHEET = "trading_blotter_group_sheet"

    fun groupHeader(value: String): String = "trading_blotter_group_header_$value"
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
        onSearchChanged = viewModel::onSearchChanged,
        onSetFilters = viewModel::onSetFilters,
        onClearFilters = viewModel::onClearFilters,
        onToggleColumn = viewModel::onToggleColumn,
        onSetGroupBy = viewModel::onSetGroupBy,
        onToggleGroupCollapsed = viewModel::onToggleGroupCollapsed,
        modifier = modifier,
    )
}

@Composable
fun TradingBlotterScreen(
    state: BlotterUiState,
    onBack: () -> Unit,
    onTabSelected: (BlotterTab) -> Unit,
    onSortColumn: (BlotterSortColumn) -> Unit,
    onSearchChanged: (String) -> Unit,
    onSetFilters: (BlotterFilters) -> Unit,
    onClearFilters: () -> Unit,
    onToggleColumn: (BlotterColumn) -> Unit,
    onSetGroupBy: (BlotterGroupKey?) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    var showFilterSheet by remember { mutableStateOf(false) }
    var showColumnsSheet by remember { mutableStateOf(false) }
    var showGroupSheet by remember { mutableStateOf(false) }

    val tablesTab = state.tab == BlotterTab.ORDERS || state.tab == BlotterTab.FILLS

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
                actions = {
                    if (tablesTab) {
                        // Filter (with active-count badge).
                        IconButton(
                            onClick = { showFilterSheet = true },
                            modifier = Modifier.testTag(TradingBlotterTestTags.ACTION_FILTER),
                        ) {
                            BadgedBox(
                                badge = {
                                    val n = state.filters.activeCount
                                    if (n > 0) Badge { Text(n.toString()) }
                                },
                            ) {
                                Icon(Icons.Filled.FilterList, contentDescription = "Filter")
                            }
                        }
                        IconButton(
                            onClick = { showGroupSheet = true },
                            modifier = Modifier.testTag(TradingBlotterTestTags.ACTION_GROUP),
                        ) {
                            Icon(Icons.Filled.Segment, contentDescription = "Group")
                        }
                        IconButton(
                            onClick = { showColumnsSheet = true },
                            modifier = Modifier.testTag(TradingBlotterTestTags.ACTION_COLUMNS),
                        ) {
                            Icon(Icons.Filled.ViewColumn, contentDescription = "Columns")
                        }
                        if (state.filters.isActive) {
                            IconButton(
                                onClick = onClearFilters,
                                modifier = Modifier.testTag(TradingBlotterTestTags.ACTION_CLEAR),
                            ) {
                                Icon(Icons.Filled.Clear, contentDescription = "Clear filters")
                            }
                        }
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
            if (tablesTab) {
                SearchBar(query = state.filters.search, onSearchChanged = onSearchChanged)
            }
            HorizontalDivider()
            when (state.tab) {
                BlotterTab.ORDERS -> OrdersFillsTable(
                    rows = state.ordersRows,
                    state = state,
                    onSortColumn = onSortColumn,
                    onToggleGroupCollapsed = onToggleGroupCollapsed,
                    fillsMode = false,
                )
                BlotterTab.FILLS -> OrdersFillsTable(
                    rows = state.fillsRows,
                    state = state,
                    onSortColumn = onSortColumn,
                    onToggleGroupCollapsed = onToggleGroupCollapsed,
                    fillsMode = true,
                )
                BlotterTab.POSITIONS -> PositionsTable(state.positions)
            }
        }
    }

    if (showFilterSheet) {
        FilterSheet(
            state = state,
            onSetFilters = onSetFilters,
            onClearFilters = onClearFilters,
            onDismiss = { showFilterSheet = false },
        )
    }
    if (showColumnsSheet) {
        ColumnsSheet(
            state = state,
            onToggleColumn = onToggleColumn,
            onDismiss = { showColumnsSheet = false },
        )
    }
    if (showGroupSheet) {
        GroupSheet(
            selected = state.groupBy,
            onSetGroupBy = onSetGroupBy,
            onDismiss = { showGroupSheet = false },
        )
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

@Composable
private fun SearchBar(
    query: String,
    onSearchChanged: (String) -> Unit,
) {
    OutlinedTextField(
        value = query,
        onValueChange = onSearchChanged,
        singleLine = true,
        leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
        trailingIcon = {
            if (query.isNotEmpty()) {
                IconButton(onClick = { onSearchChanged("") }) {
                    Icon(Icons.Filled.Clear, contentDescription = "Clear search")
                }
            }
        },
        placeholder = { Text("Search sym / side / status / clord") },
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 4.dp)
            .testTag(TradingBlotterTestTags.SEARCH),
    )
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

/** The display value for a single Orders/Fills column of an order. */
private fun cellText(col: BlotterColumn, o: BlotterOrder, fillsMode: Boolean): String = when (col) {
    BlotterColumn.SYM -> o.sym
    BlotterColumn.SIDE -> o.side.code
    BlotterColumn.PX -> fmtPx(o.px, o.sym)
    // In Fills mode the "Qty" column shows executed quantity (cumQty) — matches legacy Fills table.
    BlotterColumn.QTY -> if (fillsMode) fmtQty(o.cumQty, o.sym) else fmtQty(o.qty, o.sym)
    BlotterColumn.CUM -> fmtQty(o.cumQty, o.sym)
    BlotterColumn.LEAVES -> fmtQty(o.leaves, o.sym)
    BlotterColumn.AVG_PX -> fmtPx(o.avgPx, o.sym)
    BlotterColumn.TIF -> o.tif.label
    BlotterColumn.STATUS -> o.status.label
    BlotterColumn.CLORD -> o.clord
}

/** The header label for a column (Fills relabels QTY to "Fill" for clarity). */
private fun headerLabel(col: BlotterColumn, fillsMode: Boolean): String =
    if (fillsMode && col == BlotterColumn.QTY) "Fill" else col.header

// ---- Orders / Fills (shared, column-descriptor driven) ----------------------

@Composable
private fun OrdersFillsTable(
    rows: List<BlotterRow>,
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    fillsMode: Boolean,
) {
    val divider = rowDivider
    val columns = state.visibleColumns
    Column(modifier = Modifier.fillMaxSize()) {
        // Header row — iterate visible descriptors.
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            columns.forEach { col ->
                val align = if (col.numeric) TextAlign.End else TextAlign.Start
                val sortable = col.sortColumn
                if (sortable != null) {
                    SortableHeader(
                        label = headerLabel(col, fillsMode),
                        weight = col.weight,
                        column = sortable,
                        state = state,
                        onSortColumn = onSortColumn,
                        align = align,
                    )
                } else {
                    StaticHeader(headerLabel(col, fillsMode), Modifier.weight(col.weight), align)
                }
            }
        }
        HorizontalDivider()
        LazyColumn(modifier = Modifier.fillMaxSize()) {
            items(
                items = rows,
                key = { row ->
                    when (row) {
                        is BlotterRow.Group -> "grp:${row.value}"
                        is BlotterRow.Item -> row.order.clord
                    }
                },
            ) { row ->
                when (row) {
                    is BlotterRow.Group -> GroupHeaderRow(row, onToggleGroupCollapsed)
                    is BlotterRow.Item -> {
                        OrderRow(row.order, columns, fillsMode)
                        HorizontalDivider(color = divider)
                    }
                }
            }
        }
    }
}

@Composable
private fun GroupHeaderRow(
    group: BlotterRow.Group,
    onToggleGroupCollapsed: (String) -> Unit,
) {
    Surface(color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .clickable { onToggleGroupCollapsed(group.value) }
                .testTag(TradingBlotterTestTags.groupHeader(group.value))
                .padding(horizontal = 12.dp, vertical = 8.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                imageVector = if (group.expanded) {
                    Icons.Filled.KeyboardArrowDown
                } else {
                    Icons.Filled.KeyboardArrowRight
                },
                contentDescription = if (group.expanded) "Collapse" else "Expand",
                tint = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Spacer(Modifier.width(4.dp))
            Text(
                text = group.value,
                fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                color = MaterialTheme.colorScheme.onSurface,
            )
            Spacer(Modifier.width(8.dp))
            Text(
                text = "(${group.count})",
                fontSize = 11.sp,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

@Composable
private fun OrderRow(
    o: BlotterOrder,
    columns: List<BlotterColumn>,
    fillsMode: Boolean,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        columns.forEach { col ->
            val align = if (col.numeric) TextAlign.End else TextAlign.Start
            when (col) {
                BlotterColumn.STATUS ->
                    Box(modifier = Modifier.weight(col.weight)) { StatusBadge(o.status) }
                BlotterColumn.SIDE ->
                    ValueCell(o.side.code, Modifier.weight(col.weight), color = sideColor(o.side))
                else ->
                    ValueCell(cellText(col, o, fillsMode), Modifier.weight(col.weight), align)
            }
        }
    }
}

// ---- Positions (fixed) ------------------------------------------------------

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

// ---- Columns sheet ----------------------------------------------------------

@Composable
private fun ColumnsSheet(
    state: BlotterUiState,
    onToggleColumn: (BlotterColumn) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(TradingBlotterTestTags.COLUMNS_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                "Columns",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            BlotterColumn.entries.forEach { col ->
                val visible = col !in state.hiddenColumns
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .clickable { onToggleColumn(col) }
                        .testTag("trading_blotter_column_toggle_${col.name.lowercase()}")
                        .padding(vertical = 4.dp),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = visible, onCheckedChange = { onToggleColumn(col) })
                    Spacer(Modifier.width(8.dp))
                    Text(col.header)
                }
            }
        }
    }
}

// ---- Group sheet ------------------------------------------------------------

@Composable
private fun GroupSheet(
    selected: BlotterGroupKey?,
    onSetGroupBy: (BlotterGroupKey?) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(TradingBlotterTestTags.GROUP_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                "Group by",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            GroupOption("None", selected == null, "none") {
                onSetGroupBy(null)
                onDismiss()
            }
            BlotterGroupKey.entries.forEach { key ->
                GroupOption(key.label, selected == key, key.name.lowercase()) {
                    onSetGroupBy(key)
                    onDismiss()
                }
            }
        }
    }
}

@Composable
private fun GroupOption(
    label: String,
    selected: Boolean,
    tagSuffix: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag("trading_blotter_group_option_$tagSuffix")
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
            color = if (selected) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurface
            },
        )
    }
}

// ---- Filter sheet -----------------------------------------------------------

@Composable
private fun FilterSheet(
    state: BlotterUiState,
    onSetFilters: (BlotterFilters) -> Unit,
    onClearFilters: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    // Local draft — applied on "Apply" so we set filters once (search is preserved from state).
    var draft by remember { mutableStateOf(state.filters) }
    var pxMinText by remember { mutableStateOf(state.filters.pxMin?.toString() ?: "") }
    var pxMaxText by remember { mutableStateOf(state.filters.pxMax?.toString() ?: "") }
    var qtyMinText by remember { mutableStateOf(state.filters.qtyMin?.toString() ?: "") }
    var qtyMaxText by remember { mutableStateOf(state.filters.qtyMax?.toString() ?: "") }

    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(TradingBlotterTestTags.FILTER_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .heightIn(max = 560.dp)
                .verticalScroll(rememberScrollState())
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                "Filters",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 8.dp),
            )

            FilterSectionLabel("Symbol")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                state.allSymbols.forEach { sym ->
                    FilterChip(
                        selected = sym in draft.symbols,
                        onClick = {
                            draft = draft.copy(symbols = toggle(draft.symbols, sym))
                        },
                        label = { Text(sym, fontFamily = FontFamily.Monospace) },
                        modifier = Modifier.testTag("trading_blotter_filter_sym_$sym"),
                    )
                }
            }

            FilterSectionLabel("Side")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                BlotterSide.entries.forEach { side ->
                    FilterChip(
                        selected = side in draft.sides,
                        onClick = { draft = draft.copy(sides = toggle(draft.sides, side)) },
                        label = { Text(if (side == BlotterSide.BUY) "Buy" else "Sell") },
                        modifier = Modifier.testTag("trading_blotter_filter_side_${side.name.lowercase()}"),
                    )
                }
            }

            FilterSectionLabel("Status")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                BlotterStatus.entries.forEach { st ->
                    FilterChip(
                        selected = st in draft.statuses,
                        onClick = { draft = draft.copy(statuses = toggle(draft.statuses, st)) },
                        label = { Text(st.label) },
                        modifier = Modifier.testTag("trading_blotter_filter_status_${st.name.lowercase()}"),
                    )
                }
            }

            FilterSectionLabel("TIF")
            FlowRow(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                BlotterTif.entries.forEach { tif ->
                    FilterChip(
                        selected = tif in draft.tifs,
                        onClick = { draft = draft.copy(tifs = toggle(draft.tifs, tif)) },
                        label = { Text(tif.label) },
                        modifier = Modifier.testTag("trading_blotter_filter_tif_${tif.name.lowercase()}"),
                    )
                }
            }

            FilterSectionLabel("Price range")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                RangeField("Min", pxMinText, { pxMinText = it }, Modifier.weight(1f), "trading_blotter_filter_pxmin")
                RangeField("Max", pxMaxText, { pxMaxText = it }, Modifier.weight(1f), "trading_blotter_filter_pxmax")
            }

            FilterSectionLabel("Quantity range")
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                RangeField("Min", qtyMinText, { qtyMinText = it }, Modifier.weight(1f), "trading_blotter_filter_qtymin")
                RangeField("Max", qtyMaxText, { qtyMaxText = it }, Modifier.weight(1f), "trading_blotter_filter_qtymax")
            }

            Spacer(Modifier.width(0.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(top = 16.dp),
                horizontalArrangement = Arrangement.End,
            ) {
                TextButton(
                    onClick = {
                        onClearFilters()
                        onDismiss()
                    },
                    modifier = Modifier.testTag("trading_blotter_filter_reset"),
                ) {
                    Text("Reset")
                }
                Spacer(Modifier.width(8.dp))
                TextButton(
                    onClick = {
                        onSetFilters(
                            draft.copy(
                                pxMin = pxMinText.toDoubleOrNull(),
                                pxMax = pxMaxText.toDoubleOrNull(),
                                qtyMin = qtyMinText.toDoubleOrNull(),
                                qtyMax = qtyMaxText.toDoubleOrNull(),
                            ),
                        )
                        onDismiss()
                    },
                    modifier = Modifier.testTag("trading_blotter_filter_apply"),
                ) {
                    Text("Apply")
                }
            }
        }
    }
}

@Composable
private fun FilterSectionLabel(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.labelMedium,
        color = MaterialTheme.colorScheme.onSurfaceVariant,
        modifier = Modifier.padding(top = 12.dp, bottom = 4.dp),
    )
}

@Composable
private fun RangeField(
    label: String,
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    tag: String,
) {
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        singleLine = true,
        label = { Text(label) },
        modifier = modifier.testTag(tag),
    )
}

private fun <T> toggle(set: Set<T>, value: T): Set<T> =
    if (value in set) set - value else set + value
