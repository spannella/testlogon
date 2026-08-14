@file:OptIn(ExperimentalMaterial3Api::class, ExperimentalLayoutApi::class)

package com.testlogon.android.feature.blotter

import androidx.compose.foundation.clickable
import androidx.compose.foundation.background
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.gestures.detectDragGestures
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ExperimentalLayoutApi
import androidx.compose.foundation.layout.FlowRow
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
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
import androidx.compose.material.icons.filled.DragHandle
import androidx.compose.material.icons.filled.FilterList
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowRight
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.Share
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
import androidx.compose.material3.SwipeToDismissBox
import androidx.compose.material3.SwipeToDismissBoxValue
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.VerticalDivider
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.material3.rememberSwipeToDismissBoxState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableFloatStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
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
    const val ACTION_EXPORT = "trading_blotter_action_export"
    const val CONTENT = "trading_blotter_content"
    const val PANE_ORDERS = "trading_blotter_pane_orders"
    const val PANE_POSITIONS = "trading_blotter_pane_positions"
    const val SEARCH = "trading_blotter_search"
    const val FILTER_SHEET = "trading_blotter_filter_sheet"
    const val COLUMNS_SHEET = "trading_blotter_columns_sheet"
    const val GROUP_SHEET = "trading_blotter_group_sheet"
    const val EXPORT_SHEET = "trading_blotter_export_sheet"
    const val EXPORT_CSV = "trading_blotter_export_csv"
    const val EXPORT_TSV = "trading_blotter_export_tsv"

    fun groupHeader(value: String): String = "trading_blotter_group_header_$value"

    const val ROW_SWIPE = "trading_blotter_row_swipe"
    const val CANCEL_BG = "trading_blotter_cancel_bg"
    const val CONTEXT_SHEET = "trading_blotter_context_sheet"
    const val CONTEXT_CANCEL = "trading_blotter_context_cancel"

    fun orderRow(clord: String): String = "trading_blotter_row_$clord"

    fun contextCancel(clord: String): String = "trading_blotter_context_cancel_$clord"

    fun rowDetail(clord: String): String = "trading_blotter_row_detail_$clord"

    fun rowDetailField(clord: String, key: String): String =
        "trading_blotter_row_detail_field_${clord}_$key"
}

// Minimum content width at which the adaptive two-pane (Orders on the left, Positions on the right) layout engages.
private val WidePaneMinWidth = 600.dp

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
        onReorderColumn = viewModel::onReorderColumn,
        onSetGroupBy = viewModel::onSetGroupBy,
        onToggleGroupCollapsed = viewModel::onToggleGroupCollapsed,
        onToggleRowExpanded = viewModel::onToggleRowExpanded,
        onCancelOrder = viewModel::onCancelOrder,
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
    onReorderColumn: (Int, Int) -> Unit,
    onSetGroupBy: (BlotterGroupKey?) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    onToggleRowExpanded: (String) -> Unit,
    onCancelOrder: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val context = LocalContext.current
    var showFilterSheet by remember { mutableStateOf(false) }
    var showColumnsSheet by remember { mutableStateOf(false) }
    var showGroupSheet by remember { mutableStateOf(false) }
    var showExportSheet by remember { mutableStateOf(false) }
    var contextMenuOrder by remember { mutableStateOf<BlotterOrder?>(null) }
    // Adaptive-layout flag: true on wide widths where the two-pane layout is shown. Set from inside
    // the content BoxWithConstraints below; hoisted here so the TopAppBar actions can read it.
    var isWide by remember { mutableStateOf(false) }

    val tablesTab = state.tab == BlotterTab.ORDERS || state.tab == BlotterTab.FILLS
    // Toolbar actions apply to a table view: the Orders/Fills tab in compact, always in wide.
    val showTableActions = tablesTab || isWide

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
                    if (showTableActions) {
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
                        IconButton(
                            onClick = { showExportSheet = true },
                            modifier = Modifier.testTag(TradingBlotterTestTags.ACTION_EXPORT),
                        ) {
                            Icon(Icons.Filled.Share, contentDescription = "Export")
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
        BoxWithConstraints(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .testTag(TradingBlotterTestTags.CONTENT),
        ) {
            val wide = maxWidth >= WidePaneMinWidth
            // Publish the width decision up to the TopAppBar actions gate without a second measure.
            SideEffect { if (isWide != wide) isWide = wide }
            if (wide) {
                WidePane(
                    state = state,
                    onSortColumn = onSortColumn,
                    onSearchChanged = onSearchChanged,
                    onToggleGroupCollapsed = onToggleGroupCollapsed,
                    onToggleRowExpanded = onToggleRowExpanded,
                    onCancelOrder = onCancelOrder,
                    onLongPressOrder = { contextMenuOrder = it },
                )
            } else {
                CompactPane(
                    state = state,
                    onTabSelected = onTabSelected,
                    onSortColumn = onSortColumn,
                    onSearchChanged = onSearchChanged,
                    onToggleGroupCollapsed = onToggleGroupCollapsed,
                    onToggleRowExpanded = onToggleRowExpanded,
                    onCancelOrder = onCancelOrder,
                    onLongPressOrder = { contextMenuOrder = it },
                )
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
            onReorderColumn = onReorderColumn,
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
    if (showExportSheet) {
        val fillsMode = state.tab == BlotterTab.FILLS
        ExportSheet(
            rowCount = exportRows(state, fillsMode).size,
            columnCount = state.visibleColumns.size,
            onExport = { tsv ->
                val text = formatDelimited(
                    orders = exportRows(state, fillsMode),
                    columns = state.visibleColumns,
                    fillsMode = fillsMode,
                    delimiter = if (tsv) '\t' else ',',
                )
                shareBlotterExport(
                    context = context,
                    content = text,
                    baseName = "blotter_" + state.tab.name.lowercase(),
                    tsv = tsv,
                )
                showExportSheet = false
            },
            onDismiss = { showExportSheet = false },
        )
    }

    contextMenuOrder?.let { order ->
        OrderActionsSheet(
            order = order,
            onCancel = {
                onCancelOrder(order.clord)
                contextMenuOrder = null
            },
            onDismiss = { contextMenuOrder = null },
        )
    }
}

// ---- Adaptive panes ---------------------------------------------------------

// Compact layout (narrow widths): the tab switcher plus the single active table, unchanged.
@Composable
private fun CompactPane(
    state: BlotterUiState,
    onTabSelected: (BlotterTab) -> Unit,
    onSortColumn: (BlotterSortColumn) -> Unit,
    onSearchChanged: (String) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    onToggleRowExpanded: (String) -> Unit,
    onCancelOrder: (String) -> Unit,
    onLongPressOrder: (BlotterOrder) -> Unit,
) {
    val tablesTab = state.tab == BlotterTab.ORDERS || state.tab == BlotterTab.FILLS
    Column(modifier = Modifier.fillMaxSize()) {
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
                onToggleRowExpanded = onToggleRowExpanded,
                onCancelOrder = onCancelOrder,
                onLongPressOrder = onLongPressOrder,
                fillsMode = false,
            )
            BlotterTab.FILLS -> OrdersFillsTable(
                rows = state.fillsRows,
                state = state,
                onSortColumn = onSortColumn,
                onToggleGroupCollapsed = onToggleGroupCollapsed,
                onToggleRowExpanded = onToggleRowExpanded,
                onCancelOrder = onCancelOrder,
                onLongPressOrder = onLongPressOrder,
                fillsMode = true,
            )
            BlotterTab.POSITIONS -> PositionsTable(state.positions)
        }
    }
}

// Wide layout (>= WidePaneMinWidth): Orders on the left, Positions on the right, side by side.
// Reuses the same derived state and table composables as compact, so sort/filter/group/columns and
// the 1s ticker apply identically. Toolbar filter/group/columns/export actions drive the LEFT Orders
// pane via state.ordersRows.
@Composable
private fun WidePane(
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
    onSearchChanged: (String) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    onToggleRowExpanded: (String) -> Unit,
    onCancelOrder: (String) -> Unit,
    onLongPressOrder: (BlotterOrder) -> Unit,
) {
    Row(modifier = Modifier.fillMaxSize()) {
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight()
                .testTag(TradingBlotterTestTags.PANE_ORDERS),
        ) {
            PaneTitle("Orders")
            SearchBar(query = state.filters.search, onSearchChanged = onSearchChanged)
            HorizontalDivider()
            OrdersFillsTable(
                rows = state.ordersRows,
                state = state,
                onSortColumn = onSortColumn,
                onToggleGroupCollapsed = onToggleGroupCollapsed,
                onToggleRowExpanded = onToggleRowExpanded,
                onCancelOrder = onCancelOrder,
                onLongPressOrder = onLongPressOrder,
                fillsMode = false,
            )
        }
        VerticalDivider()
        Column(
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight()
                .testTag(TradingBlotterTestTags.PANE_POSITIONS),
        ) {
            PaneTitle("Positions")
            HorizontalDivider()
            PositionsTable(state.positions)
        }
    }
}

// A small self-identifying title label at the top of a pane in the wide layout.
@Composable
private fun PaneTitle(text: String) {
    Text(
        text = text,
        style = MaterialTheme.typography.titleSmall,
        color = MaterialTheme.colorScheme.onSurface,
        modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
    )
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
internal fun cellText(col: BlotterColumn, o: BlotterOrder, fillsMode: Boolean): String = when (col) {
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
internal fun headerLabel(col: BlotterColumn, fillsMode: Boolean): String =
    if (fillsMode && col == BlotterColumn.QTY) "Fill" else col.header

// ---- Orders / Fills (shared, column-descriptor driven) ----------------------

@Composable
private fun OrdersFillsTable(
    rows: List<BlotterRow>,
    state: BlotterUiState,
    onSortColumn: (BlotterSortColumn) -> Unit,
    onToggleGroupCollapsed: (String) -> Unit,
    onToggleRowExpanded: (String) -> Unit,
    onCancelOrder: (String) -> Unit,
    onLongPressOrder: (BlotterOrder) -> Unit,
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
                        val o = row.order
                        val expanded = o.clord in state.expandedRows
                        val working = o.status.isCancelable()
                        // Build the box state fresh per clord; confirmValueChange fires the cancel
                        // mutation but returns false so the row snaps back (the recomposed CANCELLED
                        // row then has swipe disabled) — the item is never removed from the list.
                        val boxState = rememberSwipeToDismissBoxState(
                            confirmValueChange = { v ->
                                if (v == SwipeToDismissBoxValue.EndToStart && o.status.isCancelable()) {
                                    onCancelOrder(o.clord)
                                }
                                false
                            },
                        )
                        SwipeToDismissBox(
                            state = boxState,
                            enableDismissFromEndToStart = working,
                            enableDismissFromStartToEnd = false,
                            modifier = Modifier.testTag(TradingBlotterTestTags.ROW_SWIPE),
                            backgroundContent = {
                                if (working) {
                                    CancelSwipeBackground()
                                }
                            },
                        ) {
                            OrderRow(
                                o = o,
                                columns = columns,
                                fillsMode = fillsMode,
                                onClick = { onToggleRowExpanded(o.clord) },
                                onLongClick = { onLongPressOrder(o) },
                                modifier = Modifier
                                    .testTag(TradingBlotterTestTags.orderRow(o.clord)),
                            )
                        }
                        if (expanded) OrderDetailPanel(o, fillsMode)
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

@OptIn(androidx.compose.foundation.ExperimentalFoundationApi::class)
@Composable
private fun OrderRow(
    o: BlotterOrder,
    columns: List<BlotterColumn>,
    fillsMode: Boolean,
    modifier: Modifier = Modifier,
    onClick: () -> Unit = {},
    onLongClick: () -> Unit = {},
) {
    Row(
        modifier = modifier
            .fillMaxWidth()
            .background(MaterialTheme.colorScheme.surface)
            .combinedClickable(onClick = onClick, onLongClick = onLongClick)
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

// ---- Row master-detail ------------------------------------------------------

/**
 * Inline detail panel shown beneath an expanded order/fill row. Renders every [BlotterOrder] field
 * plus a small execution breakdown (executed qty, avgPx, leaves, fill percent). Transient - driven
 * purely off [BlotterUiState.expandedRows]; the 1s ticker refreshes these values live.
 */
@Composable
private fun OrderDetailPanel(o: BlotterOrder, fillsMode: Boolean) {
    val fillPct = if (o.qty > 0.0) o.cumQty / o.qty * 100.0 else 0.0
    Surface(
        color = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.35f),
        modifier = Modifier
            .fillMaxWidth()
            .testTag(TradingBlotterTestTags.rowDetail(o.clord)),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 10.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = o.clord,
                    fontSize = 12.sp,
                    fontWeight = FontWeight.Bold,
                    fontFamily = FontFamily.Monospace,
                    color = MaterialTheme.colorScheme.onSurface,
                    modifier = Modifier.testTag(TradingBlotterTestTags.rowDetailField(o.clord, "clord")),
                )
                Spacer(Modifier.width(8.dp))
                StatusBadge(o.status)
            }

            DetailField("Symbol", o.sym, o.clord, "sym")
            DetailRowSide(o, o.clord)
            DetailField("Price", fmtPx(o.px, o.sym), o.clord, "px")
            DetailField("Qty", fmtQty(o.qty, o.sym), o.clord, "qty")
            DetailField("CumQty", fmtQty(o.cumQty, o.sym), o.clord, "cumqty")
            DetailField("Leaves", fmtQty(o.leaves, o.sym), o.clord, "leaves")
            DetailField("AvgPx", fmtPx(o.avgPx, o.sym), o.clord, "avgpx")
            DetailField("Status", o.status.label, o.clord, "status")
            DetailField("TIF", o.tif.label, o.clord, "tif")

            HorizontalDivider(
                color = MaterialTheme.colorScheme.outlineVariant.copy(alpha = 0.4f),
                modifier = Modifier.padding(vertical = 6.dp),
            )
            Text(
                text = "Execution",
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 2.dp),
            )
            DetailField("Executed", fmtQty(o.cumQty, o.sym), o.clord, "exec")
            DetailField("Avg fill px", fmtPx(o.avgPx, o.sym), o.clord, "execavgpx")
            DetailField("Open (leaves)", fmtQty(o.leaves, o.sym), o.clord, "execleaves")
            DetailField("Fill", "%.1f".format(fillPct) + "%", o.clord, "fillpct")

            // Reserved slot for the order-cancel action (a Cancel button belongs HERE when the
            // actions gap ships), so it does not compete with the row-body expand tap.
        }
    }
}

/** A compact label / value pair line inside [OrderDetailPanel]. */
@Composable
private fun DetailField(
    label: String,
    value: String,
    clord: String,
    key: String,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = label,
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1.2f),
        )
        Text(
            text = value,
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = MaterialTheme.colorScheme.onSurface,
            textAlign = TextAlign.End,
            modifier = Modifier
                .weight(2f)
                .testTag(TradingBlotterTestTags.rowDetailField(clord, key)),
        )
    }
}

/** The Side detail line, color-coded to match the row's B / S semantics. */
@Composable
private fun DetailRowSide(o: BlotterOrder, clord: String) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(vertical = 1.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Text(
            text = "Side",
            fontSize = 11.sp,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(1.2f),
        )
        Text(
            text = if (o.side == BlotterSide.BUY) "Buy (B)" else "Sell (S)",
            fontSize = 12.sp,
            fontFamily = FontFamily.Monospace,
            color = sideColor(o.side),
            textAlign = TextAlign.End,
            modifier = Modifier
                .weight(2f)
                .testTag(TradingBlotterTestTags.rowDetailField(clord, "side")),
        )
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
    onReorderColumn: (Int, Int) -> Unit,
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
                modifier = Modifier.padding(bottom = 2.dp),
            )
            Text(
                "Drag the handle to reorder; tap to show or hide.",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            // Iterate the FULL persisted order so reordering is stable for hidden columns too.
            state.columnOrder.forEachIndexed { index, col ->
                ColumnReorderRow(
                    col = col,
                    index = index,
                    visible = col !in state.hiddenColumns,
                    onToggleColumn = onToggleColumn,
                    onReorderColumn = onReorderColumn,
                )
            }
        }
    }
}

/** One reorderable column row: a checkbox target plus a draggable handle. */
@Composable
private fun ColumnReorderRow(
    col: BlotterColumn,
    index: Int,
    visible: Boolean,
    onToggleColumn: (BlotterColumn) -> Unit,
    onReorderColumn: (Int, Int) -> Unit,
) {
    val name = col.name.lowercase()
    // Row height threshold in px: one full row up or down moves one index.
    val rowHeightPx = with(LocalDensity.current) { 48.dp.toPx() }
    var dragAccum by remember(index) { mutableFloatStateOf(0f) }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .testTag("trading_blotter_column_row_${name}")
            .heightIn(min = 48.dp)
            .padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Row(
            modifier = Modifier
                .weight(1f)
                .clickable { onToggleColumn(col) }
                .testTag("trading_blotter_column_toggle_${name}"),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Checkbox(checked = visible, onCheckedChange = { onToggleColumn(col) })
            Spacer(Modifier.width(8.dp))
            Text(col.header)
        }
        Icon(
            imageVector = Icons.Filled.DragHandle,
            contentDescription = "Reorder ${col.header}",
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier
                .testTag("trading_blotter_column_drag_${name}")
                .padding(8.dp)
                .pointerInput(index) {
                    detectDragGestures(
                        onDragEnd = { dragAccum = 0f },
                        onDragCancel = { dragAccum = 0f },
                    ) { change, dragAmount ->
                        change.consume()
                        dragAccum += dragAmount.y
                        while (dragAccum <= -rowHeightPx) {
                            onReorderColumn(index, index - 1)
                            dragAccum += rowHeightPx
                        }
                        while (dragAccum >= rowHeightPx) {
                            onReorderColumn(index, index + 1)
                            dragAccum -= rowHeightPx
                        }
                    }
                },
        )
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

// ---- Export sheet -----------------------------------------------------------

/**
 * CSV / TSV export chooser. Mirrors [GroupOption] styling. Exports the CURRENT filtered + sorted
 * Orders/Fills view with only the currently-visible columns (see [exportRows] / [formatDelimited]).
 */
@Composable
private fun ExportSheet(
    rowCount: Int,
    columnCount: Int,
    onExport: (tsv: Boolean) -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(TradingBlotterTestTags.EXPORT_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Text(
                "Export",
                style = MaterialTheme.typography.titleMedium,
                modifier = Modifier.padding(bottom = 2.dp),
            )
            Text(
                "$rowCount rows, $columnCount columns",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            ExportOption("CSV", TradingBlotterTestTags.EXPORT_CSV) { onExport(false) }
            ExportOption("TSV", TradingBlotterTestTags.EXPORT_TSV) { onExport(true) }
        }
    }
}

@Composable
private fun ExportOption(
    label: String,
    tag: String,
    onClick: () -> Unit,
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .testTag(tag)
            .padding(vertical = 10.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = Icons.Filled.Share,
            contentDescription = null,
            tint = MaterialTheme.colorScheme.onSurfaceVariant,
        )
        Spacer(Modifier.width(12.dp))
        Text(label, color = MaterialTheme.colorScheme.onSurface)
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

// ---- Order actions (cancel via swipe / long-press) --------------------------

/** Whether an order is still working (LIVE/PARTIAL) and therefore cancelable. */
private fun BlotterStatus.isCancelable(): Boolean =
    this == BlotterStatus.LIVE || this == BlotterStatus.PARTIAL

/**
 * The red end-to-start swipe background revealed behind a working order row: a right-aligned
 * "Cancel" label with a clear icon. Only rendered for cancelable rows.
 */
@Composable
private fun CancelSwipeBackground() {
    Surface(
        color = SellColor.copy(alpha = 0.90f),
        modifier = Modifier
            .fillMaxSize()
            .testTag(TradingBlotterTestTags.CANCEL_BG),
    ) {
        Row(
            modifier = Modifier
                .fillMaxSize()
                .padding(horizontal = 20.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.End,
        ) {
            Text(
                text = "Cancel",
                color = Color.White,
                fontSize = 13.sp,
                fontWeight = FontWeight.SemiBold,
            )
            Spacer(Modifier.width(8.dp))
            Icon(
                imageVector = Icons.Filled.Clear,
                contentDescription = "Cancel",
                tint = Color.White,
            )
        }
    }
}

/**
 * Long-press context sheet for a single order. Lists the "Cancel order" action, enabled only when
 * the order is still working. Dismisses after the action fires (the caller clears the hoisted
 * contextMenuOrder). Mirrors [GroupOption] styling.
 */
@Composable
private fun OrderActionsSheet(
    order: BlotterOrder,
    onCancel: () -> Unit,
    onDismiss: () -> Unit,
) {
    val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
    val cancelable = order.status.isCancelable()
    ModalBottomSheet(
        onDismissRequest = onDismiss,
        sheetState = sheetState,
        modifier = Modifier.testTag(TradingBlotterTestTags.CONTEXT_SHEET),
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp)
                .padding(bottom = 24.dp),
        ) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = order.clord,
                    style = MaterialTheme.typography.titleMedium,
                    fontFamily = FontFamily.Monospace,
                )
                Spacer(Modifier.width(8.dp))
                StatusBadge(order.status)
            }
            Text(
                text = order.sym + " " + order.side.code,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.padding(bottom = 8.dp),
            )
            HorizontalDivider(modifier = Modifier.padding(bottom = 4.dp))
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .clickable(enabled = cancelable, onClick = onCancel)
                    .testTag(TradingBlotterTestTags.CONTEXT_CANCEL)
                    .padding(vertical = 12.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Icon(
                    imageVector = Icons.Filled.Clear,
                    contentDescription = null,
                    tint = if (cancelable) SellColor else MaterialTheme.colorScheme.onSurfaceVariant,
                )
                Spacer(Modifier.width(12.dp))
                Text(
                    text = "Cancel order",
                    color = if (cancelable) {
                        MaterialTheme.colorScheme.onSurface
                    } else {
                        MaterialTheme.colorScheme.onSurfaceVariant
                    },
                    modifier = Modifier.testTag(TradingBlotterTestTags.contextCancel(order.clord)),
                )
            }
            if (!cancelable) {
                Text(
                    text = "This order is " + order.status.label + " and cannot be cancelled.",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
