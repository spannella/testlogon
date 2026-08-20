@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.search

import androidx.compose.foundation.background
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
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Bolt
import androidx.compose.material.icons.filled.Close
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.ShowChart
import androidx.compose.material.icons.filled.Widgets
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalSoftwareKeyboardController
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface

/**
 * Global search route: a quick-jump over exchange symbols, the app trading destinations, and a
 * curated set of actions. Auto-focuses the field, filters/ranks live via [SearchViewModel], and
 * delegates a tapped result to the navigation lambdas. Rendered on the dark trading palette.
 */
@Composable
fun GlobalSearchRoute(
    onBack: () -> Unit,
    onOpenSymbol: (symbolId: Int) -> Unit,
    onOpenDestination: (SearchDest) -> Unit,
    onRunAction: (SearchActionId) -> Unit,
    viewModel: SearchViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    val keyboard = LocalSoftwareKeyboardController.current

    val dispatch: (SearchItem) -> Unit = remember(onOpenSymbol, onOpenDestination, onRunAction) {
        { item ->
            viewModel.onResultOpened(item)
            keyboard?.hide()
            when (item.kind) {
                SearchResultKind.SYMBOL -> item.symbolId?.let(onOpenSymbol)
                SearchResultKind.DESTINATION ->
                    runCatching { SearchDest.valueOf(item.id.removePrefix("dest:")) }
                        .getOrNull()?.let(onOpenDestination)
                SearchResultKind.ACTION -> item.actionId?.let(onRunAction)
            }
        }
    }

    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            SearchTopBar(
                query = state.query,
                onQuery = viewModel::onQueryChange,
                onBack = onBack,
            )
            Box(modifier = Modifier.fillMaxSize()) {
                when (state.phase) {
                    SearchUiState.Phase.Idle -> IdleContent(recents = state.recents, onOpen = dispatch)
                    SearchUiState.Phase.Empty -> EmptyContent(query = state.query)
                    SearchUiState.Phase.Results -> ResultsList(groups = state.groups, onOpen = dispatch)
                }
            }
        }
    }
}

@Composable
private fun SearchTopBar(
    query: String,
    onQuery: (String) -> Unit,
    onBack: () -> Unit,
) {
    val focusRequester = remember { FocusRequester() }
    LaunchedEffect(Unit) { focusRequester.requestFocus() }
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .padding(start = 4.dp, end = 12.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(
                Icons.AutoMirrored.Filled.ArrowBack,
                contentDescription = "Back",
                tint = MarketColors.TextPrimary,
            )
        }
        Row(
            modifier = Modifier
                .weight(1f)
                .height(44.dp)
                .background(MarketColors.SurfaceAlt, RoundedCornerShape(12.dp))
                .padding(horizontal = 12.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Icon(
                Icons.Filled.Search,
                contentDescription = null,
                tint = MarketColors.TextSecondary,
                modifier = Modifier.size(20.dp),
            )
            Spacer(Modifier.size(8.dp))
            Box(modifier = Modifier.weight(1f)) {
                if (query.isEmpty()) {
                    Text(
                        text = "Search symbols, screens, actions",
                        color = MarketColors.TextFaint,
                        fontSize = 15.sp,
                    )
                }
                BasicTextField(
                    value = query,
                    onValueChange = onQuery,
                    singleLine = true,
                    textStyle = TextStyle(color = MarketColors.TextPrimary, fontSize = 15.sp),
                    cursorBrush = SolidColor(MarketColors.Accent),
                    keyboardOptions = KeyboardOptions(imeAction = ImeAction.Search),
                    keyboardActions = KeyboardActions(),
                    modifier = Modifier
                        .fillMaxWidth()
                        .focusRequester(focusRequester)
                        .testTag("search_field"),
                )
            }
            if (query.isNotEmpty()) {
                IconButton(onClick = { onQuery("") }, modifier = Modifier.size(24.dp)) {
                    Icon(
                        Icons.Filled.Close,
                        contentDescription = "Clear",
                        tint = MarketColors.TextSecondary,
                        modifier = Modifier.size(18.dp),
                    )
                }
            }
        }
    }
}

@Composable
private fun ResultsList(groups: List<SearchGroup>, onOpen: (SearchItem) -> Unit) {
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("search_results"),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        groups.forEach { group ->
            item(key = "hdr:${group.kind}") { GroupHeader(kind = group.kind) }
            items(group.items.size, key = { group.items[it].id }) { i ->
                ResultRow(item = group.items[i], onClick = { onOpen(group.items[i]) })
            }
        }
    }
}

@Composable
private fun IdleContent(recents: List<SearchItem>, onOpen: (SearchItem) -> Unit) {
    if (recents.isEmpty()) {
        Column(
            modifier = Modifier.fillMaxSize().padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center,
        ) {
            Icon(
                Icons.Filled.Search,
                contentDescription = null,
                tint = MarketColors.TextFaint,
                modifier = Modifier.size(48.dp),
            )
            Spacer(Modifier.height(12.dp))
            Text("Search anything", color = MarketColors.TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
            Spacer(Modifier.height(4.dp))
            Text(
                "Jump to a symbol, a screen, or a quick action.",
                color = MarketColors.TextSecondary,
                fontSize = 13.sp,
            )
        }
        return
    }
    LazyColumn(
        modifier = Modifier.fillMaxSize().testTag("search_recents"),
        contentPadding = PaddingValues(horizontal = 12.dp, vertical = 8.dp),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        item(key = "hdr:recent") {
            Text(
                "RECENT",
                color = MarketColors.TextSecondary,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(start = 8.dp, top = 8.dp, bottom = 6.dp),
            )
        }
        items(recents.size, key = { recents[it].id }) { i ->
            ResultRow(item = recents[i], onClick = { onOpen(recents[i]) })
        }
    }
}

@Composable
private fun EmptyContent(query: String) {
    Column(
        modifier = Modifier.fillMaxSize().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(
            Icons.Filled.Search,
            contentDescription = null,
            tint = MarketColors.TextFaint,
            modifier = Modifier.size(48.dp),
        )
        Spacer(Modifier.height(12.dp))
        Text("No results", color = MarketColors.TextPrimary, fontSize = 18.sp, fontWeight = FontWeight.SemiBold)
        Spacer(Modifier.height(4.dp))
        Text("Nothing matches that search.", color = MarketColors.TextSecondary, fontSize = 13.sp)
    }
}

@Composable
private fun GroupHeader(kind: SearchResultKind) {
    val label = when (kind) {
        SearchResultKind.SYMBOL -> "SYMBOLS"
        SearchResultKind.DESTINATION -> "SCREENS"
        SearchResultKind.ACTION -> "ACTIONS"
    }
    Text(
        text = label,
        color = MarketColors.TextSecondary,
        fontSize = 11.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(start = 8.dp, top = 12.dp, bottom = 6.dp),
    )
}

@Composable
private fun ResultRow(item: SearchItem, onClick: () -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MarketColors.Surface)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 12.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Icon(
            imageVector = iconFor(item.kind),
            contentDescription = null,
            tint = MarketColors.Accent,
            modifier = Modifier.size(22.dp),
        )
        Spacer(Modifier.size(12.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(item.title, color = MarketColors.TextPrimary, fontSize = 15.sp, fontWeight = FontWeight.Medium)
            item.subtitle?.let {
                Text(it, color = MarketColors.TextSecondary, fontSize = 12.sp)
            }
        }
    }
}

private fun iconFor(kind: SearchResultKind): ImageVector = when (kind) {
    SearchResultKind.SYMBOL -> Icons.Filled.ShowChart
    SearchResultKind.DESTINATION -> Icons.Filled.Widgets
    SearchResultKind.ACTION -> Icons.Filled.Bolt
}
