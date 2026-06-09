package com.testlogon.android.feature.more

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.grid.GridCells
import androidx.compose.foundation.lazy.grid.GridItemSpan
import androidx.compose.foundation.lazy.grid.LazyVerticalGrid
import androidx.compose.foundation.lazy.grid.items
import androidx.compose.foundation.lazy.grid.rememberLazyGridState
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.alpha
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.disabled
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.R
import com.testlogon.android.core.ui.state.EmptyState
import com.testlogon.android.core.ui.state.LoadingState

/** AND-067 — route-level "More" hub entry. [onNavigate] is wired to the shared NavController. */
@Composable
fun MoreRoute(
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
    viewModel: MoreViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MoreScreen(state = state, onNavigate = onNavigate, modifier = modifier)
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun MoreScreen(
    state: MoreUiState,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    androidx.compose.material3.Scaffold(
        modifier = modifier.testTag("more_screen"),
        topBar = { TopAppBar(title = { Text(stringResource(R.string.more_title)) }) },
    ) { padding ->
        when (state) {
            MoreUiState.Loading -> LoadingState(modifier = Modifier.padding(padding))
            MoreUiState.Empty -> EmptyState(
                title = stringResource(R.string.more_empty),
                modifier = Modifier.padding(padding).testTag("more_empty"),
            )
            is MoreUiState.Content -> MoreGrid(
                sections = state.sections,
                onNavigate = onNavigate,
                modifier = Modifier.padding(padding),
            )
        }
    }
}

@Composable
private fun MoreGrid(
    sections: List<MoreSectionUi>,
    onNavigate: (route: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val gridState = rememberLazyGridState()
    LazyVerticalGrid(
        state = gridState,
        columns = GridCells.Adaptive(minSize = 160.dp),
        modifier = modifier.fillMaxSize().testTag("more_grid"),
        contentPadding = androidx.compose.foundation.layout.PaddingValues(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        sections.forEach { section ->
            item(span = { GridItemSpan(maxLineSpan) }) {
                Text(
                    text = stringResource(section.section.titleRes),
                    style = MaterialTheme.typography.titleSmall,
                    modifier = Modifier.fillMaxWidth().testTag("more_section_${section.section.name.lowercase()}"),
                )
            }
            items(section.items, key = { it.entry.id }) { item ->
                MoreEntryCard(item = item, onNavigate = onNavigate)
            }
        }
    }
}

@Composable
private fun MoreEntryCard(
    item: MoreItemUi,
    onNavigate: (route: String) -> Unit,
) {
    val entry = item.entry
    val label = stringResource(entry.labelRes)
    val disabled = item.availability is EntryAvailability.Disabled
    val reason = (item.availability as? EntryAvailability.Disabled)?.let { stringResource(it.reasonRes) }
    val cd = if (disabled && reason != null) "$label. $reason" else label

    val cardModifier = Modifier
        .fillMaxWidth()
        .heightIn(min = 96.dp)
        .testTag("more_entry_${entry.id}")
        .then(
            if (disabled) {
                Modifier.alpha(0.5f).semantics {
                    this.disabled()
                    contentDescription = cd
                }
            } else {
                Modifier.semantics { contentDescription = cd }
            },
        )

    val onClick: () -> Unit = if (disabled) ({}) else ({ onNavigate(entry.route) })

    Card(
        onClick = onClick,
        enabled = !disabled,
        modifier = cardModifier,
        colors = CardDefaults.cardColors(),
    ) {
        Column(
            modifier = Modifier.fillMaxSize().padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
        ) {
            Icon(entry.icon, contentDescription = null)
            Text(label, style = MaterialTheme.typography.bodyMedium, textAlign = TextAlign.Center)
            if (disabled && reason != null) {
                Text(
                    text = reason,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    textAlign = TextAlign.Center,
                )
            }
        }
    }
}
