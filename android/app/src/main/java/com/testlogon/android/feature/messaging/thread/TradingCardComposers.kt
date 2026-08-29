@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class, androidx.compose.ui.ExperimentalComposeUiApi::class)

package com.testlogon.android.feature.messaging.thread

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTagsAsResourceId
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.messaging.TradingCardModel

object TradingComposerTestTags {
    const val ATTACH_MARKET = "thread_attach_market"
    const val ATTACH_POSITION = "thread_attach_position"
    const val MARKET_PICKER = "thread_market_picker"
    const val MARKET_PICKER_SEARCH = "thread_market_picker_search"
    const val MARKET_PICKER_ROW = "thread_market_picker_row_"
    const val POSITION_PICKER = "thread_position_picker"
    const val POSITION_PICKER_ROW = "thread_position_picker_row_"
    const val DISCLOSURE_CHIP = "thread_position_disclosure_"
    const val POSITION_SEND = "thread_position_send"
}

/** FE-101 — "Share market": searchable symbol picker; selecting a row sends a market_card message. */
@Composable
fun MarketPickerSheet(
    state: MarketPickerState,
    onQuery: (String) -> Unit,
    onPick: (SymbolPick) -> Unit,
    onDismiss: () -> Unit,
) {
    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(TradingComposerTestTags.MARKET_PICKER).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Share market", style = MaterialTheme.typography.titleMedium)
            OutlinedTextField(
                value = state.query,
                onValueChange = onQuery,
                modifier = Modifier.fillMaxWidth().padding(top = 8.dp).testTag(TradingComposerTestTags.MARKET_PICKER_SEARCH),
                placeholder = { Text("Search symbol (e.g. BTC)") },
                singleLine = true,
            )
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.filtered.isEmpty() -> Text(
                    state.error ?: "No symbols found.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> state.filtered.forEach { sym ->
                    OutlinedButton(
                        onClick = { onPick(sym) },
                        modifier = Modifier.fillMaxWidth().padding(top = 6.dp).testTag(TradingComposerTestTags.MARKET_PICKER_ROW + sym.symbolId),
                    ) { Text(sym.symbol, style = MaterialTheme.typography.bodyLarge) }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

/**
 * FE-102 — "Share position": pick one open position + a disclosure (full / P&L% / ROI), then send a
 * position_card carrying ONLY the permitted fields (the projection is done in the ViewModel/model).
 */
@Composable
fun PositionPickerSheet(
    state: PositionPickerState,
    onSend: (OpenPositionPick, TradingCardModel.Disclosure) -> Unit,
    onDismiss: () -> Unit,
) {
    var selectedId by remember { mutableStateOf<Int?>(null) }
    var disclosure by remember { mutableStateOf(TradingCardModel.Disclosure.FULL) }

    ModalBottomSheet(onDismissRequest = onDismiss, modifier = Modifier.testTag(TradingComposerTestTags.POSITION_PICKER).semantics { testTagsAsResourceId = true }) {
        Column(Modifier.fillMaxWidth().navigationBarsPadding().padding(16.dp).verticalScroll(rememberScrollState())) {
            Text("Share position", style = MaterialTheme.typography.titleMedium)
            when {
                state.loading -> CircularProgressIndicator(Modifier.padding(16.dp))
                state.positions.isEmpty() -> Text(
                    state.error ?: "You have no open positions to share.",
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(top = 8.dp),
                )
                else -> {
                    Text("Position", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 8.dp))
                    state.positions.forEach { pos ->
                        val sideLabel = when (pos.side) { "buy" -> "LONG"; "sell" -> "SHORT"; else -> "" }
                        FilterChip(
                            selected = selectedId == pos.symbolId,
                            onClick = { selectedId = pos.symbolId },
                            label = { Text("${pos.symbol}  $sideLabel") },
                            modifier = Modifier.padding(top = 4.dp).testTag(TradingComposerTestTags.POSITION_PICKER_ROW + pos.symbolId),
                        )
                    }
                    Text("Disclosure", style = MaterialTheme.typography.labelMedium, modifier = Modifier.padding(top = 12.dp))
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        DisclosureChip(TradingCardModel.Disclosure.FULL, "Full", disclosure) { disclosure = it }
                        DisclosureChip(TradingCardModel.Disclosure.PNL_PCT, "P&L %", disclosure) { disclosure = it }
                        DisclosureChip(TradingCardModel.Disclosure.ROI, "ROI %", disclosure) { disclosure = it }
                    }
                    Text(
                        when (disclosure) {
                            TradingCardModel.Disclosure.FULL -> "Shares size, entry, mark, liquidation and uPnL."
                            TradingCardModel.Disclosure.PNL_PCT -> "Shares only your P&L percentage (no cash amounts)."
                            TradingCardModel.Disclosure.ROI -> "Shares only your ROI percentage (no cash amounts)."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(top = 6.dp),
                    )
                    val selected = state.positions.firstOrNull { it.symbolId == selectedId }
                    Button(
                        onClick = { selected?.let { onSend(it, disclosure) } },
                        enabled = selected != null,
                        modifier = Modifier.fillMaxWidth().padding(top = 16.dp).testTag(TradingComposerTestTags.POSITION_SEND),
                    ) { Text("Share position") }
                }
            }
            Box(Modifier.fillMaxWidth().heightIn(min = 16.dp))
        }
    }
}

@Composable
private fun DisclosureChip(
    value: TradingCardModel.Disclosure,
    label: String,
    selected: TradingCardModel.Disclosure,
    onSelect: (TradingCardModel.Disclosure) -> Unit,
) {
    FilterChip(
        selected = selected == value,
        onClick = { onSelect(value) },
        label = { Text(label, fontWeight = if (selected == value) FontWeight.SemiBold else FontWeight.Normal) },
        modifier = Modifier.testTag(TradingComposerTestTags.DISCLOSURE_CHIP + value.wire),
    )
}
