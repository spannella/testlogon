@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.markets.alerts.pricealerts

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material3.DropdownMenu
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.text.KeyboardOptions
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.exchange.alerts.PriceAlert
import com.testlogon.android.data.exchange.alerts.PriceAlertDirection
import com.testlogon.android.data.exchange.alerts.PriceAlertSubject
import com.testlogon.android.feature.markets.ui.MarketColors
import com.testlogon.android.feature.markets.ui.MarketSurface

/**
 * (Generalized) Price Alerts management route: an add form (subject-kind toggle Symbol/Creator Token/
 * Strategy -> subject picker + above/below + threshold + optional note) over a list of the user active +
 * triggered alerts across ALL kinds, each showing the live current value with delete and (for triggered)
 * re-arm. Reachable from the Trading Alerts screen. Renders on the dark exchange palette.
 */
@Composable
fun PriceAlertsRoute(
    onBack: () -> Unit,
    viewModel: PriceAlertsViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()
    MarketSurface {
        Column(modifier = Modifier.fillMaxSize().statusBarsPadding()) {
            Header(onBack = onBack)
            LazyColumn(
                modifier = Modifier.fillMaxSize().testTag("price_alerts_list"),
                contentPadding = PaddingValues(horizontal = 12.dp, vertical = 10.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                item {
                    AddAlertForm(state = state, viewModel = viewModel)
                }
                if (state.alerts.isEmpty()) {
                    item { EmptyState() }
                } else {
                    if (state.active.isNotEmpty()) {
                        item { SectionLabel("ACTIVE") }
                        items(state.active, key = { it.id }) { alert ->
                            AlertRow(alert, state, onDelete = { viewModel.delete(alert.id) }, onRearm = null)
                        }
                    }
                    if (state.triggered.isNotEmpty()) {
                        item { SectionLabel("TRIGGERED") }
                        items(state.triggered, key = { it.id }) { alert ->
                            AlertRow(alert, state, onDelete = { viewModel.delete(alert.id) },
                                onRearm = { viewModel.rearm(alert.id) })
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun Header(onBack: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(start = 4.dp, end = 8.dp, top = 6.dp, bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        IconButton(onClick = onBack) {
            Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "Back", tint = MarketColors.TextPrimary)
        }
        Column(modifier = Modifier.weight(1f)) {
            Text("Price alerts", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 22.sp)
            Text("Notify me when a symbol, token or fund crosses a value",
                color = MarketColors.TextSecondary, fontSize = 12.sp)
        }
    }
}

@Composable
private fun KindToggle(kind: PriceAlertSubject, onSelect: (PriceAlertSubject) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        KindChip("Symbol", "symbol", kind == PriceAlertSubject.SYMBOL) { onSelect(PriceAlertSubject.SYMBOL) }
        KindChip("Creator Token", "token", kind == PriceAlertSubject.TOKEN) { onSelect(PriceAlertSubject.TOKEN) }
        KindChip("Strategy", "strategy", kind == PriceAlertSubject.STRATEGY) { onSelect(PriceAlertSubject.STRATEGY) }
    }
}

@Composable
private fun KindChip(label: String, tag: String, selected: Boolean, onClick: () -> Unit) {
    Box(
        modifier = Modifier.clip(RoundedCornerShape(8.dp))
            .background(if (selected) MarketColors.Accent else MarketColors.SurfaceAlt)
            .border(1.dp, if (selected) MarketColors.Accent else MarketColors.Border, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick).padding(horizontal = 10.dp, vertical = 8.dp)
            .testTag("price_alert_kind_" + tag),
    ) {
        Text(label, color = if (selected) MarketColors.Bg else MarketColors.TextSecondary,
            fontWeight = FontWeight.SemiBold, fontSize = 12.sp)
    }
}

@Composable
private fun LabeledPicker(
    label: String,
    options: List<Pair<String, String>>,
    onSelect: (String) -> Unit,
    tagPrefix: String,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    Box(modifier = modifier) {
        Box(
            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp))
                .border(1.dp, MarketColors.Border, RoundedCornerShape(8.dp))
                .clickable { expanded = true }.padding(horizontal = 12.dp, vertical = 12.dp)
                .testTag(tagPrefix),
        ) {
            Text(label, color = MarketColors.TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
        }
        DropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { (id, text) ->
                DropdownMenuItem(
                    text = { Text(text) },
                    onClick = { onSelect(id); expanded = false },
                    modifier = Modifier.testTag(tagPrefix + "_" + id),
                )
            }
        }
    }
}

@Composable
private fun DirectionToggle(direction: PriceAlertDirection, onSelect: (PriceAlertDirection) -> Unit) {
    Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        Chip("Above", direction == PriceAlertDirection.ABOVE, MarketColors.Up) { onSelect(PriceAlertDirection.ABOVE) }
        Chip("Below", direction == PriceAlertDirection.BELOW, MarketColors.Down) { onSelect(PriceAlertDirection.BELOW) }
    }
}

@Composable
private fun Chip(label: String, selected: Boolean, accent: Color, onClick: () -> Unit) {
    Box(
        modifier = Modifier.clip(RoundedCornerShape(8.dp))
            .background(if (selected) accent else MarketColors.SurfaceAlt)
            .border(1.dp, if (selected) accent else MarketColors.Border, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick).padding(horizontal = 14.dp, vertical = 12.dp)
            .testTag("price_alert_dir_" + label.lowercase()),
    ) {
        Text(label, color = if (selected) MarketColors.Bg else MarketColors.TextSecondary,
            fontWeight = FontWeight.SemiBold, fontSize = 13.sp)
    }
}

@Composable
private fun SectionLabel(text: String) {
    Text(text, color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace,
        fontWeight = FontWeight.Bold, fontSize = 11.sp,
        modifier = Modifier.padding(top = 6.dp, start = 4.dp))
}

@Composable
private fun AddAlertForm(
    state: PriceAlertsUiState,
    viewModel: PriceAlertsViewModel,
) {
    var kind by remember { mutableStateOf(PriceAlertSubject.SYMBOL) }
    var symbolId by remember(state.instruments) { mutableStateOf(state.instruments.firstOrNull()?.symbolId) }
    var tokenId by remember(state.tokens) { mutableStateOf(state.tokens.firstOrNull()?.tokenId) }
    var strategyId by remember(state.strategies) { mutableStateOf(state.strategies.firstOrNull()?.strategyId) }
    var direction by remember { mutableStateOf(PriceAlertDirection.ABOVE) }
    var price by remember { mutableStateOf("") }
    var note by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }

    Column(
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
            .background(MarketColors.Surface).border(1.dp, MarketColors.Border, RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(10.dp),
    ) {
        Text("New alert", color = MarketColors.TextPrimary, fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
        KindToggle(kind = kind, onSelect = { kind = it; error = null })
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp), verticalAlignment = Alignment.CenterVertically) {
            when (kind) {
                PriceAlertSubject.SYMBOL -> LabeledPicker(
                    label = state.instruments.firstOrNull { it.symbolId == symbolId }?.symbol ?: "Symbol",
                    options = state.instruments.map { it.symbolId.toString() to it.symbol },
                    onSelect = { symbolId = it.toIntOrNull() }, tagPrefix = "price_alert_symbol",
                    modifier = Modifier.weight(1f),
                )
                PriceAlertSubject.TOKEN -> LabeledPicker(
                    label = state.tokens.firstOrNull { it.tokenId == tokenId }
                        ?.let { it.ticker.ifBlank { it.name } } ?: "Token",
                    options = state.tokens.map { it.tokenId to it.ticker.ifBlank { it.name } },
                    onSelect = { tokenId = it }, tagPrefix = "price_alert_token",
                    modifier = Modifier.weight(1f),
                )
                PriceAlertSubject.STRATEGY -> LabeledPicker(
                    label = state.strategies.firstOrNull { it.strategyId == strategyId }?.name ?: "Strategy",
                    options = state.strategies.map { it.strategyId to it.name },
                    onSelect = { strategyId = it }, tagPrefix = "price_alert_strategy",
                    modifier = Modifier.weight(1f),
                )
            }
            DirectionToggle(direction = direction, onSelect = { direction = it })
        }
        OutlinedTextField(
            value = price, onValueChange = { price = it; error = null },
            label = { Text(if (kind == PriceAlertSubject.SYMBOL) "Price" else "Price (USD)") }, singleLine = true,
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Decimal),
            modifier = Modifier.fillMaxWidth().testTag("price_alert_price"),
        )
        OutlinedTextField(
            value = note, onValueChange = { note = it },
            label = { Text("Note (optional)") }, singleLine = true,
            modifier = Modifier.fillMaxWidth().testTag("price_alert_note"),
        )
        error?.let { Text(it, color = MarketColors.Down, fontSize = 12.sp) }
        Box(
            modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp))
                .background(MarketColors.Accent).clickable {
                    val ok = when (kind) {
                        PriceAlertSubject.SYMBOL -> symbolId?.let { viewModel.add(it, direction, price, note) } ?: false
                        PriceAlertSubject.TOKEN -> tokenId?.let { viewModel.addToken(it, direction, price, note) } ?: false
                        PriceAlertSubject.STRATEGY -> strategyId?.let { viewModel.addStrategy(it, direction, price, note) } ?: false
                    }
                    if (!ok) { error = "Pick a subject and enter a valid price" }
                    else { price = ""; note = ""; error = null }
                }.padding(vertical = 12.dp).testTag("price_alert_add"),
            contentAlignment = Alignment.Center,
        ) {
            Text("Add alert", color = MarketColors.Bg, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        }
    }
}

@Composable
private fun AlertRow(
    alert: PriceAlert,
    state: PriceAlertsUiState,
    onDelete: () -> Unit,
    onRearm: (() -> Unit)?,
) {
    val accent = if (alert.direction == PriceAlertDirection.ABOVE) MarketColors.Up else MarketColors.Down
    val dir = if (alert.direction == PriceAlertDirection.ABOVE) "above" else "below"
    val label = subjectLabel(alert, state)
    val kindTag = when (alert.subject) {
        PriceAlertSubject.SYMBOL -> ""
        PriceAlertSubject.TOKEN -> " token"
        PriceAlertSubject.STRATEGY -> " NAV"
    }
    val threshold = formatValue(alert, alert.priceTicks, state)
    val current = state.currentValue(alert)?.let { formatValue(alert, it, state) }
    Row(
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(12.dp))
            .background(MarketColors.Surface).border(1.dp, MarketColors.Border, RoundedCornerShape(12.dp))
            .padding(14.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        Column(modifier = Modifier.weight(1f)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(label + kindTag + " " + dir + " " + threshold, color = MarketColors.TextPrimary,
                    fontWeight = FontWeight.SemiBold, fontSize = 14.sp)
                Spacer(Modifier.width(8.dp))
                Box(modifier = Modifier.size(6.dp).clip(RoundedCornerShape(3.dp)).background(accent))
            }
            Spacer(Modifier.size(3.dp))
            Text(
                buildString {
                    append("current ").append(current ?: "-")
                    if (alert.triggeredTs != null) append("  -  triggered")
                    alert.note?.let { append("  -  ").append(it) }
                },
                color = MarketColors.TextSecondary, fontSize = 12.sp,
            )
        }
        if (onRearm != null) {
            Box(
                modifier = Modifier.clip(RoundedCornerShape(8.dp))
                    .border(1.dp, MarketColors.Accent, RoundedCornerShape(8.dp))
                    .clickable(onClick = onRearm).padding(horizontal = 12.dp, vertical = 8.dp)
                    .testTag("price_alert_rearm_" + alert.id),
            ) {
                Text("Re-arm", color = MarketColors.Accent, fontSize = 12.sp, fontWeight = FontWeight.SemiBold)
            }
            Spacer(Modifier.width(6.dp))
        }
        IconButton(onClick = onDelete, modifier = Modifier.testTag("price_alert_delete_" + alert.id)) {
            Icon(Icons.Filled.Delete, contentDescription = "Delete", tint = MarketColors.TextSecondary)
        }
    }
}

/** Resolve a human subject label for a row across all kinds, falling back to the cached label / id. */
private fun subjectLabel(alert: PriceAlert, state: PriceAlertsUiState): String = when (alert.subject) {
    PriceAlertSubject.SYMBOL -> state.instrument(alert.symbolId)?.symbol
    PriceAlertSubject.TOKEN -> state.token(alert.subjectId)?.let { it.ticker.ifBlank { it.name } }
    PriceAlertSubject.STRATEGY -> state.strategy(alert.subjectId)?.name
} ?: alert.subjectLabel ?: ("#" + alert.subjectId)

/** Format an integer value for a row: symbol scaler for SYMBOL, dollars for TOKEN/STRATEGY cents. */
private fun formatValue(alert: PriceAlert, raw: Long, state: PriceAlertsUiState): String =
    when (alert.subject) {
        PriceAlertSubject.SYMBOL ->
            state.instrument(alert.symbolId)?.display(raw)?.let(::fmt) ?: raw.toString()
        PriceAlertSubject.TOKEN, PriceAlertSubject.STRATEGY -> fmtCents(raw)
    }

@Composable
private fun EmptyState() {
    Column(
        modifier = Modifier.fillMaxWidth().padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text("No price alerts", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 16.sp)
        Spacer(Modifier.size(6.dp))
        Text("Add one above to be notified when a symbol, token or fund crosses your value.",
            color = MarketColors.TextSecondary, fontSize = 13.sp)
    }
}

private fun fmt(v: Double): String =
    if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()

private fun fmtCents(cents: Long): String {
    val sign = if (cents < 0) "-" else ""
    val abs = kotlin.math.abs(cents)
    return sign + "USD " + (abs / 100) + "." + (abs % 100).toString().padStart(2, ZERO_CHAR)
}

private const val ZERO_CHAR = '0'
