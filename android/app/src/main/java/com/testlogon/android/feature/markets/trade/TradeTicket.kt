package com.testlogon.android.feature.markets.trade

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.ui.MarketColors
import java.util.Locale

/**
 * Order ticket. Account context sits on top; the rest is split into Trade / Positions / Orders / Fills
 * sections so order entry isn't buried under a long scroll.
 */
@Composable
fun TradeTicket(
    lastPrice: Long?,
    modifier: Modifier = Modifier,
    viewModel: TradingViewModel = hiltViewModel(),
) {
    val state by viewModel.uiState.collectAsStateWithLifecycle()

    // Prefill the price from the last trade once, while the field is untouched.
    LaunchedEffect(lastPrice) {
        if (state.priceText.isEmpty() && lastPrice != null && lastPrice > 0) {
            viewModel.setPrice(lastPrice.toString())
        }
    }

    Column(modifier = modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp).testTag("trade_ticket")) {
        state.pm?.let {
            PmBanner(it, lastPrice)
            Spacer(Modifier.height(10.dp))
        }
        state.account?.let {
            AccountStrip(it)
            Spacer(Modifier.height(10.dp))
        }

        SectionTabs(
            section = state.section,
            ordersCount = state.workingOrders.size,
            posCount = if (state.account?.position != null) 1 else 0,
            fillsCount = state.sessionFills.size,
            onSelect = viewModel::setSection,
        )
        Spacer(Modifier.height(12.dp))

        when (state.section) {
            TicketSection.TRADE -> TradeSection(state, lastPrice, viewModel)
            TicketSection.POSITIONS -> PositionsSection(state, lastPrice, viewModel)
            TicketSection.ORDERS -> OrdersSection(state, viewModel)
            TicketSection.FILLS -> FillsSection(state)
        }

        if (state.isAmending) {
            Spacer(Modifier.height(6.dp))
            Text(
                text = "Amending order · tap to cancel amend",
                color = MarketColors.TextSecondary,
                fontFamily = FontFamily.Monospace,
                fontSize = 11.sp,
                modifier = Modifier.clip(RoundedCornerShape(6.dp)).clickable { viewModel.cancelAmend() }.testTag("cancel_amend").padding(vertical = 4.dp),
            )
        }

        state.message?.let {
            Spacer(Modifier.height(8.dp))
            Text(
                text = it,
                color = if (state.messageIsError) MarketColors.Down else MarketColors.Up,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
            )
        }

        if (state.isAdmin) {
            Spacer(Modifier.height(16.dp))
            MarginConfigPanel(state.marginConfig, viewModel)
        }
    }
}

// ======================= Sections =======================

@Composable
private fun TradeSection(state: TradingUiState, lastPrice: Long?, viewModel: TradingViewModel) {
    val sideColor = if (state.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down

    OrderTypeRow(selected = state.orderType, onSelect = viewModel::setOrderType)
    Spacer(Modifier.height(10.dp))

    if (state.orderType != OrderType.QUOTE && state.orderType != OrderType.FUNDING) {
        val buyLabel = if (state.pm != null) "YES" else "Buy"
        val sellLabel = if (state.pm != null) "NO" else "Sell"
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SideButton(buyLabel, state.side == OrderSide.BUY, MarketColors.Up, Modifier.weight(1f)) { viewModel.setSide(OrderSide.BUY) }
            SideButton(sellLabel, state.side == OrderSide.SELL, MarketColors.Down, Modifier.weight(1f)) { viewModel.setSide(OrderSide.SELL) }
        }
        Spacer(Modifier.height(10.dp))
    }

    // Reference price for %-of-buying-power sizing.
    val refPrice = state.priceLong ?: state.stopLong ?: lastPrice

    when (state.orderType) {
        OrderType.LIMIT -> {
            StepperField("Price", state.priceText, viewModel::setPrice) { viewModel.stepPrice(it) }
            Spacer(Modifier.height(8.dp))
            StepperField("Quantity", state.qtyText, viewModel::setQty) { viewModel.stepQty(it) }
            QtyPercentRow { viewModel.setQtyPercent(it, refPrice) }
            Spacer(Modifier.height(8.dp))
            TifRow(state.tif, viewModel::setTif)
            if (state.tif == "GTD") {
                Spacer(Modifier.height(8.dp))
                NumberField("Expires in (minutes)", state.expiryMinText, viewModel::setExpiryMin)
            }
            Spacer(Modifier.height(8.dp))
            OrderValueRow(state.orderValue, state.account?.availableBalance)
            AdvancedSection(state, viewModel)
        }
        OrderType.MARKET -> {
            StepperField("Quantity", state.qtyText, viewModel::setQty) { viewModel.stepQty(it) }
            QtyPercentRow { viewModel.setQtyPercent(it, refPrice) }
            Spacer(Modifier.height(4.dp))
            Text("Market order — fills immediately at the best available price.", color = MarketColors.TextSecondary, fontSize = 11.sp)
            AdvancedSection(state, viewModel)
        }
        OrderType.STOP -> {
            StepperField("Stop (trigger) price", state.stopText, viewModel::setStop) { viewModel.stepStop(it) }
            Spacer(Modifier.height(8.dp))
            StepperField("Quantity", state.qtyText, viewModel::setQty) { viewModel.stepQty(it) }
            QtyPercentRow { viewModel.setQtyPercent(it, refPrice) }
        }
        OrderType.STOP_LIMIT -> {
            StepperField("Stop (trigger) price", state.stopText, viewModel::setStop) { viewModel.stepStop(it) }
            Spacer(Modifier.height(8.dp))
            StepperField("Limit price", state.priceText, viewModel::setPrice) { viewModel.stepPrice(it) }
            Spacer(Modifier.height(8.dp))
            StepperField("Quantity", state.qtyText, viewModel::setQty) { viewModel.stepQty(it) }
            QtyPercentRow { viewModel.setQtyPercent(it, refPrice) }
        }
        OrderType.TAKE_PROFIT -> {
            StepperField("Take-profit trigger", state.stopText, viewModel::setStop) { viewModel.stepStop(it) }
            Spacer(Modifier.height(8.dp))
            NumberField("Limit price (optional)", state.priceText, viewModel::setPrice)
            Spacer(Modifier.height(8.dp))
            StepperField("Quantity", state.qtyText, viewModel::setQty) { viewModel.stepQty(it) }
            QtyPercentRow { viewModel.setQtyPercent(it, refPrice) }
        }
        OrderType.QUOTE -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { NumberField("Bid price", state.bidText, viewModel::setBid) }
                Box(Modifier.weight(1f)) { NumberField("Ask price", state.askText, viewModel::setAsk) }
            }
            Spacer(Modifier.height(8.dp))
            NumberField("Quantity (each side)", state.qtyText, viewModel::setQty)
        }
        OrderType.OTO -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { NumberField("Parent price", state.priceText, viewModel::setPrice) }
                Box(Modifier.weight(1f)) { NumberField("Parent qty", state.qtyText, viewModel::setQty) }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { NumberField("Child price", state.childPriceText, viewModel::setChildPrice) }
                Box(Modifier.weight(1f)) { NumberField("Child qty", state.childQtyText, viewModel::setChildQty) }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Child = ${if (state.side == OrderSide.BUY) "Sell" else "Buy"} · triggers when the parent fills",
                color = MarketColors.TextSecondary,
                fontSize = 11.sp,
            )
        }
        OrderType.OCO -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { NumberField("Leg A price", state.priceText, viewModel::setPrice) }
                Box(Modifier.weight(1f)) { NumberField("Leg A qty", state.qtyText, viewModel::setQty) }
            }
            Spacer(Modifier.height(8.dp))
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Box(Modifier.weight(1f)) { NumberField("Leg B price", state.childPriceText, viewModel::setChildPrice) }
                Box(Modifier.weight(1f)) { NumberField("Leg B qty", state.childQtyText, viewModel::setChildQty) }
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Leg A = ${if (state.side == OrderSide.BUY) "Buy" else "Sell"}, Leg B = ${if (state.side == OrderSide.BUY) "Sell" else "Buy"} · a fill on one cancels the other",
                color = MarketColors.TextSecondary,
                fontSize = 11.sp,
            )
        }
        OrderType.FUNDING -> {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SideButton("Borrow", state.fundingBorrow, MarketColors.Up, Modifier.weight(1f)) { viewModel.setFundingBorrow(true) }
                SideButton("Lend", !state.fundingBorrow, MarketColors.Down, Modifier.weight(1f)) { viewModel.setFundingBorrow(false) }
            }
            Spacer(Modifier.height(8.dp))
            NumberField("Rate (bps)", state.fundingRateText, viewModel::setFundingRate)
            Spacer(Modifier.height(8.dp))
            NumberField("Quantity", state.fundingQtyText, viewModel::setFundingQty)
            Spacer(Modifier.height(8.dp))
            NumberField("Duration (seconds, optional)", state.fundingDurationText, viewModel::setFundingDuration)
        }
    }

    Spacer(Modifier.height(12.dp))
    val armedMarket = state.armed == "market"
    val submitColor = when {
        armedMarket -> MarketColors.Accent
        state.orderType == OrderType.QUOTE -> MarketColors.Accent
        else -> sideColor
    }
    Box(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(if (state.canSubmit) submitColor else MarketColors.SurfaceAlt)
            .clickable(enabled = state.canSubmit) { viewModel.submit() }
            .testTag("trade_place")
            .padding(vertical = 14.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(
            text = if (armedMarket) "Confirm ${if (state.side == OrderSide.BUY) "Buy" else "Sell"} ${state.qtyText} @ market".trim() else submitLabel(state),
            color = if (state.canSubmit) Color.Black else MarketColors.TextFaint,
            fontWeight = FontWeight.Bold,
            fontSize = 15.sp,
        )
    }
    state.entryHint?.let {
        Spacer(Modifier.height(6.dp))
        Text(it, color = MarketColors.TextFaint, fontSize = 11.sp)
    }

    Spacer(Modifier.height(16.dp))
    FundRow(
        value = state.depositText,
        canDeposit = state.canDeposit,
        depositing = state.depositing,
        onValue = viewModel::setDeposit,
        onDeposit = viewModel::deposit,
    )
    if (TradingFeatures.SPOT_ENABLED) {
        Spacer(Modifier.height(10.dp))
        SpotPanel(state, viewModel)
    }
}

@Composable
private fun PositionsSection(state: TradingUiState, lastPrice: Long?, viewModel: TradingViewModel) {
    val pos = state.account?.position
    if (pos == null) {
        EmptyHint("No open position")
    } else {
        PositionCard(pos = pos, liquidating = state.account?.isLiquidating == true, armed = state.armed == "close", onClose = { lastPrice?.let { viewModel.closePositionRequested(it) } })
    }
}

@Composable
private fun OrdersSection(state: TradingUiState, viewModel: TradingViewModel) {
    if (state.workingOrders.isEmpty()) {
        EmptyHint("No resting orders this session")
    } else {
        state.workingOrders.forEach { wo ->
            WorkingOrderRow(
                label = "${if (wo.side == OrderSide.BUY) "Buy" else "Sell"}  ${fmt(wo.qty.toDouble())} @ ${fmt(wo.price.toDouble())}",
                sideColor = if (wo.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down,
                onAmend = { viewModel.startAmend(wo); viewModel.setSection(TicketSection.TRADE) },
                onCancel = { viewModel.cancel(wo.clordid) },
            )
        }
        Spacer(Modifier.height(12.dp))
    }
    // Cancel-all also clears server-side quote/OTO legs (no local clordid), so keep it always available.
    Text(
        text = "Cancel all resting orders",
        color = MarketColors.Down,
        fontFamily = FontFamily.Monospace,
        fontSize = 12.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
            .clickable { viewModel.cancelAll() }
            .testTag("cancel_all")
            .padding(horizontal = 12.dp, vertical = 7.dp),
    )
}

@Composable
private fun FillsSection(state: TradingUiState) {
    if (state.sessionFills.isEmpty()) {
        EmptyHint("No fills this session")
        return
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("Price", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.2f))
        Text("Qty", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
    }
    state.sessionFills.take(60).forEach { f -> FillRow(f) }
}

@Composable
private fun EmptyHint(text: String) {
    Text(text, color = MarketColors.TextFaint, fontSize = 12.sp, modifier = Modifier.padding(vertical = 8.dp))
}

// ======================= Building blocks =======================

@Composable
private fun SectionTabs(section: TicketSection, ordersCount: Int, posCount: Int, fillsCount: Int, onSelect: (TicketSection) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().clip(RoundedCornerShape(8.dp)).background(MarketColors.SurfaceAlt).padding(3.dp),
        horizontalArrangement = Arrangement.spacedBy(3.dp),
    ) {
        TicketSection.values().forEach { s ->
            val count = when (s) {
                TicketSection.ORDERS -> ordersCount
                TicketSection.POSITIONS -> posCount
                TicketSection.FILLS -> fillsCount
                else -> 0
            }
            val label = if (count > 0 && s != TicketSection.TRADE) "${s.label} $count" else s.label
            val on = s == section
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (on) MarketColors.Surface else Color.Transparent)
                    .clickable { onSelect(s) }
                    .testTag("section_${s.name}")
                    .padding(vertical = 8.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(
                    label,
                    color = if (on) MarketColors.TextPrimary else MarketColors.TextSecondary,
                    fontWeight = if (on) FontWeight.Bold else FontWeight.Normal,
                    fontSize = 12.sp,
                    maxLines = 1,
                )
            }
        }
    }
}

@Composable
private fun QtyPercentRow(onPct: (Int) -> Unit) {
    Spacer(Modifier.height(6.dp))
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
        listOf(25, 50, 75, 100).forEach { pct ->
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(6.dp))
                    .background(MarketColors.Surface)
                    .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
                    .clickable { onPct(pct) }
                    .testTag("qty_pct_$pct")
                    .padding(vertical = 6.dp),
                contentAlignment = Alignment.Center,
            ) {
                Text(if (pct == 100) "Max" else "$pct%", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
            }
        }
    }
}

@Composable
private fun StepperField(label: String, value: String, onValue: (String) -> Unit, onStep: (Long) -> Unit) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(3.dp))
        Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            StepBtn("−", "step_dn_$label") { onStep(-1L) }
            Box(
                modifier = Modifier
                    .weight(1f)
                    .clip(RoundedCornerShape(8.dp))
                    .background(MarketColors.Surface)
                    .border(1.dp, MarketColors.Border, RoundedCornerShape(8.dp))
                    .padding(horizontal = 12.dp, vertical = 12.dp),
            ) {
                if (value.isEmpty()) {
                    Text("0", color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 16.sp)
                }
                BasicTextField(
                    value = value,
                    onValueChange = onValue,
                    singleLine = true,
                    textStyle = TextStyle(color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 16.sp),
                    cursorBrush = SolidColor(MarketColors.Accent),
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    modifier = Modifier.fillMaxWidth().testTag("field_$label"),
                )
            }
            StepBtn("+", "step_up_$label") { onStep(1L) }
        }
    }
}

@Composable
private fun StepBtn(sym: String, tag: String, onClick: () -> Unit) {
    Box(
        modifier = Modifier
            .width(44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .testTag(tag)
            .padding(vertical = 12.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(sym, color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 18.sp)
    }
}

private val fillTimeFmt = java.text.SimpleDateFormat("HH:mm:ss", Locale.US)

@Composable
private fun FillRow(fill: com.testlogon.android.data.exchange.Fill) {
    val color = when (fill.side) {
        OrderSide.BUY -> MarketColors.Up
        OrderSide.SELL -> MarketColors.Down
        null -> MarketColors.TextPrimary
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(fmt(fill.price.toDouble()), color = color, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1.2f))
        Text(fill.qty.toString(), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(
            text = if (fill.tsNs > 0) fillTimeFmt.format(java.util.Date(fill.tsNs / 1_000_000L)) else "--",
            color = MarketColors.TextFaint,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
            modifier = Modifier.weight(1f),
        )
    }
}

@Composable
private fun WalletRow(label: String, value: Long) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Text(fmt(value.toDouble()), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun PositionCard(pos: com.testlogon.android.data.exchange.PositionSnapshot, liquidating: Boolean, armed: Boolean, onClose: () -> Unit) {
    val long = pos.qty > 0
    val sideColor = if (long) MarketColors.Up else MarketColors.Down
    val pnlColor = if (pos.unrealizedPnl >= 0) MarketColors.Up else MarketColors.Down
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(12.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = "${if (long) "Long" else "Short"} ${fmt(kotlin.math.abs(pos.qty).toDouble())}",
                color = sideColor,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                fontSize = 14.sp,
            )
            Text(
                text = if (armed) "Confirm close" else "Close",
                color = Color.Black,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (armed) MarketColors.Accent else sideColor)
                    .clickable(onClick = onClose)
                    .testTag("close_position")
                    .padding(horizontal = 12.dp, vertical = 6.dp),
            )
        }
        Spacer(Modifier.height(6.dp))
        PosStat("Entry", fmt(pos.entryPrice.toDouble()))
        PosStat(
            "Liq. price",
            if (pos.liquidationPrice > 0) fmt(pos.liquidationPrice.toDouble()) else "--",
            valueColor = if (liquidating) MarketColors.Down else MarketColors.TextPrimary,
        )
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Unrealized PnL", color = MarketColors.TextSecondary, fontSize = 11.sp)
            Text(
                text = (if (pos.unrealizedPnl >= 0) "+" else "") + fmt(pos.unrealizedPnl.toDouble()),
                color = pnlColor,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                fontSize = 12.sp,
            )
        }
    }
}

@Composable
private fun PosStat(label: String, value: String, valueColor: Color = MarketColors.TextPrimary) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Text(value, color = valueColor, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
}

@Composable
private fun SideButton(text: String, selected: Boolean, color: Color, modifier: Modifier, onClick: () -> Unit) {
    Box(
        modifier = modifier
            .clip(RoundedCornerShape(8.dp))
            .background(if (selected) color else MarketColors.Surface)
            .border(1.dp, if (selected) color else MarketColors.Border, RoundedCornerShape(8.dp))
            .clickable(onClick = onClick)
            .testTag("side_$text")
            .padding(vertical = 10.dp),
        contentAlignment = Alignment.Center,
    ) {
        Text(text, color = if (selected) Color.Black else MarketColors.TextSecondary, fontWeight = FontWeight.Bold, fontSize = 14.sp)
    }
}

@Composable
private fun AccountStrip(account: com.testlogon.android.data.exchange.MarginAccount) {
    Column(modifier = Modifier.fillMaxWidth()) {
        WalletRow("Balance", account.balance)
        Spacer(Modifier.height(3.dp))
        WalletRow("Available", account.availableBalance)
        Spacer(Modifier.height(3.dp))
        WalletRow("Reserved margin", account.reservedMargin)
        Spacer(Modifier.height(6.dp))
        Row(modifier = Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Margin used", color = MarketColors.TextSecondary, fontSize = 11.sp)
            Text("${(account.marginUsedFraction * 100).toInt()}%", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        Spacer(Modifier.height(3.dp))
        Row(modifier = Modifier.fillMaxWidth().height(5.dp).clip(RoundedCornerShape(3.dp)).background(MarketColors.SurfaceAlt)) {
            val f = account.marginUsedFraction.coerceIn(0.001f, 1f)
            Box(modifier = Modifier.weight(f).fillMaxHeight().background(if (account.isLiquidating) MarketColors.Down else MarketColors.Accent))
            Box(modifier = Modifier.weight((1f - f).coerceAtLeast(0.001f)))
        }
        if (account.isLiquidating || account.distressLevel > 0) {
            Spacer(Modifier.height(4.dp))
            Text(
                text = if (account.isLiquidating) "⚠ Liquidating" else "⚠ Distress level ${account.distressLevel}",
                color = MarketColors.Down,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
            )
        }
    }
}

@Composable
private fun TifRow(selected: String, onSelect: (String) -> Unit) {
    Column(Modifier.fillMaxWidth()) {
        Text("Time in force", color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(3.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            listOf("GTC", "IOC", "FOK", "GTD").forEach { t ->
                val on = t == selected
                Text(
                    text = t,
                    color = if (on) Color.Black else MarketColors.TextSecondary,
                    fontWeight = FontWeight.Bold,
                    fontSize = 11.sp,
                    modifier = Modifier
                        .clip(RoundedCornerShape(6.dp))
                        .background(if (on) MarketColors.Accent else MarketColors.Surface)
                        .border(1.dp, if (on) MarketColors.Accent else MarketColors.Border, RoundedCornerShape(6.dp))
                        .clickable { onSelect(t) }
                        .testTag("tif_$t")
                        .padding(horizontal = 12.dp, vertical = 6.dp),
                )
            }
        }
    }
}

@Composable
private fun TogglePill(label: String, on: Boolean, onToggle: () -> Unit, tag: String) {
    Text(
        text = label,
        color = if (on) Color.Black else MarketColors.TextSecondary,
        fontWeight = FontWeight.Bold,
        fontSize = 11.sp,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(if (on) MarketColors.Accent else MarketColors.Surface)
            .border(1.dp, if (on) MarketColors.Accent else MarketColors.Border, RoundedCornerShape(6.dp))
            .clickable(onClick = onToggle)
            .testTag(tag)
            .padding(horizontal = 10.dp, vertical = 6.dp),
    )
}

@Composable
private fun AdvancedSection(state: TradingUiState, viewModel: TradingViewModel) {
    Spacer(Modifier.height(8.dp))
    Text(
        text = if (state.advancedOpen) "Advanced ▲" else "Advanced ▼",
        color = MarketColors.Accent,
        fontSize = 12.sp,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.clickable { viewModel.toggleAdvanced() }.testTag("advanced_toggle").padding(vertical = 4.dp),
    )
    if (state.advancedOpen) {
        Spacer(Modifier.height(6.dp))
        Row(
            modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            if (state.orderType == OrderType.LIMIT) {
                TogglePill("Post-only", state.postOnly, viewModel::togglePostOnly, "flag_post_only")
            }
            TogglePill("Hidden", state.hidden, viewModel::toggleHidden, "flag_hidden")
            TogglePill("AON", state.aon, viewModel::toggleAon, "flag_aon")
            TogglePill("1-tap", state.oneTap, viewModel::toggleOneTap, "flag_one_tap")
        }
        Spacer(Modifier.height(8.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.weight(1f)) { NumberField("Display qty (iceberg)", state.displayText, viewModel::setDisplayQty) }
            Box(Modifier.weight(1f)) { NumberField("Min qty", state.minQtyText, viewModel::setMinQty) }
        }
    }
}

@Composable
private fun OrderTypeRow(selected: OrderType, onSelect: (OrderType) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        OrderType.values().filter { it.isAvailable() }.forEach { t ->
            val on = t == selected
            Text(
                text = t.label,
                color = if (on) Color.Black else MarketColors.TextSecondary,
                fontWeight = FontWeight.Bold,
                fontSize = 12.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(if (on) MarketColors.Accent else MarketColors.Surface)
                    .border(1.dp, if (on) MarketColors.Accent else MarketColors.Border, RoundedCornerShape(8.dp))
                    .clickable { onSelect(t) }
                    .testTag("otype_${t.name}")
                    .padding(horizontal = 12.dp, vertical = 7.dp),
            )
        }
    }
}

@Composable
private fun OrderValueRow(value: Long?, available: Long?) {
    val exceeds = value != null && available != null && value > available
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text("Order value", color = MarketColors.TextSecondary, fontSize = 12.sp)
        Text(
            text = (value?.let { fmt(it.toDouble()) } ?: "--") + (available?.let { " · avail ${fmt(it.toDouble())}" } ?: ""),
            color = if (exceeds) MarketColors.Down else MarketColors.TextPrimary,
            fontFamily = FontFamily.Monospace,
            fontWeight = FontWeight.SemiBold,
            fontSize = 12.sp,
        )
    }
}

private fun submitLabel(state: TradingUiState): String {
    if (state.placing) return if (state.isAmending) "Amending…" else "Working…"
    if (state.isAmending) return "Amend order"
    val side = if (state.side == OrderSide.BUY) "Buy" else "Sell"
    return when (state.orderType) {
        OrderType.LIMIT -> "$side ${state.qtyText}".trim()
        OrderType.MARKET -> "$side ${state.qtyText} (market)".trim()
        OrderType.STOP -> "$side Stop"
        OrderType.STOP_LIMIT -> "$side Stop-Limit"
        OrderType.TAKE_PROFIT -> "$side Take-Profit"
        OrderType.QUOTE -> "Place quote"
        OrderType.OTO -> "Place OTO ($side parent)"
        OrderType.OCO -> "Place OCO ($side / ${if (state.side == OrderSide.BUY) "Sell" else "Buy"})"
        OrderType.FUNDING -> if (state.fundingBorrow) "Borrow" else "Lend"
    }
}

@Composable
private fun PmBanner(pm: com.testlogon.android.data.exchange.PmState, lastPrice: Long?) {
    val resolved = pm.resolved
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(if (resolved) MarketColors.SurfaceAlt else MarketColors.Surface)
            .border(1.dp, if (resolved) MarketColors.Border else MarketColors.Accent, RoundedCornerShape(10.dp))
            .padding(12.dp),
    ) {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("Prediction market", color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Text("payout ${fmt(pm.faceValue.toDouble())}", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
        Spacer(Modifier.height(6.dp))
        if (resolved) {
            val yesWon = pm.outcomeYes == true
            Text(
                text = "Resolved: ${if (yesWon) "YES" else "NO"} - " + if (yesWon) "YES pays ${fmt(pm.faceValue.toDouble())}" else "YES pays 0",
                color = if (yesWon) MarketColors.Up else MarketColors.Down,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                fontSize = 13.sp,
            )
        } else {
            val prob = pm.impliedYes(lastPrice)
            Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                Text("Implied YES", color = MarketColors.TextSecondary, fontSize = 11.sp)
                Text(prob?.let { "${(it * 100f).toInt()}%" } ?: "--", color = MarketColors.Up, fontFamily = FontFamily.Monospace, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            }
            Spacer(Modifier.height(4.dp))
            Row(modifier = Modifier.fillMaxWidth().height(6.dp).clip(RoundedCornerShape(3.dp)).background(MarketColors.Down.copy(alpha = 0.35f))) {
                val f = (prob ?: 0f).coerceIn(0.001f, 1f)
                Box(modifier = Modifier.weight(f).fillMaxHeight().background(MarketColors.Up))
                Box(modifier = Modifier.weight((1f - f).coerceAtLeast(0.001f)))
            }
            Spacer(Modifier.height(4.dp))
            Text(
                "Buy YES to bet it happens, Buy NO to bet against; each YES contract pays ${fmt(pm.faceValue.toDouble())} if it resolves YES.",
                color = MarketColors.TextFaint,
                fontSize = 10.sp,
            )
        }
    }
}

@Composable
private fun SpotPanel(state: TradingUiState, viewModel: TradingViewModel) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(12.dp),
    ) {
        Text("Spot balances", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        Spacer(Modifier.height(6.dp))
        val bal = state.spotBalance
        if (bal == null || bal.assets.isEmpty()) {
            Text("No spot balances", color = MarketColors.TextFaint, fontSize = 11.sp)
        } else {
            bal.assets.forEach { a ->
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
                    Text(if (a.symbol.isNotEmpty()) a.symbol else "asset ${a.asset}", color = MarketColors.TextSecondary, fontSize = 11.sp)
                    Text(fmt(a.balance.toDouble()), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
                }
            }
        }
        Spacer(Modifier.height(8.dp))
        Row(verticalAlignment = Alignment.Bottom, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            Box(Modifier.weight(1f)) { NumberField("Asset id", state.spotAssetText, viewModel::setSpotAsset) }
            Box(Modifier.weight(1f)) { NumberField("Amount", state.spotAmountText, viewModel::setSpotAmount) }
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(8.dp))
                    .background(MarketColors.Accent)
                    .clickable { viewModel.spotDeposit() }
                    .testTag("spot_deposit")
                    .padding(horizontal = 14.dp, vertical = 13.dp),
                contentAlignment = Alignment.Center,
            ) { Text("Deposit", color = Color.Black, fontWeight = FontWeight.Bold, fontSize = 12.sp) }
        }
    }
}

@Composable
private fun FundRow(
    value: String,
    canDeposit: Boolean,
    depositing: Boolean,
    onValue: (String) -> Unit,
    onDeposit: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        verticalAlignment = Alignment.Bottom,
        horizontalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        Box(modifier = Modifier.weight(1f)) {
            NumberField("Deposit collateral", value, onValue)
        }
        Box(
            modifier = Modifier
                .clip(RoundedCornerShape(8.dp))
                .background(if (canDeposit) MarketColors.Accent else MarketColors.SurfaceAlt)
                .clickable(enabled = canDeposit && !depositing, onClick = onDeposit)
                .testTag("trade_deposit")
                .padding(horizontal = 16.dp, vertical = 13.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (depositing) "…" else "Deposit",
                color = if (canDeposit) Color.Black else MarketColors.TextFaint,
                fontWeight = FontWeight.Bold,
                fontSize = 13.sp,
            )
        }
    }
}

@Composable
private fun NumberField(label: String, value: String, onValue: (String) -> Unit) {
    Column(modifier = Modifier.fillMaxWidth()) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(3.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(MarketColors.Surface)
                .border(1.dp, MarketColors.Border, RoundedCornerShape(8.dp))
                .padding(horizontal = 12.dp, vertical = 12.dp),
        ) {
            if (value.isEmpty()) {
                Text("0", color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 16.sp)
            }
            BasicTextField(
                value = value,
                onValueChange = onValue,
                singleLine = true,
                textStyle = TextStyle(color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 16.sp),
                cursorBrush = SolidColor(MarketColors.Accent),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                modifier = Modifier.fillMaxWidth().testTag("field_$label"),
            )
        }
    }
}

@Composable
private fun WorkingOrderRow(label: String, sideColor: Color, onAmend: () -> Unit, onCancel: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = sideColor, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            Text(
                text = "Amend",
                color = MarketColors.Accent,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
                    .clickable(onClick = onAmend)
                    .testTag("wo_amend")
                    .padding(horizontal = 10.dp, vertical = 5.dp),
            )
            Text(
                text = "Cancel",
                color = MarketColors.Down,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
                    .clickable(onClick = onCancel)
                    .testTag("wo_cancel")
                    .padding(horizontal = 10.dp, vertical = 5.dp),
            )
        }
    }
}

@Composable
private fun MarginConfigPanel(form: MarginConfigForm, viewModel: TradingViewModel) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(12.dp),
    ) {
        Text("Admin · Margin config", color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        Spacer(Modifier.height(2.dp))
        Text(
            "Per-symbol margin, fee and borrow parameters (basis points).",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(10.dp))
        NumberField("Symbol id", form.symbolText, viewModel::setMcSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Initial margin (bps)", form.initialMarginText, viewModel::setMcInitialMargin)
        Spacer(Modifier.height(8.dp))
        NumberField("Maintenance margin (bps)", form.maintenanceMarginText, viewModel::setMcMaintenanceMargin)
        Spacer(Modifier.height(8.dp))
        NumberField("Liquidation fee (bps)", form.liquidationFeeText, viewModel::setMcLiquidationFee)
        Spacer(Modifier.height(8.dp))
        NumberField("Hourly borrow rate (bps)", form.hourlyBorrowText, viewModel::setMcHourlyBorrow)
        Spacer(Modifier.height(8.dp))
        NumberField("Maker fee (bps)", form.makerFeeText, viewModel::setMcMakerFee)
        Spacer(Modifier.height(8.dp))
        NumberField("Taker fee (bps)", form.takerFeeText, viewModel::setMcTakerFee)
        Spacer(Modifier.height(8.dp))
        NumberField("Max position qty", form.maxPositionText, viewModel::setMcMaxPosition)
        Spacer(Modifier.height(12.dp))
        Text(
            text = if (form.submitting) "Applying…" else "Apply margin config",
            color = if (form.canSubmit) Color.Black else MarketColors.TextFaint,
            fontWeight = FontWeight.Bold,
            fontSize = 13.sp,
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(8.dp))
                .background(if (form.canSubmit) MarketColors.Accent else MarketColors.SurfaceAlt)
                .then(if (form.canSubmit) Modifier.clickable { viewModel.submitMarginConfig() } else Modifier)
                .testTag("apply_margin_config")
                .padding(vertical = 12.dp),
            textAlign = TextAlign.Center,
        )
        form.error?.let {
            Spacer(Modifier.height(8.dp))
            Text(it, color = MarketColors.Down, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
        form.result?.let { r ->
            Spacer(Modifier.height(8.dp))
            Text(
                text = if (r.applied) "Applied (result 0)" else (r.message ?: "Rejected (result ${r.result ?: "?"})"),
                color = if (r.applied) MarketColors.Up else MarketColors.Down,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
            )
            Spacer(Modifier.height(4.dp))
            Text(
                "Dismiss",
                color = MarketColors.TextSecondary,
                fontSize = 11.sp,
                modifier = Modifier.clickable { viewModel.clearMcResult() }.padding(vertical = 2.dp),
            )
        }
    }
}

private fun fmt(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong()) else String.format(Locale.US, "%,.2f", v)
}
