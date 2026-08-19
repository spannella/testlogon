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
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
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
import com.testlogon.android.data.exchange.EngineConfigAck
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
            ordersCount = state.ordersBadgeCount,
            posCount = if (state.account?.position != null) 1 else 0,
            fillsCount = state.fillsFees?.fills?.size?.takeIf { it > 0 } ?: state.sessionFills.size,
            onSelect = viewModel::setSection,
        )
        Spacer(Modifier.height(12.dp))

        when (state.section) {
            TicketSection.TRADE -> TradeSection(state, lastPrice, viewModel)
            TicketSection.POSITIONS -> PositionsSection(state, lastPrice, viewModel)
            TicketSection.ORDERS -> OrdersSection(state, viewModel)
            TicketSection.FILLS -> FillsSection(state)
            TicketSection.LIQUIDATIONS -> LiquidationsSection(state)
            TicketSection.FUNDING -> FundingSection(state)
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
            Spacer(Modifier.height(16.dp))
            EngineConfigSection(state, viewModel)
            Spacer(Modifier.height(16.dp))
            PmAdminSection(state, viewModel)
        }
    }
}

// ======================= Sections =======================

@Composable
private fun TradeSection(state: TradingUiState, lastPrice: Long?, viewModel: TradingViewModel) {
    val sideColor = if (state.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down
    var showDepositConfirm by remember { mutableStateOf(false) }

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
        onDeposit = { if (state.canDeposit) showDepositConfirm = true },
    )

    if (showDepositConfirm) {
        AlertDialog(
            onDismissRequest = { showDepositConfirm = false },
            title = { Text("Confirm deposit") },
            text = {
                Column {
                    ConfirmLine("Action", "Deposit collateral")
                    ConfirmLine("Amount", state.depositText.ifBlank { "0" })
                    state.account?.let { ConfirmLine("Current balance", fmt(it.balance.toDouble())) }
                    Spacer(Modifier.height(6.dp))
                    Text(
                        "Funds move from your wallet into the margin account and become available for trading.",
                        color = MarketColors.TextSecondary,
                        fontSize = 11.sp,
                    )
                }
            },
            confirmButton = {
                TextButton(onClick = {
                    showDepositConfirm = false
                    viewModel.deposit()
                }, modifier = Modifier.testTag("trade_deposit_confirm")) { Text("Confirm") }
            },
            dismissButton = { TextButton(onClick = { showDepositConfirm = false }) { Text("Cancel") } },
        )
    }
    if (TradingFeatures.SPOT_ENABLED) {
        Spacer(Modifier.height(10.dp))
        SpotPanel(state, viewModel)
    }

    Spacer(Modifier.height(20.dp))
    StakingAuctionsSection(state, viewModel)
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
    // Prefer the LIVE server feed (survives restarts + includes quote/OTO legs); the ViewModel falls
    // back to the session-tracked list when the /me/orders/live read is unavailable/undeployed.
    val orders = state.displayOrders
    val live = state.liveOrders?.orders?.isNotEmpty() == true

    Row(
        modifier = Modifier.fillMaxWidth().padding(bottom = 6.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(
            text = if (live) "Working orders (live)" else "Working orders (this session)",
            color = MarketColors.TextSecondary,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
        )
        Text(
            text = "Refresh",
            color = MarketColors.Accent,
            fontFamily = FontFamily.Monospace,
            fontSize = 11.sp,
            modifier = Modifier
                .clip(RoundedCornerShape(6.dp))
                .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
                .clickable { viewModel.refreshOrdersLive() }
                .testTag("orders_refresh")
                .padding(horizontal = 10.dp, vertical = 4.dp),
        )
    }
    if (orders.isEmpty()) {
        EmptyHint(if (live) "No working orders" else "No resting orders this session")
    } else {
        orders.forEach { wo ->
            val sideLabel = when (wo.side) { OrderSide.BUY -> "Buy"; OrderSide.SELL -> "Sell" }
            WorkingOrderRow(
                label = "$sideLabel  ${fmt(wo.qty.toDouble())} @ ${fmt(wo.price.toDouble())}",
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
    state.feeSchedule?.let {
        FeeScheduleCard(it)
        Spacer(Modifier.height(10.dp))
    }
    // Prefer the REAL enriched feed (engine-charged fee + maker/taker liquidity); fall back to this
    // session's own fills (fee unknown) only when the feed is empty/undeployed.
    val feed = state.fillsFees?.fills.orEmpty()
    if (feed.isNotEmpty()) {
        Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
            Text("Sym", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
            Text("Price", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.2f))
            Text("Qty", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.8f))
            Text("Liq", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.7f))
            Text("Fee", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.9f))
            Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        }
        feed.take(60).forEach { f -> FillFeeRow(f, state.symbolLabel(f.symbolId)) }
        return
    }
    if (state.sessionFills.isEmpty()) {
        EmptyHint("No fills this session")
        return
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("Price", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.2f))
        Text("Qty", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
    }
    state.sessionFills.take(60).forEach { f -> SessionFillRow(f) }
    Spacer(Modifier.height(6.dp))
    Text(
        "Per-fill fees appear here from the engine feed once it reports them.",
        color = MarketColors.TextFaint,
        fontFamily = FontFamily.Monospace,
        fontSize = 10.sp,
    )
}
/**
 * Fee schedule card (GET /me/fees/schedule?symbolid=<n>). A small source marker shows whether these are
 * the engine-configured rates or the venue defaults, so the rate is read correctly.
 */
@Composable
private fun FeeScheduleCard(fee: com.testlogon.android.data.exchange.FeeSchedule) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MarketColors.SurfaceAlt)
            .padding(12.dp)
            .testTag("fee_schedule_card"),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text("Fee schedule", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp, modifier = Modifier.weight(1f))
            Box(
                modifier = Modifier
                    .clip(RoundedCornerShape(50))
                    .background(MarketColors.Surface)
                    .padding(horizontal = 8.dp, vertical = 2.dp),
            ) {
                Text(fee.sourceLabel, color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 10.sp)
            }
        }
        Spacer(Modifier.height(8.dp))
        FeeRow("Maker", fee.makerPct(), fee.makerFeeBps)
        FeeRow("Taker", fee.takerPct(), fee.takerFeeBps)
        FeeRow("Liquidation", fee.liquidationPct(), fee.liquidationFeeBps)
    }
}

@Composable
private fun FeeRow(label: String, pct: String, bps: Int) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(label, color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(pct, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text("$bps bps", color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

@Composable
private fun EmptyHint(text: String) {
    Text(text, color = MarketColors.TextFaint, fontSize = 12.sp, modifier = Modifier.padding(vertical = 8.dp))
}

// ======================= Building blocks =======================

@Composable
private fun SectionTabs(section: TicketSection, ordersCount: Int, posCount: Int, fillsCount: Int, onSelect: (TicketSection) -> Unit) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(MarketColors.SurfaceAlt)
            .horizontalScroll(rememberScrollState())
            .padding(3.dp),
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
                    .clip(RoundedCornerShape(6.dp))
                    .background(if (on) MarketColors.Surface else Color.Transparent)
                    .clickable { onSelect(s) }
                    .testTag("section_${s.name}")
                    .padding(horizontal = 12.dp, vertical = 8.dp),
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

/** Format an int64 nanosecond timestamp at the domain edge, matching the session-fill formatting. */
private fun fmtTsNs(tsNs: Long): String =
    if (tsNs > 0) fillTimeFmt.format(java.util.Date(tsNs / 1_000_000L)) else "--"

/** One REAL enriched fill: symbol, price, qty, maker/taker liquidity, engine fee, time. */
@Composable
private fun FillFeeRow(fill: com.testlogon.android.data.exchange.FillFee, symbol: String) {
    val color = when (fill.side) {
        OrderSide.BUY -> MarketColors.Up
        OrderSide.SELL -> MarketColors.Down
        null -> MarketColors.TextPrimary
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(symbol, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Text(fmt(fill.price.toDouble()), color = color, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1.2f))
        Text(fill.qty.toString(), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(0.8f))
        Text(fill.liquidity.label, color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.7f))
        Text(fmt(fill.fee.toDouble()), color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(0.9f))
        Text(fmtTsNs(fill.tsNs), color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

/** A this-session fill (no server fee available); shown only when the enriched feed is empty. */
@Composable
private fun SessionFillRow(fill: com.testlogon.android.data.exchange.Fill) {
    val color = when (fill.side) {
        OrderSide.BUY -> MarketColors.Up
        OrderSide.SELL -> MarketColors.Down
        null -> MarketColors.TextPrimary
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(fmt(fill.price.toDouble()), color = color, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1.2f))
        Text(fill.qty.toString(), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(fmtTsNs(fill.tsNs), color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

// ======================= Liquidations (me/liquidations) =======================

@Composable
private fun LiquidationsSection(state: TradingUiState) {
    val events = state.liquidations?.events.orEmpty()
    if (events.isEmpty()) {
        EmptyHint("No liquidations")
        return
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("Sym", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Qty", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.9f))
        Text("Mark", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.1f))
        Text("PnL", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Fee", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.8f))
        Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
    }
    events.take(60).forEach { e -> LiquidationRow(e, state.symbolLabel(e.symbolId)) }
}

@Composable
private fun LiquidationRow(e: com.testlogon.android.data.exchange.Liquidation, symbol: String) {
    val pnlColor = if (e.realizedPnl >= 0) MarketColors.Up else MarketColors.Down
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(symbol, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Text(e.qty.toString(), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(0.9f))
        Text(fmt(e.markPrice.toDouble()), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1.1f))
        Text(fmtSigned(e.realizedPnl), color = pnlColor, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(fmt(e.fee.toDouble()), color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(0.8f))
        Text(fmtTsNs(e.tsNs), color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

// ======================= Funding (me/funding/payments) =======================

@Composable
private fun FundingSection(state: TradingUiState) {
    val payments = state.fundingPayments?.payments.orEmpty()
    if (payments.isEmpty()) {
        EmptyHint("No funding payments")
        return
    }
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
        Text("Sym", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Rate", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.9f))
        Text("Mark", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.1f))
        Text("Pos", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.9f))
        Text("Pay", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
        Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
    }
    payments.take(60).forEach { fp -> FundingRow(fp, state.symbolLabel(fp.symbolId)) }
}

@Composable
private fun FundingRow(fp: com.testlogon.android.data.exchange.FundingPayment, symbol: String) {
    // received (positive) is green, paid (negative) is red.
    val payColor = if (fp.received || fp.payment > 0) MarketColors.Up else MarketColors.Down
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 1.dp)) {
        Text(symbol, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, maxLines = 1, modifier = Modifier.weight(1f))
        Text("${fp.fundingRateBps} bps", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(0.9f))
        Text(fmt(fp.markPrice.toDouble()), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1.1f))
        Text(fp.positionQty.toString(), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(0.9f))
        Text(fmtSigned(fp.payment), color = payColor, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
        Text(fmtTsNs(fp.tsNs), color = MarketColors.TextFaint, fontFamily = FontFamily.Monospace, fontSize = 12.sp, modifier = Modifier.weight(1f))
    }
}

/** Signed integer formatting for PnL / funding payments (keeps a leading + on positives). */
private fun fmtSigned(v: Long): String {
    val body = fmt(kotlin.math.abs(v).toDouble())
    return when {
        v > 0 -> "+" + body
        v < 0 -> "-" + body
        else -> body
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
private fun ConfirmLine(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 12.sp)
        Text(value, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
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

// ======================= Admin engine-config (exchange-admin-config) =======================

/**
 * Admin-only "Engine config" section: six compact forms mirroring [MarginConfigPanel], one per engine
 * config route. Each is a bordered card with labeled integer inputs, defaults, a validated Apply button,
 * and inline ack/error feedback. Shown only when [TradingUiState.isAdmin]. Endpoints 404 until deployed
 * -> the repository degrades to an un-applied ack surfaced here.
 */
@Composable
private fun EngineConfigSection(state: TradingUiState, viewModel: TradingViewModel) {
    Column(modifier = Modifier.fillMaxWidth().testTag("engine_config_section")) {
        Text("Engine config (admin)", color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        Spacer(Modifier.height(2.dp))
        Text(
            "Matching-engine parameters. Not deployed to every venue; an undeployed route reports \"not deployed\".",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(10.dp))
        MatchingAlgoPanel(state.matchingAlgo, viewModel)
        Spacer(Modifier.height(12.dp))
        SpreadConfigPanel(state.spreadConfig, viewModel)
        Spacer(Modifier.height(12.dp))
        TradingParamsPanel(state.tradingParams, viewModel)
        Spacer(Modifier.height(12.dp))
        RiskConfigPanel(state.riskConfig, viewModel)
        Spacer(Modifier.height(12.dp))
        SpotIndexPanel(state.spotIndex, viewModel)
        Spacer(Modifier.height(12.dp))
        SpotConfigPanel(state.spotConfig, viewModel)
    }
}

/** Bordered card wrapper shared by every engine-config form (matches MarginConfigPanel styling). */
@Composable
private fun EngineCard(title: String, subtitle: String, content: @Composable () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(10.dp))
            .background(MarketColors.Surface)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(10.dp))
            .padding(12.dp),
    ) {
        Text(title, color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        Spacer(Modifier.height(2.dp))
        Text(subtitle, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(10.dp))
        content()
    }
}

/** Apply button + inline error/ack feedback, shared by every engine-config form. */
@Composable
private fun EngineApply(
    label: String,
    canSubmit: Boolean,
    submitting: Boolean,
    error: String?,
    result: EngineConfigAck?,
    testTag: String,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    Spacer(Modifier.height(12.dp))
    Text(
        text = if (submitting) "Applying…" else label,
        color = if (canSubmit) Color.Black else MarketColors.TextFaint,
        fontWeight = FontWeight.Bold,
        fontSize = 13.sp,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(if (canSubmit) MarketColors.Accent else MarketColors.SurfaceAlt)
            .then(if (canSubmit) Modifier.clickable { onSubmit() } else Modifier)
            .testTag(testTag)
            .padding(vertical = 12.dp),
        textAlign = TextAlign.Center,
    )
    error?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, color = MarketColors.Down, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
    result?.let { r ->
        Spacer(Modifier.height(8.dp))
        Text(
            text = if (r.applied) "Applied (result ${r.result ?: 0})" else (r.message ?: "Rejected (result ${r.result ?: "?"})"),
            color = if (r.applied) MarketColors.Up else MarketColors.Down,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Dismiss",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
            modifier = Modifier.clickable { onDismiss() }.padding(vertical = 2.dp),
        )
    }
}

@Composable
private fun MatchingAlgoPanel(form: MatchingAlgoForm, viewModel: TradingViewModel) {
    EngineCard("Matching algorithm", "Order-allocation model for a symbol.") {
        NumberField("Symbol id", form.symbolText, viewModel::setAlgoSymbol)
        Spacer(Modifier.height(8.dp))
        Text("Algorithm", color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            AlgoChip("Price-time", form.algo == 0) { viewModel.setAlgo(0) }
            AlgoChip("Pro-rata", form.algo == 1) { viewModel.setAlgo(1) }
            AlgoChip("Specialist", form.algo == 2) { viewModel.setAlgo(2) }
        }
        if (form.algo >= 2) {
            Spacer(Modifier.height(8.dp))
            TextInputField("Specialist MPID", form.specialistMpidText, viewModel::setAlgoSpecialistMpid)
            Spacer(Modifier.height(8.dp))
            NumberField("Specialist %", form.specialistPctText, viewModel::setAlgoSpecialistPct)
        }
        EngineApply(
            label = "Apply matching algo",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_matching_algo",
            onSubmit = viewModel::submitMatchingAlgo,
            onDismiss = viewModel::clearAlgoResult,
        )
    }
}

@Composable
private fun AlgoChip(label: String, selected: Boolean, onClick: () -> Unit) {
    Text(
        text = label,
        color = if (selected) Color.Black else MarketColors.TextSecondary,
        fontSize = 12.sp,
        fontWeight = if (selected) FontWeight.Bold else FontWeight.Normal,
        modifier = Modifier
            .clip(RoundedCornerShape(6.dp))
            .background(if (selected) MarketColors.Accent else MarketColors.SurfaceAlt)
            .border(1.dp, MarketColors.Border, RoundedCornerShape(6.dp))
            .clickable(onClick = onClick)
            .testTag("algo_$label")
            .padding(horizontal = 10.dp, vertical = 6.dp),
    )
}

@Composable
private fun SpreadConfigPanel(form: SpreadConfigForm, viewModel: TradingViewModel) {
    EngineCard("Spread instrument", "Two-leg spread (signed ratios; e.g. 1 / -1).") {
        NumberField("Spread symbol id", form.spreadSymbolText, viewModel::setSpreadSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Leg 1 symbol id", form.leg1Text, viewModel::setSpreadLeg1)
        Spacer(Modifier.height(8.dp))
        NumberField("Leg 2 symbol id", form.leg2Text, viewModel::setSpreadLeg2)
        Spacer(Modifier.height(8.dp))
        TextInputField("Leg 1 ratio", form.leg1RatioText, viewModel::setSpreadLeg1Ratio)
        Spacer(Modifier.height(8.dp))
        TextInputField("Leg 2 ratio", form.leg2RatioText, viewModel::setSpreadLeg2Ratio)
        EngineApply(
            label = "Apply spread config",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_spread_config",
            onSubmit = viewModel::submitSpreadConfig,
            onDismiss = viewModel::clearSpreadResult,
        )
    }
}

@Composable
private fun TradingParamsPanel(form: TradingParamsForm, viewModel: TradingViewModel) {
    EngineCard("Trading params", "Per-symbol risk limits (leave blank to skip a param).") {
        NumberField("Symbol id", form.symbolText, viewModel::setTpSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Max qty", form.maxQtyText, viewModel::setTpMaxQty)
        Spacer(Modifier.height(8.dp))
        NumberField("Max notional", form.maxNotionalText, viewModel::setTpMaxNotional)
        Spacer(Modifier.height(8.dp))
        NumberField("Price band %", form.priceBandPctText, viewModel::setTpPriceBand)
        Spacer(Modifier.height(8.dp))
        NumberField("Circuit breaker %", form.circuitBreakerPctText, viewModel::setTpCircuitBreaker)
        Spacer(Modifier.height(8.dp))
        NumberField("Min block size", form.minBlockSizeText, viewModel::setTpMinBlock)
        EngineApply(
            label = "Apply trading params",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_trading_params",
            onSubmit = viewModel::submitTradingParams,
            onDismiss = viewModel::clearTpResult,
        )
    }
}

@Composable
private fun RiskConfigPanel(form: RiskConfigForm, viewModel: TradingViewModel) {
    EngineCard("Risk config", "Aggregate notional cap over a rolling window.") {
        NumberField("Max notional", form.maxNotionalText, viewModel::setRiskMaxNotional)
        Spacer(Modifier.height(8.dp))
        NumberField("Window seconds", form.windowSecondsText, viewModel::setRiskWindow)
        Spacer(Modifier.height(8.dp))
        TextInputField("MPID (optional)", form.mpidText, viewModel::setRiskMpid)
        EngineApply(
            label = "Apply risk config",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_risk_config",
            onSubmit = viewModel::submitRiskConfig,
            onDismiss = viewModel::clearRiskResult,
        )
    }
}

@Composable
private fun SpotIndexPanel(form: SpotIndexForm, viewModel: TradingViewModel) {
    EngineCard("Spot index", "Publish a spot index (mark) price.") {
        NumberField("Symbol id", form.symbolText, viewModel::setSpotIndexSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Spot index price", form.spotIndexPriceText, viewModel::setSpotIndexPrice)
        EngineApply(
            label = "Apply spot index",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_spot_index",
            onSubmit = viewModel::submitSpotIndex,
            onDismiss = viewModel::clearSpotIndexResult,
        )
    }
}

@Composable
private fun SpotConfigPanel(form: SpotConfigForm, viewModel: TradingViewModel) {
    EngineCard("Spot config", "Bind a symbol to its base/quote asset ids.") {
        NumberField("Symbol id", form.symbolText, viewModel::setSpotCfgSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Base asset id", form.baseAssetText, viewModel::setSpotCfgBase)
        Spacer(Modifier.height(8.dp))
        NumberField("Quote asset id", form.quoteAssetText, viewModel::setSpotCfgQuote)
        EngineApply(
            label = "Apply spot config",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_spot_config",
            onSubmit = viewModel::submitSpotConfig,
            onDismiss = viewModel::clearSpotCfgResult,
        )
    }
}

/** Like [NumberField] but accepts free text (for signed ratios / alphanumeric MPIDs). */
@Composable
private fun TextInputField(label: String, value: String, onValue: (String) -> Unit) {
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
            BasicTextField(
                value = value,
                onValueChange = onValue,
                singleLine = true,
                textStyle = TextStyle(color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 16.sp),
                cursorBrush = SolidColor(MarketColors.Accent),
                modifier = Modifier.fillMaxWidth().testTag("field_$label"),
            )
        }
    }
}


/**
 * Admin prediction-markets section (exchange-admin-config). Compact create/resolve forms for binary +
 * categorical PMs plus a resolution-history list. isAdmin-gated by the caller. Endpoints 404 until
 * deployed -> the repository degrades to an un-applied ack surfaced inline; a 403 on resolve (caller is
 * not the designated resolver) is surfaced as the engine's error message.
 */
@Composable
private fun PmAdminSection(state: TradingUiState, viewModel: TradingViewModel) {
    Column(modifier = Modifier.fillMaxWidth().testTag("pm_admin_section")) {
        Text("Prediction markets (admin)", color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        Spacer(Modifier.height(2.dp))
        Text(
            "Configure and resolve prediction markets. Resolving requires the designated resolver (else 403).",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(10.dp))
        PmCreateBinaryPanel(state.pmCreateBinary, viewModel)
        Spacer(Modifier.height(12.dp))
        PmCreateCategoricalPanel(state.pmCreateCategorical, viewModel)
        Spacer(Modifier.height(12.dp))
        PmResolveBinaryPanel(state.pmResolveBinary, viewModel)
        Spacer(Modifier.height(12.dp))
        PmResolveCategoricalPanel(state.pmResolveCategorical, viewModel)
        Spacer(Modifier.height(12.dp))
        PmResolutionHistory(state.pmResolutions, viewModel)
    }
}

/** Apply button + inline error/ack feedback for the PM admin forms (mirrors [EngineApply]). */
@Composable
private fun PmApply(
    label: String,
    canSubmit: Boolean,
    submitting: Boolean,
    error: String?,
    result: com.testlogon.android.data.exchange.PmConfigAck?,
    testTag: String,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    Spacer(Modifier.height(12.dp))
    Text(
        text = if (submitting) "Applying" else label,
        color = if (canSubmit) Color.Black else MarketColors.TextFaint,
        fontWeight = FontWeight.Bold,
        fontSize = 13.sp,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(if (canSubmit) MarketColors.Accent else MarketColors.SurfaceAlt)
            .then(if (canSubmit) Modifier.clickable { onSubmit() } else Modifier)
            .testTag(testTag)
            .padding(vertical = 12.dp),
        textAlign = TextAlign.Center,
    )
    error?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, color = MarketColors.Down, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
    result?.let { r ->
        Spacer(Modifier.height(8.dp))
        Text(
            text = if (r.applied) "Applied (result ${r.result ?: 0})" else (r.message ?: "Rejected (result ${r.result ?: "?"})"),
            color = if (r.applied) MarketColors.Up else MarketColors.Down,
            fontFamily = FontFamily.Monospace,
            fontSize = 12.sp,
        )
        Spacer(Modifier.height(4.dp))
        Text(
            "Dismiss",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
            modifier = Modifier.clickable { onDismiss() }.padding(vertical = 2.dp),
        )
    }
}

@Composable
private fun PmCreateBinaryPanel(form: PmCreateBinaryForm, viewModel: TradingViewModel) {
    EngineCard("Create binary market", "YES pays the face value on YES; face value must be > 1.") {
        NumberField("Symbol id", form.symbolText, viewModel::setPmBinSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Face value (payout)", form.faceText, viewModel::setPmBinFace)
        Spacer(Modifier.height(8.dp))
        TextInputField("Resolver id (optional)", form.resolverText, viewModel::setPmBinResolver)
        PmApply(
            label = "Create binary market",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_pm_create_binary",
            onSubmit = viewModel::submitPmCreateBinary,
            onDismiss = viewModel::clearPmBinResult,
        )
    }
}

@Composable
private fun PmCreateCategoricalPanel(form: PmCreateCategoricalForm, viewModel: TradingViewModel) {
    EngineCard("Create categorical market", "A group of >= 2 mutually-exclusive outcome symbols.") {
        NumberField("Group id", form.groupText, viewModel::setPmCatGroup)
        Spacer(Modifier.height(8.dp))
        TextInputField("Outcome symbol ids (comma-separated)", form.outcomesText, viewModel::setPmCatOutcomes)
        Spacer(Modifier.height(4.dp))
        Text("${form.outcomes.size} outcome(s): ${form.outcomes.joinToString(", ")}", color = MarketColors.TextFaint, fontSize = 10.sp)
        Spacer(Modifier.height(8.dp))
        NumberField("Face value (payout)", form.faceText, viewModel::setPmCatFace)
        Spacer(Modifier.height(8.dp))
        TextInputField("Resolver id (optional)", form.resolverText, viewModel::setPmCatResolver)
        PmApply(
            label = "Create categorical market",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_pm_create_categorical",
            onSubmit = viewModel::submitPmCreateCategorical,
            onDismiss = viewModel::clearPmCatResult,
        )
    }
}

@Composable
private fun PmResolveBinaryPanel(form: PmResolveBinaryForm, viewModel: TradingViewModel) {
    EngineCard("Resolve binary market", "Settle a binary PM. Requires the designated resolver.") {
        NumberField("Symbol id", form.symbolText, viewModel::setPmResolveSymbol)
        Spacer(Modifier.height(8.dp))
        Text("Outcome", color = MarketColors.TextSecondary, fontSize = 11.sp)
        Spacer(Modifier.height(4.dp))
        Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            AlgoChip("YES", form.yes) { viewModel.setPmResolveYes(true) }
            AlgoChip("NO", !form.yes) { viewModel.setPmResolveYes(false) }
        }
        Spacer(Modifier.height(8.dp))
        TextInputField("Source (optional)", form.sourceText, viewModel::setPmResolveSource)
        PmApply(
            label = "Resolve ${form.outcome.uppercase()}",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_pm_resolve_binary",
            onSubmit = viewModel::submitPmResolveBinary,
            onDismiss = viewModel::clearPmResolveResult,
        )
    }
}

@Composable
private fun PmResolveCategoricalPanel(form: PmResolveCategoricalForm, viewModel: TradingViewModel) {
    EngineCard("Resolve categorical market", "Settle a group to its winning outcome symbol.") {
        NumberField("Group id", form.groupText, viewModel::setPmGroupResolveGroup)
        Spacer(Modifier.height(8.dp))
        NumberField("Winning symbol id", form.winningText, viewModel::setPmGroupResolveWinning)
        Spacer(Modifier.height(8.dp))
        TextInputField("Source (optional)", form.sourceText, viewModel::setPmGroupResolveSource)
        PmApply(
            label = "Resolve group",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "apply_pm_resolve_categorical",
            onSubmit = viewModel::submitPmResolveCategorical,
            onDismiss = viewModel::clearPmGroupResolveResult,
        )
    }
}

@Composable
private fun PmResolutionHistory(resolutions: List<com.testlogon.android.data.exchange.PmResolution>, viewModel: TradingViewModel) {
    EngineCard("Resolution history", "The most recent PM resolutions (audit log).") {
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
            Text("${resolutions.size} resolution(s)", color = MarketColors.TextSecondary, fontSize = 11.sp)
            Text(
                "Refresh",
                color = MarketColors.Accent,
                fontSize = 11.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.clickable { viewModel.loadPmResolutions() }.testTag("pm_resolutions_refresh").padding(vertical = 2.dp),
            )
        }
        if (resolutions.isEmpty()) {
            Spacer(Modifier.height(8.dp))
            Text("No resolutions yet.", color = MarketColors.TextFaint, fontSize = 11.sp)
        } else {
            resolutions.take(20).forEach { r ->
                Spacer(Modifier.height(8.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween, verticalAlignment = Alignment.CenterVertically) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            "${r.marketLabel} -> ${r.outcomeLabel}",
                            color = MarketColors.TextPrimary,
                            fontFamily = FontFamily.Monospace,
                            fontWeight = FontWeight.Bold,
                            fontSize = 12.sp,
                        )
                        val meta = listOfNotNull(
                            r.resolverId.takeIf { it.isNotBlank() }?.let { "by $it" },
                            r.source.takeIf { it.isNotBlank() }?.let { "src $it" },
                        ).joinToString(" · ")
                        if (meta.isNotBlank()) {
                            Text(meta, color = MarketColors.TextFaint, fontSize = 10.sp)
                        }
                    }
                    Text(
                        if (r.isGroup) "GROUP" else (r.outcome?.uppercase() ?: "--"),
                        color = when {
                            r.isGroup -> MarketColors.Accent
                            r.outcomeYes == true -> MarketColors.Up
                            r.outcomeYes == false -> MarketColors.Down
                            else -> MarketColors.TextSecondary
                        },
                        fontFamily = FontFamily.Monospace,
                        fontSize = 11.sp,
                    )
                }
            }
        }
    }
}

/**
 * Trader-facing Staking & Auctions section (peer mechanisms). NOT admin-gated. Four compact forms:
 * create a stake request, offer on an open request (by id), auction a position qty, and bid on an
 * auction (by id). Each surfaces the engine's returned request_id / auction_id prominently. There is
 * no list/GET for open items yet, so an honest "browsing open items isn't available yet" note is shown;
 * the routes 404 until deployed -> the repository degrades to an un-applied ack surfaced inline.
 */
@Composable
private fun StakingAuctionsSection(state: TradingUiState, viewModel: TradingViewModel) {
    Column(modifier = Modifier.fillMaxWidth().testTag("staking_auctions_section")) {
        Text("Staking & auctions", color = MarketColors.Accent, fontWeight = FontWeight.Bold, fontSize = 14.sp)
        Spacer(Modifier.height(2.dp))
        Text(
            "Peer mechanisms: stake against another trader's request, or auction a position. Browse open " +
                "requests/auctions below (read-only preview), or act on an id you already have — create one " +
                "and share the id it returns.",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
        )
        Spacer(Modifier.height(10.dp))
        BrowseOpenStakeRequests(state.stakeRequestsBrowse)
        Spacer(Modifier.height(12.dp))
        BrowseOpenAuctions(state.auctionsBrowse)
        Spacer(Modifier.height(12.dp))
        StakeRequestPanel(state.stakeRequest, viewModel)
        Spacer(Modifier.height(12.dp))
        StakeOfferPanel(state.stakeOffer, viewModel)
        Spacer(Modifier.height(12.dp))
        AuctionRequestPanel(state.auctionRequest, viewModel)
        Spacer(Modifier.height(12.dp))
        AuctionBidPanel(state.auctionBid, viewModel)
    }
}

/**
 * Browse-open (read) subsection for open stake requests. STUB today: the backend returns an empty list
 * plus a human note, so an honest empty state from [StakeRequestsBrowse.note] is rendered; when real
 * rows arrive they render as compact cards. Keeps the action forms below unchanged.
 */
@Composable
private fun BrowseOpenStakeRequests(browse: com.testlogon.android.data.exchange.StakeRequestsBrowse?) {
    EngineCard("Browse open stake requests", "Open requests you can stake against.") {
        when {
            browse == null -> Text("Loading...", color = MarketColors.TextSecondary, fontSize = 12.sp)
            browse.isEmpty -> Text(
                browse.note ?: if (browse.unavailable) "Browsing open requests isn't available yet." else "No open stake requests right now.",
                color = MarketColors.TextSecondary,
                fontSize = 12.sp,
            )
            else -> Column(modifier = Modifier.fillMaxWidth()) {
                browse.items.forEach { item ->
                    BrowseRow(
                        title = item.idLabel,
                        subtitle = listOfNotNull(
                            item.symbolLabel,
                            item.minCollateral?.let { "min $it" },
                            item.maxStakePct?.let { "<= $it%" },
                            item.status,
                        ).joinToString("  -  "),
                    )
                }
            }
        }
    }
}

/**
 * Browse-open (read) subsection for open auctions. STUB today (empty + note); renders rows when present.
 */
@Composable
private fun BrowseOpenAuctions(browse: com.testlogon.android.data.exchange.AuctionsBrowse?) {
    EngineCard("Browse open auctions", "Open auctions you can bid on.") {
        when {
            browse == null -> Text("Loading...", color = MarketColors.TextSecondary, fontSize = 12.sp)
            browse.isEmpty -> Text(
                browse.note ?: if (browse.unavailable) "Browsing open auctions isn't available yet." else "No open auctions right now.",
                color = MarketColors.TextSecondary,
                fontSize = 12.sp,
            )
            else -> Column(modifier = Modifier.fillMaxWidth()) {
                browse.items.forEach { item ->
                    BrowseRow(
                        title = item.idLabel,
                        subtitle = listOfNotNull(
                            item.symbolLabel,
                            item.qty?.let { "qty $it" },
                            item.reservePrice?.let { "reserve $it" },
                            item.status,
                        ).joinToString("  -  "),
                    )
                }
            }
        }
    }
}

/** One compact browse row: a bold id label + a monospace subtitle line. */
@Composable
private fun BrowseRow(title: String, subtitle: String) {
    Column(modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp)) {
        Text(title, color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
        if (subtitle.isNotBlank()) {
            Text(subtitle, color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp)
        }
    }
}

/**
 * Apply button + inline feedback for a staking/auction form. On accept it surfaces the created id
 * ([StakeAuctionAck.idLabel]) prominently so the trader can copy/share it (there's no list view yet).
 */
@Composable
private fun StakeApply(
    label: String,
    canSubmit: Boolean,
    submitting: Boolean,
    error: String?,
    result: com.testlogon.android.data.exchange.StakeAuctionAck?,
    testTag: String,
    onSubmit: () -> Unit,
    onDismiss: () -> Unit,
) {
    Spacer(Modifier.height(12.dp))
    Text(
        text = if (submitting) "Submitting…" else label,
        color = if (canSubmit) Color.Black else MarketColors.TextFaint,
        fontWeight = FontWeight.Bold,
        fontSize = 13.sp,
        modifier = Modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(8.dp))
            .background(if (canSubmit) MarketColors.Accent else MarketColors.SurfaceAlt)
            .then(if (canSubmit) Modifier.clickable { onSubmit() } else Modifier)
            .testTag(testTag)
            .padding(vertical = 12.dp),
        textAlign = TextAlign.Center,
    )
    error?.let {
        Spacer(Modifier.height(8.dp))
        Text(it, color = MarketColors.Down, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
    }
    result?.let { r ->
        Spacer(Modifier.height(8.dp))
        if (r.accepted) {
            r.idLabel?.let { idLabel ->
                Text(
                    text = idLabel,
                    color = Color.Black,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Bold,
                    fontSize = 15.sp,
                    modifier = Modifier
                        .fillMaxWidth()
                        .clip(RoundedCornerShape(8.dp))
                        .background(MarketColors.Up)
                        .testTag(testTag + "_id")
                        .padding(vertical = 10.dp),
                    textAlign = TextAlign.Center,
                )
                Spacer(Modifier.height(4.dp))
            }
            Text(
                text = if (r.idLabel != null) "Accepted — save this id (no open-items list yet)." else "Accepted.",
                color = MarketColors.Up,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
            )
        } else {
            Text(
                text = r.message ?: "Rejected",
                color = MarketColors.Down,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
            )
        }
        Spacer(Modifier.height(4.dp))
        Text(
            "Dismiss",
            color = MarketColors.TextSecondary,
            fontSize = 11.sp,
            modifier = Modifier.clickable { onDismiss() }.padding(vertical = 2.dp),
        )
    }
}

@Composable
private fun StakeRequestPanel(form: StakeRequestForm, viewModel: TradingViewModel) {
    EngineCard("Create stake request", "Invite others to stake against your position.") {
        NumberField("Symbol id (optional)", form.symbolText, viewModel::setStakeReqSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Min collateral", form.minCollateralText, viewModel::setStakeReqMinCollateral)
        Spacer(Modifier.height(8.dp))
        NumberField("Max stake %", form.maxStakePctText, viewModel::setStakeReqMaxPct)
        Spacer(Modifier.height(8.dp))
        NumberField("Lockup seconds", form.lockupSecondsText, viewModel::setStakeReqLockup)
        Spacer(Modifier.height(8.dp))
        NumberField("Duration seconds", form.durationSecondsText, viewModel::setStakeReqDuration)
        StakeApply(
            label = "Create stake request",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "create_stake_request",
            onSubmit = viewModel::submitStakeRequest,
            onDismiss = viewModel::clearStakeReqResult,
        )
    }
}

@Composable
private fun StakeOfferPanel(form: StakeOfferForm, viewModel: TradingViewModel) {
    EngineCard("Offer on stake request", "Stake against an open request by its id.") {
        NumberField("Request id", form.requestIdText, viewModel::setStakeOfferRequestId)
        Spacer(Modifier.height(8.dp))
        NumberField("Collateral amount", form.collateralText, viewModel::setStakeOfferCollateral)
        Spacer(Modifier.height(8.dp))
        NumberField("Stake %", form.stakePctText, viewModel::setStakeOfferPct)
        StakeApply(
            label = "Submit offer",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "submit_stake_offer",
            onSubmit = viewModel::submitStakeOffer,
            onDismiss = viewModel::clearStakeOfferResult,
        )
    }
}

@Composable
private fun AuctionRequestPanel(form: AuctionRequestForm, viewModel: TradingViewModel) {
    EngineCard("Create auction", "Auction a position quantity (optional reserve + duration).") {
        NumberField("Symbol id (optional)", form.symbolText, viewModel::setAuctionReqSymbol)
        Spacer(Modifier.height(8.dp))
        NumberField("Quantity", form.qtyText, viewModel::setAuctionReqQty)
        Spacer(Modifier.height(8.dp))
        NumberField("Reserve price (optional)", form.reservePriceText, viewModel::setAuctionReqReserve)
        Spacer(Modifier.height(8.dp))
        NumberField("Duration seconds (optional)", form.durationSecondsText, viewModel::setAuctionReqDuration)
        StakeApply(
            label = "Create auction",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "create_auction_request",
            onSubmit = viewModel::submitAuctionRequest,
            onDismiss = viewModel::clearAuctionReqResult,
        )
    }
}

@Composable
private fun AuctionBidPanel(form: AuctionBidForm, viewModel: TradingViewModel) {
    EngineCard("Bid on auction", "Bid on an open auction by its id.") {
        NumberField("Auction id", form.auctionIdText, viewModel::setAuctionBidId)
        Spacer(Modifier.height(8.dp))
        NumberField("Price", form.priceText, viewModel::setAuctionBidPrice)
        Spacer(Modifier.height(8.dp))
        NumberField("Quantity", form.qtyText, viewModel::setAuctionBidQty)
        StakeApply(
            label = "Submit bid",
            canSubmit = form.canSubmit,
            submitting = form.submitting,
            error = form.error,
            result = form.result,
            testTag = "submit_auction_bid",
            onSubmit = viewModel::submitAuctionBid,
            onDismiss = viewModel::clearAuctionBidResult,
        )
    }
}
