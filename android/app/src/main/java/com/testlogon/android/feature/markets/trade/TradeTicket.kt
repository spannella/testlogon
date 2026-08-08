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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.hilt.navigation.compose.hiltViewModel
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.testlogon.android.data.exchange.OrderSide
import com.testlogon.android.feature.markets.ui.MarketColors
import java.util.Locale

/** Order ticket: side + limit price + qty → place, plus this-session working orders + margin strip. */
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

    val sideColor = if (state.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down
    Column(modifier = modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 8.dp).testTag("trade_ticket")) {
        // ---- Order type ----
        OrderTypeRow(selected = state.orderType, onSelect = viewModel::setOrderType)
        Spacer(Modifier.height(10.dp))

        // ---- Buy / Sell (hidden for the two-sided quote) ----
        if (state.orderType != OrderType.QUOTE) {
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                SideButton("Buy", selected = state.side == OrderSide.BUY, color = MarketColors.Up, modifier = Modifier.weight(1f)) {
                    viewModel.setSide(OrderSide.BUY)
                }
                SideButton("Sell", selected = state.side == OrderSide.SELL, color = MarketColors.Down, modifier = Modifier.weight(1f)) {
                    viewModel.setSide(OrderSide.SELL)
                }
            }
        }

        Spacer(Modifier.height(10.dp))
        state.account?.let { AccountStrip(it) }

        Spacer(Modifier.height(8.dp))
        FundRow(
            value = state.depositText,
            canDeposit = state.canDeposit,
            depositing = state.depositing,
            onValue = viewModel::setDeposit,
            onDeposit = viewModel::deposit,
        )

        Spacer(Modifier.height(10.dp))
        // ---- Type-specific inputs ----
        when (state.orderType) {
            OrderType.LIMIT -> {
                NumberField("Price", state.priceText, viewModel::setPrice)
                Spacer(Modifier.height(8.dp))
                NumberField("Quantity", state.qtyText, viewModel::setQty)
                Spacer(Modifier.height(8.dp))
                OrderValueRow(state.orderValue)
            }
            OrderType.STOP -> {
                NumberField("Stop (trigger) price", state.stopText, viewModel::setStop)
                Spacer(Modifier.height(8.dp))
                NumberField("Quantity", state.qtyText, viewModel::setQty)
            }
            OrderType.STOP_LIMIT -> {
                NumberField("Stop (trigger) price", state.stopText, viewModel::setStop)
                Spacer(Modifier.height(8.dp))
                NumberField("Limit price", state.priceText, viewModel::setPrice)
                Spacer(Modifier.height(8.dp))
                NumberField("Quantity", state.qtyText, viewModel::setQty)
            }
            OrderType.TAKE_PROFIT -> {
                NumberField("Take-profit trigger", state.stopText, viewModel::setStop)
                Spacer(Modifier.height(8.dp))
                NumberField("Limit price (optional)", state.priceText, viewModel::setPrice)
                Spacer(Modifier.height(8.dp))
                NumberField("Quantity", state.qtyText, viewModel::setQty)
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
        }

        Spacer(Modifier.height(12.dp))
        val submitColor = if (state.orderType == OrderType.QUOTE) MarketColors.Accent else sideColor
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
                text = submitLabel(state),
                color = if (state.canSubmit) Color.Black else MarketColors.TextFaint,
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
            )
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

        Spacer(Modifier.height(12.dp))
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

        if (state.workingOrders.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text("Open orders · this session", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            state.workingOrders.forEach { wo ->
                WorkingOrderRow(
                    label = "${if (wo.side == OrderSide.BUY) "Buy" else "Sell"}  ${fmt(wo.qty.toDouble())} @ ${fmt(wo.price.toDouble())}",
                    sideColor = if (wo.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down,
                    onAmend = { viewModel.startAmend(wo) },
                    onCancel = { viewModel.cancel(wo.clordid) },
                )
            }
        }

        state.account?.position?.let { pos ->
            Spacer(Modifier.height(16.dp))
            Text("Position", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            PositionCard(pos = pos, onClose = { lastPrice?.let { viewModel.closePosition(it) } })
        }

        if (state.sessionFills.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text("Fills · this session", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            Row(modifier = Modifier.fillMaxWidth().padding(vertical = 2.dp)) {
                Text("Price", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1.2f))
                Text("Qty", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
                Text("Time", color = MarketColors.TextSecondary, fontFamily = FontFamily.Monospace, fontSize = 11.sp, modifier = Modifier.weight(1f))
            }
            state.sessionFills.take(40).forEach { f -> FillRow(f) }
        }
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
private fun PositionCard(pos: com.testlogon.android.data.exchange.PositionSnapshot, onClose: () -> Unit) {
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
                text = "Close",
                color = Color.Black,
                fontWeight = FontWeight.Bold,
                fontFamily = FontFamily.Monospace,
                fontSize = 12.sp,
                modifier = Modifier
                    .clip(RoundedCornerShape(6.dp))
                    .background(sideColor)
                    .clickable(onClick = onClose)
                    .testTag("close_position")
                    .padding(horizontal = 12.dp, vertical = 6.dp),
            )
        }
        Spacer(Modifier.height(6.dp))
        PosStat("Entry", fmt(pos.entryPrice.toDouble()))
        PosStat("Liq. price", if (pos.liquidationPrice > 0) fmt(pos.liquidationPrice.toDouble()) else "--")
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
private fun PosStat(label: String, value: String) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text(label, color = MarketColors.TextSecondary, fontSize = 11.sp)
        Text(value, color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
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
private fun OrderTypeRow(selected: OrderType, onSelect: (OrderType) -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().horizontalScroll(rememberScrollState()),
        horizontalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        OrderType.values().forEach { t ->
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
private fun OrderValueRow(value: Long?) {
    Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
        Text("Order value", color = MarketColors.TextSecondary, fontSize = 12.sp)
        Text(
            text = value?.let { fmt(it.toDouble()) } ?: "--",
            color = MarketColors.TextPrimary,
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
        OrderType.STOP -> "$side Stop"
        OrderType.STOP_LIMIT -> "$side Stop-Limit"
        OrderType.TAKE_PROFIT -> "$side Take-Profit"
        OrderType.QUOTE -> "Place quote"
        OrderType.OTO -> "Place OTO ($side parent)"
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

private fun fmt(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong()) else String.format(Locale.US, "%,.2f", v)
}
