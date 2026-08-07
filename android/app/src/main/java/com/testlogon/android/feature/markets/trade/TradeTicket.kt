package com.testlogon.android.feature.markets.trade

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
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
        // ---- Buy / Sell ----
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            SideButton("Buy", selected = state.side == OrderSide.BUY, color = MarketColors.Up, modifier = Modifier.weight(1f)) {
                viewModel.setSide(OrderSide.BUY)
            }
            SideButton("Sell", selected = state.side == OrderSide.SELL, color = MarketColors.Down, modifier = Modifier.weight(1f)) {
                viewModel.setSide(OrderSide.SELL)
            }
        }

        Spacer(Modifier.height(10.dp))
        state.account?.let { AccountStrip(it) }

        Spacer(Modifier.height(10.dp))
        NumberField("Price", state.priceText, viewModel::setPrice)
        Spacer(Modifier.height(8.dp))
        NumberField("Quantity", state.qtyText, viewModel::setQty)

        Spacer(Modifier.height(8.dp))
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Order value", color = MarketColors.TextSecondary, fontSize = 12.sp)
            Text(
                text = state.orderValue?.let { fmt(it.toDouble()) } ?: "--",
                color = MarketColors.TextPrimary,
                fontFamily = FontFamily.Monospace,
                fontWeight = FontWeight.SemiBold,
                fontSize = 12.sp,
            )
        }

        Spacer(Modifier.height(12.dp))
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .clip(RoundedCornerShape(10.dp))
                .background(if (state.canPlace) sideColor else MarketColors.SurfaceAlt)
                .clickable(enabled = state.canPlace) { viewModel.place() }
                .testTag("trade_place")
                .padding(vertical = 14.dp),
            contentAlignment = Alignment.Center,
        ) {
            Text(
                text = if (state.placing) "Placing…" else "${if (state.side == OrderSide.BUY) "Buy" else "Sell"} ${state.qtyText.ifBlank { "" }}".trim(),
                color = if (state.canPlace) Color.Black else MarketColors.TextFaint,
                fontWeight = FontWeight.Bold,
                fontSize = 15.sp,
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

        if (state.workingOrders.isNotEmpty()) {
            Spacer(Modifier.height(16.dp))
            Text("Open orders · this session", color = MarketColors.TextPrimary, fontWeight = FontWeight.Bold, fontSize = 13.sp)
            Spacer(Modifier.height(4.dp))
            state.workingOrders.forEach { wo ->
                WorkingOrderRow(
                    label = "${if (wo.side == OrderSide.BUY) "Buy" else "Sell"}  ${fmt(wo.qty.toDouble())} @ ${fmt(wo.price.toDouble())}",
                    sideColor = if (wo.side == OrderSide.BUY) MarketColors.Up else MarketColors.Down,
                    onCancel = { viewModel.cancel(wo.clordid) },
                )
            }
        }
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
        Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.SpaceBetween) {
            Text("Available", color = MarketColors.TextSecondary, fontSize = 11.sp)
            Text(fmt(account.availableBalance.toDouble()), color = MarketColors.TextPrimary, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
        }
        Spacer(Modifier.height(4.dp))
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
private fun WorkingOrderRow(label: String, sideColor: Color, onCancel: () -> Unit) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 4.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.SpaceBetween,
    ) {
        Text(label, color = sideColor, fontFamily = FontFamily.Monospace, fontSize = 12.sp)
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

private fun fmt(v: Double): String {
    val whole = v == v.toLong().toDouble()
    return if (whole) String.format(Locale.US, "%,d", v.toLong()) else String.format(Locale.US, "%,.2f", v)
}
