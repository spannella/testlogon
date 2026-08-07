package com.testlogon.android.feature.markets.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.LocalContentColor
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

/**
 * Self-contained premium dark palette + surface wrapper for the Markets screens ONLY. The exchange
 * screens must render like a high-end trading terminal (Binance / Coinbase Pro / Bybit dark)
 * regardless of the host app Material theme, so we provide an explicit dark scheme + content color
 * locally rather than reading MaterialTheme.colorScheme (which is the light app theme).
 */
object MarketColors {
    val Bg = Color(0xFF0B0E11)
    val Surface = Color(0xFF151A21)
    val SurfaceAlt = Color(0xFF1C222B)
    val Border = Color(0xFF252C36)

    val TextPrimary = Color(0xFFEAECEF)
    val TextSecondary = Color(0xFF848E9C)
    val TextFaint = Color(0xFF5E6673)

    val Up = Color(0xFF0ECB81)
    val Down = Color(0xFFF6465D)
    val Accent = Color(0xFFF0B90B)

    // Translucent depth fills (crisp, not pastel).
    val UpFill = Color(0x240ECB81)
    val DownFill = Color(0x24F6465D)
    val UpPill = Color(0x1F0ECB81)
    val DownPill = Color(0x1FF6465D)
}

private val MarketDarkScheme = darkColorScheme(
    background = MarketColors.Bg,
    surface = MarketColors.Surface,
    surfaceVariant = MarketColors.SurfaceAlt,
    primary = MarketColors.Up,
    error = MarketColors.Down,
    onBackground = MarketColors.TextPrimary,
    onSurface = MarketColors.TextPrimary,
    onSurfaceVariant = MarketColors.TextSecondary,
    outline = MarketColors.Border,
)

/**
 * Wrap Markets content so every child renders on the dark exchange palette. Provides a dark
 * [MaterialTheme] scheme + a default [LocalContentColor] of [MarketColors.TextPrimary] and paints
 * the full-bleed [MarketColors.Bg] behind the content.
 */
@Composable
fun MarketSurface(
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    MaterialTheme(colorScheme = MarketDarkScheme) {
        CompositionLocalProvider(LocalContentColor provides MarketColors.TextPrimary) {
            Box(modifier = modifier.fillMaxSize().background(MarketColors.Bg)) {
                content()
            }
        }
    }
}
