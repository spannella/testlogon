package com.testlogon.android.core.ui.input

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.defaultMinSize
import androidx.compose.foundation.layout.size
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.theme.TestLogonTheme

/** Visual variants for [TlButton]. */
enum class TlButtonVariant { Primary, Secondary, Text }

/**
 * App button. Stateless; renders [variant] and supports a [loading] state that swaps the label for
 * a spinner while preserving width and suppressing clicks.
 */
@Composable
fun TlButton(
    text: String,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
    variant: TlButtonVariant = TlButtonVariant.Primary,
    enabled: Boolean = true,
    loading: Boolean = false,
    leadingIcon: ImageVector? = null,
) {
    val effectiveEnabled = enabled && !loading
    val content: @Composable () -> Unit = {
        Box(contentAlignment = Alignment.Center) {
            // Keep the label in the layout (transparent) so width is preserved while loading.
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                if (leadingIcon != null) {
                    Icon(leadingIcon, contentDescription = null, modifier = Modifier.size(18.dp))
                }
                Text(text)
            }
            if (loading) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(18.dp))
            }
        }
    }

    val btnModifier = modifier.defaultMinSize(minHeight = InputTokens.ButtonMinHeight)
    when (variant) {
        TlButtonVariant.Primary ->
            Button(onClick = onClick, modifier = btnModifier, enabled = effectiveEnabled) { content() }
        TlButtonVariant.Secondary ->
            OutlinedButton(onClick = onClick, modifier = btnModifier, enabled = effectiveEnabled) { content() }
        TlButtonVariant.Text ->
            TextButton(onClick = onClick, modifier = btnModifier, enabled = effectiveEnabled) { content() }
    }
}

@Preview
@Composable
private fun TlButtonPreview() {
    TestLogonTheme(dynamicColor = false) {
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            TlButton(text = "Primary", onClick = {})
            TlButton(text = "Loading", onClick = {}, loading = true)
            TlButton(text = "Disabled", onClick = {}, enabled = false, variant = TlButtonVariant.Secondary)
        }
    }
}
