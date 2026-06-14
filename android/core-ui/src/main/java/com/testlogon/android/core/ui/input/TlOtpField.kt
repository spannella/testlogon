package com.testlogon.android.core.ui.input

import androidx.compose.foundation.border
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.stateDescription
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.theme.TestLogonTheme

/**
 * Fixed-length numeric OTP input (default 6 digits) with paste support.
 *
 * Stateless: [value] is always a sanitized digit string of length 0..[length]. Implemented as a
 * single transparent [BasicTextField] with decorative cells so the platform handles focus, the
 * numeric keyboard, and paste. [onCompleted] fires exactly once on the transition to a full code.
 */
@Composable
fun TlOtpField(
    value: String,
    onValueChange: (String) -> Unit,
    modifier: Modifier = Modifier,
    length: Int = 6,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    onCompleted: (String) -> Unit = {},
) {
    val sanitized = sanitizeOtp(value, length)
    val fieldValue = TextFieldValue(text = sanitized, selection = TextRange(sanitized.length))
    val focusedIndex = sanitized.length.coerceAtMost(length - 1)
    val hasError = isError || errorText != null

    Column(modifier = modifier) {
        Box {
            BasicTextField(
                value = fieldValue,
                onValueChange = { tfv ->
                    val next = sanitizeOtp(tfv.text, length)
                    if (next != sanitized) {
                        onValueChange(next)
                        if (next.length == length && sanitized.length < length) {
                            onCompleted(next)
                        }
                    }
                },
                enabled = enabled,
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.NumberPassword),
                // The real text field is invisible; the cells are the visible decoration that read
                // from the hoisted [value]. innerTextField() is invoked (size-collapsed) so the
                // platform keeps focus/IME/paste behavior wired to the actual field.
                decorationBox = { innerTextField ->
                    Box {
                        Box(Modifier.size(0.dp)) { innerTextField() }
                        Row(horizontalArrangement = Arrangement.spacedBy(InputTokens.OtpCellGap)) {
                            repeat(length) { i ->
                                OtpCell(
                                    char = sanitized.getOrNull(i)?.toString().orEmpty(),
                                    focused = enabled && i == focusedIndex,
                                    error = hasError,
                                )
                            }
                        }
                    }
                },
                modifier = Modifier
                    .clearAndSetSemantics {
                        contentDescription = "Verification code, $length digits"
                        stateDescription = "${sanitized.length} of $length digits entered"
                    },
            )
        }
        if (hasError && errorText != null) {
            Text(
                text = errorText,
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

@Composable
private fun OtpCell(char: String, focused: Boolean, error: Boolean) {
    val borderColor = when {
        error -> MaterialTheme.colorScheme.error
        focused -> MaterialTheme.colorScheme.primary
        else -> MaterialTheme.colorScheme.outline
    }
    Box(
        contentAlignment = Alignment.Center,
        modifier = Modifier
            .size(InputTokens.OtpCellSize)
            .border(width = if (focused) 2.dp else 1.dp, color = borderColor, shape = MaterialTheme.shapes.small),
    ) {
        Text(
            text = char,
            style = MaterialTheme.typography.titleLarge,
            textAlign = TextAlign.Center,
            color = MaterialTheme.colorScheme.onSurface,
        )
    }
}

@Preview
@Composable
private fun TlOtpFieldPreview() {
    TestLogonTheme(dynamicColor = false) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            TlOtpField(value = "123", onValueChange = {})
            TlOtpField(value = "12", onValueChange = {}, isError = true, errorText = "Wrong code")
        }
    }
}
