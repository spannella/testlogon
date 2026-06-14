package com.testlogon.android.core.ui.input

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.testlogon.android.core.ui.theme.TestLogonTheme

/**
 * Labeled single-line (configurable) text field built on Material 3 [OutlinedTextField].
 *
 * Stateless: [value]/[onValueChange] are hoisted. Below the field, [errorText] (in error color)
 * takes precedence over [helperText]; a non-null [errorText] also forces the error visual state.
 */
@Composable
fun TlTextField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    helperText: String? = null,
    singleLine: Boolean = true,
    leading: @Composable (() -> Unit)? = null,
    trailing: @Composable (() -> Unit)? = null,
    keyboardOptions: KeyboardOptions = KeyboardOptions.Default,
    keyboardActions: KeyboardActions = KeyboardActions.Default,
    visualTransformation: VisualTransformation = VisualTransformation.None,
) {
    val hasError = isError || errorText != null
    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        enabled = enabled,
        isError = hasError,
        label = { Text(label) },
        singleLine = singleLine,
        leadingIcon = leading,
        trailingIcon = trailing,
        keyboardOptions = keyboardOptions,
        keyboardActions = keyboardActions,
        visualTransformation = visualTransformation,
        supportingText = supportingText(hasError, errorText, helperText),
    )
}

/** Builds the supporting-text slot: error text (if errored) wins over helper text. */
internal fun supportingText(
    hasError: Boolean,
    errorText: String?,
    helperText: String?,
): (@Composable () -> Unit)? = when {
    hasError && errorText != null -> {
        { Text(errorText, color = MaterialTheme.colorScheme.error) }
    }
    helperText != null -> {
        { Text(helperText, color = MaterialTheme.colorScheme.onSurfaceVariant) }
    }
    else -> null
}

@Preview
@Composable
private fun TlTextFieldPreview() {
    TestLogonTheme(dynamicColor = false) {
        Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
            TlTextField(value = "alice", onValueChange = {}, label = "Email", helperText = "We never share it")
            TlTextField(value = "x", onValueChange = {}, label = "Email", errorText = "Invalid email")
        }
    }
}
