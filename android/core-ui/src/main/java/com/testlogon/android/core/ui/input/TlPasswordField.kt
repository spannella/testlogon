package com.testlogon.android.core.ui.input

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import com.testlogon.android.core.ui.R
import com.testlogon.android.core.ui.theme.TestLogonTheme

/**
 * Password field. Masks input by default and exposes a labeled show/hide toggle. Visibility is
 * the only internal UI state (never hoisted, never persisted — a security choice).
 */
@Composable
fun TlPasswordField(
    value: String,
    onValueChange: (String) -> Unit,
    label: String,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
    isError: Boolean = false,
    errorText: String? = null,
    helperText: String? = null,
    imeAction: ImeAction = ImeAction.Done,
    onImeAction: () -> Unit = {},
) {
    var visible by remember { mutableStateOf(false) }
    val hasError = isError || errorText != null

    OutlinedTextField(
        value = value,
        onValueChange = onValueChange,
        modifier = modifier.fillMaxWidth(),
        enabled = enabled,
        isError = hasError,
        label = { Text(label) },
        singleLine = true,
        visualTransformation =
            if (visible) VisualTransformation.None else PasswordVisualTransformation(),
        keyboardOptions = KeyboardOptions(
            keyboardType = KeyboardType.Password,
            imeAction = imeAction,
        ),
        keyboardActions = KeyboardActions(onAny = { onImeAction() }),
        trailingIcon = {
            val cd = stringResource(
                if (visible) R.string.cd_hide_password else R.string.cd_show_password,
            )
            IconButton(onClick = { visible = !visible }, enabled = enabled) {
                Icon(
                    imageVector = if (visible) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                    contentDescription = cd,
                )
            }
        },
        supportingText = supportingText(hasError, errorText, helperText),
    )
}

@Preview
@Composable
private fun TlPasswordFieldPreview() {
    TestLogonTheme(dynamicColor = false) {
        TlPasswordField(value = "hunter2", onValueChange = {}, label = "Password")
    }
}
