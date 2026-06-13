package com.testlogon.android.feature.questionnaire.render

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.R

/**
 * AND-347 - common scaffold for ONE rendered question. Renders the label (with a required marker for
 * required questions), the type-specific control [content], the [hint] as supporting text, and the
 * [error] text (error color) when present.
 *
 * Controls that are themselves full text fields (TlTextField) already surface their own label / helper /
 * error; for those the dispatcher passes the label through to the control instead of duplicating it here
 * (see [QuestionField]). This container is used for the non-text controls (choices, slider, pickers,
 * address) that need an external label + supporting text.
 */
@Composable
fun QuestionFieldContainer(
    label: String,
    required: Boolean,
    hint: String?,
    error: String?,
    enabled: Boolean,
    modifier: Modifier = Modifier,
    content: @Composable () -> Unit,
) {
    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(4.dp),
    ) {
        Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
            val labelColor = if (enabled) {
                MaterialTheme.colorScheme.onSurface
            } else {
                MaterialTheme.colorScheme.onSurfaceVariant
            }
            Text(
                text = label,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                color = labelColor,
            )
            if (required) {
                Text(
                    text = stringResource(R.string.questionnaire_required_marker),
                    style = MaterialTheme.typography.bodyLarge,
                    fontWeight = FontWeight.Medium,
                    color = MaterialTheme.colorScheme.error,
                )
            }
        }

        content()

        // Error wins over hint, mirroring the TlTextField supporting-text precedence.
        when {
            error != null -> Text(
                text = error,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.error,
            )
            hint != null -> Text(
                text = hint,
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}
