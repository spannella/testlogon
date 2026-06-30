@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.builder.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MenuAnchorType
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.questionnaire.builder.data.QnrQuestionType

/** The three draft visibility values the backend accepts. */
private val VISIBILITIES = listOf("private" to "Private", "unlisted" to "Unlisted", "public" to "Public")

/** A labelled visibility dropdown (private / unlisted / public). Reused by create + builder. */
@Composable
fun VisibilityPicker(value: String, onChange: (String) -> Unit, modifier: Modifier = Modifier) {
    var expanded by remember { mutableStateOf(false) }
    val display = VISIBILITIES.firstOrNull { it.first == value }?.second ?: value
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = display,
            onValueChange = {},
            readOnly = true,
            label = { Text("Visibility") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable, enabled = true),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            VISIBILITIES.forEach { (wire, label) ->
                DropdownMenuItem(
                    text = { Text(label) },
                    onClick = {
                        expanded = false
                        if (wire != value) onChange(wire)
                    },
                )
            }
        }
    }
}

/** A labelled question-type dropdown over the nine [QnrQuestionType]s. */
@Composable
fun QuestionTypePicker(value: QnrQuestionType, onChange: (QnrQuestionType) -> Unit, modifier: Modifier = Modifier) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = value.wire,
            onValueChange = {},
            readOnly = true,
            label = { Text("Type") },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .fillMaxWidth()
                .menuAnchor(MenuAnchorType.PrimaryNotEditable, enabled = true),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            QnrQuestionType.entries.forEach { type ->
                DropdownMenuItem(
                    text = { Text(type.wire) },
                    onClick = {
                        expanded = false
                        if (type != value) onChange(type)
                    },
                )
            }
        }
    }
}

/**
 * Per-type config editor (mirrors the web QuestionTypeConfigEditor). Edits a copy of [config] and emits
 * the full updated map via [onChange]. Numbers are stored as Double (the JSON number type); option /
 * timezone / address lists are stored as List<String> from comma-separated input.
 *
 * Only the fields the web editor exposes are surfaced; unknown keys in [config] are preserved on every
 * edit (we copy the whole map and overwrite individual keys).
 */
@Composable
fun QuestionConfigEditor(
    type: QnrQuestionType,
    config: Map<String, Any?>,
    onChange: (Map<String, Any?>) -> Unit,
    modifier: Modifier = Modifier,
) {
    fun put(key: String, value: Any?) = onChange(config.toMutableMap().apply { this[key] = value })

    Column(modifier = modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(8.dp)) {
        when (type) {
            QnrQuestionType.TEXT -> {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    NumberField("Min length", config.numStr("minLength"), { put("minLength", it) }, Modifier.weight(1f))
                    NumberField("Max length", config.numStr("maxLength"), { put("maxLength", it) }, Modifier.weight(1f))
                }
                TextConfigField("Regex pattern (optional)", config.str("pattern"), { put("pattern", it) })
            }
            QnrQuestionType.SELECT, QnrQuestionType.RADIO ->
                CsvField("Options (comma separated)", config.csv("options"), { put("options", it) })
            QnrQuestionType.MULTISELECT -> {
                CsvField("Options (comma separated)", config.csv("options"), { put("options", it) })
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    NumberField("Min selections", config.numStr("minSelections"), { put("minSelections", it) }, Modifier.weight(1f))
                    NumberField("Max selections", config.numStr("maxSelections"), { put("maxSelections", it) }, Modifier.weight(1f))
                }
            }
            QnrQuestionType.SLIDER ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    NumberField("Min", config.numStr("min"), { put("min", it) }, Modifier.weight(1f))
                    NumberField("Max", config.numStr("max"), { put("max", it) }, Modifier.weight(1f))
                    NumberField("Step", config.numStr("step"), { put("step", it) }, Modifier.weight(1f))
                }
            QnrQuestionType.DATE ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextConfigField("Min date (YYYY-MM-DD)", config.str("minDate"), { put("minDate", it) }, Modifier.weight(1f))
                    TextConfigField("Max date (YYYY-MM-DD)", config.str("maxDate"), { put("maxDate", it) }, Modifier.weight(1f))
                }
            QnrQuestionType.TIME ->
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextConfigField("Min time (HH:MM)", config.str("minTime"), { put("minTime", it) }, Modifier.weight(1f))
                    TextConfigField("Max time (HH:MM)", config.str("maxTime"), { put("maxTime", it) }, Modifier.weight(1f))
                }
            QnrQuestionType.TIMEZONE ->
                CsvField("Allowed timezones (comma separated)", config.csv("allowedTimezones"), { put("allowedTimezones", it) })
            QnrQuestionType.ADDRESS ->
                CsvField("Required address fields (comma separated)", config.csv("requiredFields"), { put("requiredFields", it) })
        }
    }
}

@Composable
private fun TextConfigField(label: String, value: String, onChange: (String) -> Unit, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = onChange,
        label = { Text(label) },
        singleLine = true,
        modifier = modifier.fillMaxWidth(),
    )
}

@Composable
private fun NumberField(label: String, value: String, onChange: (Number?) -> Unit, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = { raw ->
            val cleaned = raw.filter { it.isDigit() || it == '.' || it == '-' }
            // Emit an Int for whole numbers (so Moshi serializes e.g. 200 not 200.0 - the backend's text
            // minLength/maxLength validator rejects non-integers); fall back to Double for decimals.
            val number: Number? = cleaned.toIntOrNull() ?: cleaned.toDoubleOrNull()
            onChange(number)
        },
        label = { Text(label) },
        singleLine = true,
        modifier = modifier.fillMaxWidth(),
    )
}

@Composable
private fun CsvField(label: String, value: String, onChange: (List<String>) -> Unit, modifier: Modifier = Modifier) {
    OutlinedTextField(
        value = value,
        onValueChange = { raw -> onChange(raw.split(",").map { it.trim() }.filter { it.isNotEmpty() }) },
        label = { Text(label) },
        modifier = modifier.fillMaxWidth().padding(top = 0.dp),
    )
}

// ---- config map read helpers ----

private fun Map<String, Any?>.str(key: String): String = (this[key] as? String).orEmpty()

private fun Map<String, Any?>.numStr(key: String): String = when (val v = this[key]) {
    is Number -> {
        val d = v.toDouble()
        if (d == d.toLong().toDouble()) d.toLong().toString() else d.toString()
    }
    is String -> v
    else -> ""
}

@Suppress("UNCHECKED_CAST")
private fun Map<String, Any?>.csv(key: String): String =
    (this[key] as? List<*>)?.filterIsInstance<String>()?.joinToString(", ").orEmpty()
