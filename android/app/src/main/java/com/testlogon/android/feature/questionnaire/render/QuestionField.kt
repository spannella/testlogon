@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.questionnaire.render

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.toggleable
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Slider
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TimePicker
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.material3.rememberTimePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.core.model.questionnaire.AnswerValue
import com.testlogon.android.core.model.questionnaire.QuestionnaireField
import com.testlogon.android.core.ui.input.TlButton
import com.testlogon.android.core.ui.input.TlButtonVariant
import com.testlogon.android.core.ui.input.TlTextField
import java.time.Instant
import java.time.LocalDate
import java.time.LocalTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter

/**
 * AND-347 - the STATELESS dynamic-form field DISPATCHER. Given one [QuestionnaireField] (the real AND-346
 * sealed type), the incoming [answer] (rehydration), and an [onAnswerChanged] sink, renders the correct
 * Material3 control. Exhaustive `when` over the sealed hierarchy INCLUDING [QuestionnaireField.Unknown],
 * which renders a non-crashing placeholder and emits nothing.
 *
 * Contract: every edit emits onAnswerChanged(field.questionId, value); clearing emits
 * [AnswerValue.Empty]; the control is rehydrated from [answer]. NO networking / session / validation /
 * visibility (AND-346 / 348 / 350 / 351). Material3 built-ins only - no vendor SDK, no new dependency.
 */
@Composable
fun QuestionField(
    field: QuestionnaireField,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    onAnswerChanged: (questionId: String, value: AnswerValue) -> Unit,
    modifier: Modifier = Modifier,
) {
    val emit: (AnswerValue) -> Unit = { onAnswerChanged(field.questionId, it) }
    when (field) {
        is QuestionnaireField.Text ->
            TextQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Select ->
            SelectQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Multiselect ->
            MultiselectQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Radio ->
            RadioQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Slider ->
            SliderQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.DateField ->
            DateQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.TimeField ->
            TimeQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Timezone ->
            TimezoneQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Address ->
            AddressQuestion(field, answer, enabled, error, emit, modifier)
        is QuestionnaireField.Unknown ->
            UnsupportedFieldPlaceholder(field.rawType, field.label, modifier)
    }
}

// ---- Text ----

/** Free-text -> single-line TlTextField. Soft-trims to config maxLength; emits Text or Empty. */
@Composable
private fun TextQuestion(
    field: QuestionnaireField.Text,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val current = QuestionRenderSupport.textOf(answer)
    val labelWithMarker = labelWithRequired(field.label, field.required)
    TlTextField(
        value = current,
        onValueChange = { raw ->
            val coerced = QuestionRenderSupport.coerceText(field, raw)
            emit(QuestionRenderSupport.textAnswer(coerced))
        },
        label = labelWithMarker,
        modifier = modifier.testTag(QuestionFieldTestTags.field(field.questionId)),
        enabled = enabled,
        errorText = error,
        helperText = field.hint ?: field.placeholder(),
    )
    ErrorTag(field.questionId, error)
}

// ---- Select (single, dropdown) ----

/** Single-select -> ExposedDropdownMenuBox over options() (order preserved). Emits Text(value)/Empty. */
@Composable
private fun SelectQuestion(
    field: QuestionnaireField.Select,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val options = field.options()
    val selectedValue = QuestionRenderSupport.selectedOption(answer)
    val selectedLabel = options.firstOrNull { it.value == selectedValue }
        ?.let { it.label ?: it.value }
        ?: selectedValue.orEmpty()

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        var expanded by remember { mutableStateOf(false) }
        ExposedDropdownMenuBox(
            expanded = expanded && enabled,
            onExpandedChange = { if (enabled) expanded = it },
        ) {
            OutlinedTextField(
                value = selectedLabel,
                onValueChange = {},
                readOnly = true,
                enabled = enabled,
                label = { Text(stringResource(R.string.questionnaire_select_label)) },
                trailingIcon = {
                    ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded && enabled)
                },
                modifier = Modifier
                    .menuAnchor()
                    .fillMaxWidth()
                    .testTag(QuestionFieldTestTags.field(field.questionId)),
            )
            ExposedDropdownMenu(
                expanded = expanded && enabled,
                onDismissRequest = { expanded = false },
            ) {
                options.forEachIndexed { index, option ->
                    DropdownMenuItem(
                        text = { Text(option.label ?: option.value) },
                        onClick = {
                            expanded = false
                            emit(QuestionRenderSupport.singleChoiceAnswer(option.value))
                        },
                        modifier = Modifier.testTag(
                            QuestionFieldTestTags.option(field.questionId, index),
                        ),
                    )
                }
            }
        }
    }
    ErrorTag(field.questionId, error)
}

// ---- Multiselect ----

/** Multiselect -> checkbox group over options(). Honors min/max as affordance text. Emits Choices/Empty. */
@Composable
private fun MultiselectQuestion(
    field: QuestionnaireField.Multiselect,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val options = field.options()
    val order = options.map { it.value }
    val selected = QuestionRenderSupport.selectedOptions(answer)
    val min = QuestionRenderSupport.readInt(field.configJson, "minSelections")
    val max = QuestionRenderSupport.readInt(field.configJson, "maxSelections")
    val affordance = selectionAffordance(min, max)
    val hint = listOfNotNull(field.hint, affordance).joinToString(" ").ifBlank { null }

    QuestionFieldContainer(field.label, field.required, hint, error, enabled, modifier) {
        Column(
            modifier = Modifier.testTag(QuestionFieldTestTags.field(field.questionId)),
        ) {
            options.forEachIndexed { index, option ->
                val checked = option.value in selected
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .toggleable(
                            value = checked,
                            enabled = enabled,
                            role = Role.Checkbox,
                            onValueChange = { isChecked ->
                                emit(
                                    QuestionRenderSupport.toggleMultiselect(
                                        current = selected,
                                        option = option.value,
                                        checked = isChecked,
                                        optionOrder = order,
                                    ),
                                )
                            },
                        )
                        .testTag(QuestionFieldTestTags.option(field.questionId, index)),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    Checkbox(checked = checked, onCheckedChange = null, enabled = enabled)
                    Text(
                        text = option.label ?: option.value,
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
        }
    }
    ErrorTag(field.questionId, error)
}

// ---- Radio ----

/** Radio -> single-choice radio group over options(). Emits Text(value)/Empty. */
@Composable
private fun RadioQuestion(
    field: QuestionnaireField.Radio,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val options = field.options()
    val selectedValue = QuestionRenderSupport.selectedOption(answer)

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        Column(
            modifier = Modifier.testTag(QuestionFieldTestTags.field(field.questionId)),
        ) {
            options.forEachIndexed { index, option ->
                val isSelected = option.value == selectedValue
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .heightIn(min = 48.dp)
                        .selectable(
                            selected = isSelected,
                            enabled = enabled,
                            role = Role.RadioButton,
                            onClick = {
                                emit(QuestionRenderSupport.singleChoiceAnswer(option.value))
                            },
                        )
                        .testTag(QuestionFieldTestTags.option(field.questionId, index)),
                    verticalAlignment = Alignment.CenterVertically,
                ) {
                    RadioButton(selected = isSelected, onClick = null, enabled = enabled)
                    Text(
                        text = option.label ?: option.value,
                        modifier = Modifier.padding(start = 8.dp),
                    )
                }
            }
        }
    }
    ErrorTag(field.questionId, error)
}

// ---- Slider ----

/** Slider -> discrete Material3 Slider across min..max step. Shows value + endpoints. Emits Num. */
@Composable
private fun SliderQuestion(
    field: QuestionnaireField.Slider,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val min = QuestionRenderSupport.sliderMin(field)
    val max = QuestionRenderSupport.sliderMax(field)
    val steps = QuestionRenderSupport.sliderSteps(field)
    val value = QuestionRenderSupport.sliderValueOf(field, answer)

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        Text(
            text = stringResource(
                R.string.questionnaire_slider_value,
                QuestionRenderSupport.formatNumber(value.toDouble()),
            ),
            style = MaterialTheme.typography.bodyMedium,
        )
        Slider(
            value = value,
            onValueChange = { raw ->
                emit(
                    QuestionRenderSupport.sliderAnswer(
                        QuestionRenderSupport.coerceSliderValue(field, raw),
                    ),
                )
            },
            valueRange = min..max,
            steps = steps,
            enabled = enabled,
            modifier = Modifier
                .fillMaxWidth()
                .testTag(QuestionFieldTestTags.field(field.questionId)),
        )
        Row(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = QuestionRenderSupport.formatNumber(min.toDouble()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
            Box(modifier = Modifier.weight(1f))
            Text(
                text = QuestionRenderSupport.formatNumber(max.toDouble()),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
    ErrorTag(field.questionId, error)
}

// ---- Date ----

private val ISO_DATE: DateTimeFormatter = DateTimeFormatter.ISO_LOCAL_DATE

/** Date -> a read-only field opening a Material3 DatePicker dialog. Value yyyy-MM-dd. Emits Text/Empty. */
@Composable
private fun DateQuestion(
    field: QuestionnaireField.DateField,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val current = QuestionRenderSupport.textOf(answer)
    var showDialog by remember { mutableStateOf(false) }

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        PickerField(
            value = current,
            placeholder = stringResource(R.string.questionnaire_date_placeholder),
            enabled = enabled,
            questionId = field.questionId,
            onOpen = { showDialog = true },
            onClear = { emit(AnswerValue.Empty) },
        )
    }
    ErrorTag(field.questionId, error)

    if (showDialog && enabled) {
        val initialMillis = current.takeIf { it.isNotBlank() }
            ?.let { runCatching { LocalDate.parse(it, ISO_DATE) }.getOrNull() }
            ?.atStartOfDay(ZoneOffset.UTC)?.toInstant()?.toEpochMilli()
        val state = rememberDatePickerState(initialSelectedDateMillis = initialMillis)
        DatePickerDialog(
            onDismissRequest = { showDialog = false },
            confirmButton = {
                TextButton(
                    onClick = {
                        showDialog = false
                        val millis = state.selectedDateMillis
                        if (millis != null) {
                            val date = Instant.ofEpochMilli(millis).atZone(ZoneOffset.UTC).toLocalDate()
                            emit(AnswerValue.Text(date.format(ISO_DATE)))
                        }
                    },
                    modifier = Modifier.testTag(QuestionFieldTestTags.pickerConfirm(field.questionId)),
                ) { Text(stringResource(R.string.questionnaire_picker_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { showDialog = false }) {
                    Text(stringResource(R.string.questionnaire_picker_cancel))
                }
            },
        ) {
            DatePicker(state = state)
        }
    }
}

// ---- Time ----

private val ISO_TIME: DateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm")

/** Time -> a read-only field opening a Material3 TimePicker dialog. Value HH:mm. Emits Text/Empty. */
@Composable
private fun TimeQuestion(
    field: QuestionnaireField.TimeField,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val current = QuestionRenderSupport.textOf(answer)
    var showDialog by remember { mutableStateOf(false) }

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        PickerField(
            value = current,
            placeholder = stringResource(R.string.questionnaire_time_placeholder),
            enabled = enabled,
            questionId = field.questionId,
            onOpen = { showDialog = true },
            onClear = { emit(AnswerValue.Empty) },
        )
    }
    ErrorTag(field.questionId, error)

    if (showDialog && enabled) {
        val parsed = current.takeIf { it.isNotBlank() }
            ?.let { runCatching { LocalTime.parse(it, ISO_TIME) }.getOrNull() }
        val state = rememberTimePickerState(
            initialHour = parsed?.hour ?: 12,
            initialMinute = parsed?.minute ?: 0,
            is24Hour = true,
        )
        // Reuse the date dialog scaffold via a simple Card-hosted dialog.
        androidx.compose.ui.window.Dialog(onDismissRequest = { showDialog = false }) {
            Card {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(12.dp),
                ) {
                    TimePicker(state = state)
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Box(modifier = Modifier.weight(1f))
                        TextButton(onClick = { showDialog = false }) {
                            Text(stringResource(R.string.questionnaire_picker_cancel))
                        }
                        TextButton(
                            onClick = {
                                showDialog = false
                                val time = LocalTime.of(state.hour, state.minute)
                                emit(AnswerValue.Text(time.format(ISO_TIME)))
                            },
                            modifier = Modifier.testTag(
                                QuestionFieldTestTags.pickerConfirm(field.questionId),
                            ),
                        ) { Text(stringResource(R.string.questionnaire_picker_confirm)) }
                    }
                }
            }
        }
    }
}

// ---- Timezone ----

/** Timezone -> ExposedDropdownMenuBox over allowed/all zone ids. Emits Text(zoneId)/Empty. */
@Composable
private fun TimezoneQuestion(
    field: QuestionnaireField.Timezone,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val all = remember(field) { QuestionRenderSupport.timezoneOptions(field) }
    val selected = QuestionRenderSupport.selectedOption(answer).orEmpty()

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        var expanded by remember { mutableStateOf(false) }
        var query by remember(selected) { mutableStateOf(selected) }
        val filtered = remember(query, all) {
            if (query.isBlank()) all
            else all.filter { it.contains(query, ignoreCase = true) }
        }
        ExposedDropdownMenuBox(
            expanded = expanded && enabled,
            onExpandedChange = { if (enabled) expanded = it },
        ) {
            OutlinedTextField(
                value = query,
                onValueChange = {
                    query = it
                    expanded = true
                },
                enabled = enabled,
                label = { Text(stringResource(R.string.questionnaire_timezone_label)) },
                trailingIcon = {
                    ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded && enabled)
                },
                modifier = Modifier
                    .menuAnchor()
                    .fillMaxWidth()
                    .testTag(QuestionFieldTestTags.field(field.questionId)),
            )
            ExposedDropdownMenu(
                expanded = expanded && enabled,
                onDismissRequest = { expanded = false },
            ) {
                filtered.take(50).forEachIndexed { index, zone ->
                    DropdownMenuItem(
                        text = { Text(zone) },
                        onClick = {
                            expanded = false
                            query = zone
                            emit(QuestionRenderSupport.singleChoiceAnswer(zone))
                        },
                        modifier = Modifier.testTag(
                            QuestionFieldTestTags.option(field.questionId, index),
                        ),
                    )
                }
            }
        }
    }
    ErrorTag(field.questionId, error)
}

// ---- Address ----

/** Address -> structured group of TlTextFields. Encodes to a JSON-ish Text value (see support). */
@Composable
private fun AddressQuestion(
    field: QuestionnaireField.Address,
    answer: AnswerValue?,
    enabled: Boolean,
    error: String?,
    emit: (AnswerValue) -> Unit,
    modifier: Modifier,
) {
    val parts = QuestionRenderSupport.decodeAddress(answer)
    val required = QuestionRenderSupport.addressRequiredFields(field)

    QuestionFieldContainer(field.label, field.required, field.hint, error, enabled, modifier) {
        Column(
            modifier = Modifier.testTag(QuestionFieldTestTags.field(field.questionId)),
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            QuestionRenderSupport.ADDRESS_FIELDS.forEach { part ->
                val isRequired = field.required && part in required
                TlTextField(
                    value = parts[part].orEmpty(),
                    onValueChange = { newValue ->
                        val updated = parts.toMutableMap()
                        updated[part] = newValue
                        emit(QuestionRenderSupport.encodeAddress(updated))
                    },
                    label = labelWithRequired(addressPartLabel(part), isRequired),
                    enabled = enabled,
                    modifier = Modifier.testTag(
                        QuestionFieldTestTags.addressPart(field.questionId, part),
                    ),
                )
            }
        }
    }
    ErrorTag(field.questionId, error)
}

/** Human label for an address sub-field id. */
@Composable
private fun addressPartLabel(part: String): String = when (part) {
    "line1" -> stringResource(R.string.questionnaire_address_line1)
    "line2" -> stringResource(R.string.questionnaire_address_line2)
    "city" -> stringResource(R.string.questionnaire_address_city)
    "state" -> stringResource(R.string.questionnaire_address_state)
    "postalCode" -> stringResource(R.string.questionnaire_address_postal)
    "country" -> stringResource(R.string.questionnaire_address_country)
    else -> part
}

// ---- Unknown ----

/** Non-crashing placeholder for an unrecognized/future field type (FR-5). Emits nothing. */
@Composable
fun UnsupportedFieldPlaceholder(
    rawType: String,
    label: String,
    modifier: Modifier = Modifier,
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .testTag(QuestionFieldTestTags.unsupported(rawType)),
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Text(text = label, style = MaterialTheme.typography.bodyLarge)
            Text(
                text = stringResource(R.string.questionnaire_unsupported_field, rawType),
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
    }
}

// ---- shared bits ----

/** A read-only date/time field with an Open button and (when filled) a Clear button. */
@Composable
private fun PickerField(
    value: String,
    placeholder: String,
    enabled: Boolean,
    questionId: String,
    onOpen: () -> Unit,
    onClear: () -> Unit,
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.spacedBy(8.dp),
        verticalAlignment = Alignment.CenterVertically,
    ) {
        OutlinedTextField(
            value = value.ifBlank { "" },
            onValueChange = {},
            readOnly = true,
            enabled = enabled,
            placeholder = { Text(placeholder) },
            modifier = Modifier
                .weight(1f)
                .testTag(QuestionFieldTestTags.field(questionId)),
        )
        TlButton(
            text = stringResource(R.string.questionnaire_picker_open),
            onClick = onOpen,
            enabled = enabled,
            variant = TlButtonVariant.Secondary,
        )
        if (value.isNotBlank()) {
            TlButton(
                text = stringResource(R.string.questionnaire_picker_clear),
                onClick = onClear,
                enabled = enabled,
                variant = TlButtonVariant.Text,
                modifier = Modifier.testTag(QuestionFieldTestTags.clear(questionId)),
            )
        }
    }
}

/** Tags an invisible node carrying the error text so tests can target `qfield_error_<id>`. */
@Composable
private fun ErrorTag(questionId: String, error: String?) {
    if (error != null) {
        Text(
            text = error,
            style = MaterialTheme.typography.bodySmall,
            color = MaterialTheme.colorScheme.error,
            modifier = Modifier.testTag(QuestionFieldTestTags.error(questionId)),
        )
    }
}

/** Appends the required marker glyph to a label for controls that own their own label (TlTextField). */
@Composable
private fun labelWithRequired(label: String, required: Boolean): String =
    if (required) label + " " + stringResource(R.string.questionnaire_required_marker) else label

/** Affordance text describing min/max selection constraints (display-only; validation is AND-350). */
@Composable
private fun selectionAffordance(min: Int?, max: Int?): String? = when {
    min != null && max != null -> stringResource(R.string.questionnaire_select_min_max, min, max)
    min != null -> stringResource(R.string.questionnaire_select_min, min)
    max != null -> stringResource(R.string.questionnaire_select_max, max)
    else -> null
}
