@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.legal

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.DatePicker
import androidx.compose.material3.DatePickerDialog
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.SelectableDates
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.rememberDatePickerState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.FormatStyle

/**
 * PAR-29 — pure, Android-free whole-year age math (mirrors the iOS `AgeCheck`). Unit-testable: no
 * Compose / framework dependencies. A birthday that has not yet occurred this year does NOT count.
 */
object AgeCheck {
    /** Whole years between [dob] and [asOf] (default today, UTC). Never negative for a future DOB → 0. */
    fun ageInYears(dob: LocalDate, asOf: LocalDate = LocalDate.now(ZoneOffset.UTC)): Int {
        if (dob.isAfter(asOf)) return 0
        var years = asOf.year - dob.year
        // Subtract one if this year's birthday hasn't happened yet (whole-year, not fractional).
        val hadBirthdayThisYear =
            asOf.monthValue > dob.monthValue ||
                (asOf.monthValue == dob.monthValue && asOf.dayOfMonth >= dob.dayOfMonth)
        if (!hadBirthdayThisYear) years -= 1
        return years.coerceAtLeast(0)
    }

    /** True when the person born on [dob] is at least [minimumAge] whole years old as of [asOf]. */
    fun isOldEnough(
        dob: LocalDate,
        minimumAge: Int = LegalConstants.MINIMUM_AGE,
        asOf: LocalDate = LocalDate.now(ZoneOffset.UTC),
    ): Boolean = ageInYears(dob, asOf) >= minimumAge
}

/** PAR-29 — stable testTags for the reusable date-of-birth age gate. */
object AgeGateTestTags {
    const val PICK_BUTTON = "age_gate_pick_dob"
    const val ERROR = "age_gate_error"
    const val SELECTED = "age_gate_selected"
}

/**
 * PAR-29 — a reusable date-of-birth gate. Opens the Material [DatePicker], validates the whole-year age
 * against [minimumAge] via [AgeCheck], and reports the result through [onResult] (dob + isOldEnough).
 * Under-age selections surface an inline error and do NOT report a passing result. Framework-independent
 * validation lives in [AgeCheck] so it can be unit-tested without Compose.
 *
 * Left as a reusable component: not yet wired into registration (see PAR-29 notes) — a caller can drop
 * this into any onboarding step and gate progression on [AgeGateResult.isOldEnough].
 */
@Composable
fun DateOfBirthGate(
    onResult: (AgeGateResult) -> Unit,
    modifier: Modifier = Modifier,
    minimumAge: Int = LegalConstants.MINIMUM_AGE,
) {
    var showPicker by remember { mutableStateOf(false) }
    var selected by remember { mutableStateOf<LocalDate?>(null) }
    var underAge by remember { mutableStateOf(false) }

    val formatter = remember { DateTimeFormatter.ofLocalizedDate(FormatStyle.MEDIUM) }

    Column(
        modifier = modifier.fillMaxWidth(),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedButton(
            onClick = { showPicker = true },
            modifier = Modifier.fillMaxWidth().testTag(AgeGateTestTags.PICK_BUTTON),
        ) {
            Text(
                selected?.let { stringResource(R.string.age_gate_dob_value, it.format(formatter)) }
                    ?: stringResource(R.string.age_gate_pick_dob),
            )
        }

        selected?.let { dob ->
            Text(
                text = dob.format(formatter),
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.testTag(AgeGateTestTags.SELECTED),
            )
        }

        if (underAge) {
            Text(
                text = stringResource(R.string.age_gate_too_young, minimumAge),
                color = MaterialTheme.colorScheme.error,
                style = MaterialTheme.typography.bodySmall,
                modifier = Modifier.padding(top = 4.dp).testTag(AgeGateTestTags.ERROR),
            )
        }
    }

    if (showPicker) {
        val todayMillis = remember { LocalDate.now(ZoneOffset.UTC).atStartOfDay(ZoneOffset.UTC).toInstant().toEpochMilli() }
        val datePickerState = rememberDatePickerState(
            // A birth date can never be in the future.
            selectableDates = object : SelectableDates {
                override fun isSelectableDate(utcTimeMillis: Long): Boolean = utcTimeMillis <= todayMillis
            },
        )
        DatePickerDialog(
            onDismissRequest = { showPicker = false },
            confirmButton = {
                TextButton(onClick = {
                    val millis = datePickerState.selectedDateMillis
                    if (millis != null) {
                        val dob = Instant.ofEpochMilli(millis).atZone(ZoneOffset.UTC).toLocalDate()
                        selected = dob
                        val ok = AgeCheck.isOldEnough(dob, minimumAge)
                        underAge = !ok
                        onResult(AgeGateResult(dob = dob, isOldEnough = ok))
                    }
                    showPicker = false
                }) { Text(stringResource(R.string.age_gate_confirm)) }
            },
            dismissButton = {
                TextButton(onClick = { showPicker = false }) {
                    Text(stringResource(R.string.age_gate_cancel))
                }
            },
        ) {
            DatePicker(state = datePickerState)
        }
    }
}

/** PAR-29 — the outcome of an [DateOfBirthGate] selection. */
data class AgeGateResult(
    val dob: LocalDate,
    val isOldEnough: Boolean,
)
