@file:OptIn(ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.licenses.compliance

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.text.KeyboardOptions

private val FLAG_REASONS = listOf(
    "unlicensed_music",
    "unlicensed_video",
    "unlicensed_image",
    "expired_license",
    "copyright_claim",
    "other",
)

/** Dialog to flag (report) a content item for a licensing issue. Mirrors web FlagContentDialog. */
@Composable
fun FlagContentDialog(
    isSubmitting: Boolean,
    onDismiss: () -> Unit,
    onSubmit: (contentId: String, reason: String, evidence: String) -> Unit,
) {
    var contentId by remember { mutableStateOf("") }
    var reason by remember { mutableStateOf(FLAG_REASONS.first()) }
    var evidence by remember { mutableStateOf("") }
    var menuExpanded by remember { mutableStateOf(false) }

    AlertDialog(
        onDismissRequest = onDismiss,
        modifier = Modifier.testTag("compliance_flag_dialog"),
        title = { Text("Report Licensing Issue") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Text("Flag content you believe uses unlicensed material. Reports go to platform admins.")
                OutlinedTextField(
                    value = contentId,
                    onValueChange = { contentId = it },
                    label = { Text("Content ID") },
                    singleLine = true,
                    placeholder = { Text("vid_xyz789") },
                    modifier = Modifier.fillMaxWidth().testTag("compliance_flag_content_id"),
                )
                ExposedDropdownMenuBox(
                    expanded = menuExpanded,
                    onExpandedChange = { menuExpanded = it },
                ) {
                    OutlinedTextField(
                        value = reason.replace('_', ' '),
                        onValueChange = {},
                        readOnly = true,
                        label = { Text("Reason") },
                        trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = menuExpanded) },
                        modifier = Modifier
                            .fillMaxWidth()
                            .menuAnchor()
                            .testTag("compliance_flag_reason"),
                    )
                    ExposedDropdownMenu(
                        expanded = menuExpanded,
                        onDismissRequest = { menuExpanded = false },
                    ) {
                        FLAG_REASONS.forEach { r ->
                            DropdownMenuItem(
                                text = { Text(r.replace('_', ' ')) },
                                onClick = {
                                    reason = r
                                    menuExpanded = false
                                },
                            )
                        }
                    }
                }
                OutlinedTextField(
                    value = evidence,
                    onValueChange = { if (it.length <= 2000) evidence = it },
                    label = { Text("Evidence (optional)") },
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Text),
                    modifier = Modifier.fillMaxWidth().testTag("compliance_flag_evidence"),
                )
            }
        },
        confirmButton = {
            TextButton(
                onClick = { onSubmit(contentId, reason, evidence) },
                enabled = !isSubmitting && contentId.isNotBlank(),
                modifier = Modifier.testTag("compliance_flag_submit"),
            ) { Text(if (isSubmitting) "Submitting..." else "Submit Flag") }
        },
        dismissButton = {
            TextButton(onClick = onDismiss) { Text("Cancel") }
        },
    )
}
