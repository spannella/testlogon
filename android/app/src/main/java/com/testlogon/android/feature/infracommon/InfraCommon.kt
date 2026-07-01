@file:OptIn(androidx.compose.material3.ExperimentalMaterial3Api::class)

package com.testlogon.android.feature.infracommon

import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExposedDropdownMenuBox
import androidx.compose.material3.DropdownMenuItem
import androidx.compose.material3.ExposedDropdownMenuDefaults
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.feature.adminmod.AdminOpsErrorType

/**
 * B7 Cloud-Infra shared UI helpers, used by all six management screens (EC2, K8s, security-groups,
 * host inventory, instance monitoring, compute billing). Keeps the per-screen files idiomatic and DRY.
 */

/** Shared transient-error copy, mirroring the fraud/admin-ops mapper. */
fun infraErrorMessage(type: AdminOpsErrorType): String = when (type) {
    AdminOpsErrorType.AUTH -> "Your session expired. Please sign in again."
    AdminOpsErrorType.SERVER -> "Something went wrong on the server. Try again."
    AdminOpsErrorType.NETWORK -> "You appear to be offline. Check your connection."
}

/** USD money from cents. */
fun centsToUsd(cents: Long): String = "$%,.2f".format(cents / 100.0)

/** A resource-status → semantic color mapping for pill/label chips (running=green-ish, etc.). */
@Composable
fun statusColor(status: String): Color = when (status.lowercase()) {
    "running", "active", "healthy", "published" -> MaterialTheme.colorScheme.primary
    "pending", "starting", "provisioning", "launching", "warning", "rebooting", "stopping" ->
        MaterialTheme.colorScheme.tertiary
    "stopped", "terminated", "critical", "failed", "error" -> MaterialTheme.colorScheme.error
    else -> MaterialTheme.colorScheme.onSurfaceVariant
}

/**
 * A reusable single-select dropdown (Material3 ExposedDropdownMenuBox). [options] are the raw values;
 * [labelFor] renders each option (and the current selection). [fieldTestTag] identifies the field.
 */
@Composable
fun <T> InfraDropdown(
    label: String,
    options: List<T>,
    selected: T?,
    labelFor: (T) -> String,
    onSelect: (T) -> Unit,
    fieldTestTag: String,
    modifier: Modifier = Modifier,
) {
    var expanded by remember { mutableStateOf(false) }
    ExposedDropdownMenuBox(
        expanded = expanded,
        onExpandedChange = { expanded = it },
        modifier = modifier,
    ) {
        OutlinedTextField(
            value = selected?.let(labelFor) ?: "",
            onValueChange = {},
            readOnly = true,
            label = { Text(label) },
            trailingIcon = { ExposedDropdownMenuDefaults.TrailingIcon(expanded = expanded) },
            modifier = Modifier
                .menuAnchor()
                .fillMaxWidth()
                .testTag(fieldTestTag),
        )
        ExposedDropdownMenu(expanded = expanded, onDismissRequest = { expanded = false }) {
            options.forEach { opt ->
                DropdownMenuItem(
                    text = { Text(labelFor(opt)) },
                    onClick = {
                        onSelect(opt)
                        expanded = false
                    },
                )
            }
        }
    }
}

/** A subtle section header. */
@Composable
fun InfraSectionHeader(text: String, modifier: Modifier = Modifier) {
    Box(modifier = modifier.padding(vertical = 4.dp)) {
        Text(text, style = MaterialTheme.typography.titleSmall, color = MaterialTheme.colorScheme.primary)
    }
}
