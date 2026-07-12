package com.testlogon.android.feature.common.poll

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import com.testlogon.android.data.poll.PollComposeBody

/**
 * A draft for an ARBITRARY text-option poll (custom question + 2..N text options, single OR multi-select,
 * optional auto-close). Shared by the newsfeed / group / syndicate / messaging composers.
 */
data class PollDraft(
    val question: String = "",
    val options: List<String> = listOf("", ""),
    val multiSelect: Boolean = false,
    /** Optional auto-close horizon in hours from now (null = never / manual close). */
    val closesInHours: Int? = null,
    /** Sender-controlled: when true, voters may add their own write-in options. */
    val allowWriteIn: Boolean = false,
) {
    val trimmedOptions: List<String> get() = options.map { it.trim() }.filter { it.isNotEmpty() }
    val isValid: Boolean get() = question.isNotBlank() && trimmedOptions.size >= 2

    private fun closesAt(nowSeconds: Long): Long? = closesInHours?.let { nowSeconds + it * 3600L }

    /** The simple create body used by group / syndicate / messaging. */
    fun toComposeBody(nowSeconds: Long = System.currentTimeMillis() / 1000L): PollComposeBody =
        PollComposeBody(
            question = question.trim(),
            options = trimmedOptions,
            choiceMode = if (multiSelect) "multi" else "single",
            maxSelections = if (multiSelect) trimmedOptions.size else null,
            closesAt = closesAt(nowSeconds),
            allowWriteIn = allowWriteIn,
        )

    fun closesAtOrNull(nowSeconds: Long = System.currentTimeMillis() / 1000L): Long? = closesAt(nowSeconds)
}

object PollComposerTestTags {
    const val QUESTION = "poll_compose_question"
    const val ADD_OPTION = "poll_compose_add_option"
    const val MULTI_TOGGLE = "poll_compose_multi"
    const val SINGLE_TOGGLE = "poll_compose_single"
    const val WRITE_IN_TOGGLE = "poll_compose_write_in"
    fun option(index: Int) = "poll_compose_option_$index"
    fun removeOption(index: Int) = "poll_compose_remove_$index"
    fun duration(hours: Int) = "poll_compose_duration_$hours"
}

/**
 * Stateless arbitrary-poll composer section: a question field, 2..N option fields (add/remove), a
 * single/multi toggle and optional auto-close duration chips. State is hoisted via [draft]/[onChange].
 */
@Composable
fun PollComposer(
    draft: PollDraft,
    onChange: (PollDraft) -> Unit,
    modifier: Modifier = Modifier,
    enabled: Boolean = true,
) {
    Column(
        modifier = modifier.fillMaxWidth().testTag("poll_composer"),
        verticalArrangement = Arrangement.spacedBy(8.dp),
    ) {
        OutlinedTextField(
            value = draft.question,
            onValueChange = { onChange(draft.copy(question = it)) },
            enabled = enabled,
            singleLine = false,
            label = { Text("Poll question") },
            modifier = Modifier.fillMaxWidth().testTag(PollComposerTestTags.QUESTION),
        )

        draft.options.forEachIndexed { index, value ->
            Row(verticalAlignment = Alignment.CenterVertically) {
                OutlinedTextField(
                    value = value,
                    onValueChange = { text ->
                        onChange(draft.copy(options = draft.options.toMutableList().also { it[index] = text }))
                    },
                    enabled = enabled,
                    singleLine = true,
                    label = { Text("Option ${index + 1}") },
                    modifier = Modifier.weight(1f).testTag(PollComposerTestTags.option(index)),
                )
                if (draft.options.size > 2) {
                    IconButton(
                        onClick = {
                            onChange(draft.copy(options = draft.options.toMutableList().also { it.removeAt(index) }))
                        },
                        enabled = enabled,
                        modifier = Modifier.testTag(PollComposerTestTags.removeOption(index)),
                    ) { Icon(Icons.Outlined.Close, contentDescription = "Remove option") }
                }
            }
        }

        if (draft.options.size < 10) {
            TextButton(
                onClick = { onChange(draft.copy(options = draft.options + "")) },
                enabled = enabled,
                modifier = Modifier.testTag(PollComposerTestTags.ADD_OPTION),
            ) {
                Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                Text("Add option", modifier = Modifier.padding(start = 6.dp))
            }
        }

        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            FilterChip(
                selected = !draft.multiSelect,
                onClick = { onChange(draft.copy(multiSelect = false)) },
                enabled = enabled,
                label = { Text("Single choice") },
                modifier = Modifier.testTag(PollComposerTestTags.SINGLE_TOGGLE),
            )
            FilterChip(
                selected = draft.multiSelect,
                onClick = { onChange(draft.copy(multiSelect = true)) },
                enabled = enabled,
                label = { Text("Multi-select") },
                modifier = Modifier.testTag(PollComposerTestTags.MULTI_TOGGLE),
            )
        }

        // Sender-controlled write-in: when on, voters may add their own options to this poll.
        Row(verticalAlignment = Alignment.CenterVertically) {
            Column(modifier = Modifier.weight(1f)) {
                Text("Allow write-in answers", style = MaterialTheme.typography.labelLarge)
                Text(
                    "Voters can add their own options",
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            androidx.compose.material3.Switch(
                checked = draft.allowWriteIn,
                onCheckedChange = { onChange(draft.copy(allowWriteIn = it)) },
                enabled = enabled,
                modifier = Modifier.testTag(PollComposerTestTags.WRITE_IN_TOGGLE),
            )
        }

        Text("Auto-close", style = MaterialTheme.typography.labelMedium)
        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
            val choices = listOf<Pair<String, Int?>>("Never" to null, "1h" to 1, "1d" to 24, "1w" to 168)
            choices.forEach { (label, hours) ->
                FilterChip(
                    selected = draft.closesInHours == hours,
                    onClick = { onChange(draft.copy(closesInHours = hours)) },
                    enabled = enabled,
                    label = { Text(label) },
                    modifier = Modifier.testTag(PollComposerTestTags.duration(hours ?: 0)),
                )
            }
        }
    }
}
