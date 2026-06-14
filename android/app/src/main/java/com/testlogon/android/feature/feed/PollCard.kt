package com.testlogon.android.feature.feed

import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.feed.PollOption
import com.testlogon.android.data.feed.PollQuestion

/** Stable test tags for the poll card (AND-179). */
object PollCardTestTags {
    const val CARD = "poll_card"
    const val TOTAL = "poll_total"
    const val CLOSED = "poll_closed"
    const val ERROR = "poll_error"
    const val RETRY = "poll_retry"
    fun option(optionId: String): String = "poll_option_$optionId"
}

/**
 * AND-179 — renders a poll embedded in a post: each question's text, its options as selectable rows with
 * a results bar + count/percent (computed against the QUESTION total), the poll-wide total-votes label,
 * and a "Poll closed" / inline-error+retry affordance. Stateless; all state arrives via [state] and
 * events are hoisted up. Single-select voting; multi polls render read-only (FR-9).
 */
@Composable
fun PollCard(
    state: PollCardState,
    onOptionClick: (questionId: String, optionId: String) -> Unit,
    onRetry: (questionId: String, optionId: String) -> Unit,
    modifier: Modifier = Modifier,
) {
    val poll = state.poll
    val readOnly = state !is PollCardState.Idle || !poll.isInteractive
    val voting = state as? PollCardState.Voting
    val error = state as? PollCardState.Error

    Column(
        modifier = modifier
            .fillMaxWidth()
            .clip(RoundedCornerShape(12.dp))
            .background(MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.4f))
            .padding(12.dp)
            .testTag(PollCardTestTags.CARD),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        poll.questions.forEach { question ->
            PollQuestionBlock(
                question = question,
                readOnly = readOnly,
                pendingOptionId = voting?.takeIf { it.questionId == question.id }?.pendingOptionId,
                onOptionClick = { optionId -> onOptionClick(question.id, optionId) },
            )
        }

        Text(
            text = pluralStringResource(R.plurals.poll_total_votes, poll.totalVotes, poll.totalVotes),
            style = MaterialTheme.typography.labelMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.testTag(PollCardTestTags.TOTAL),
        )

        if (poll.closed) {
            Text(
                text = stringResource(R.string.poll_closed),
                style = MaterialTheme.typography.labelMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
                modifier = Modifier.testTag(PollCardTestTags.CLOSED),
            )
        }

        if (error != null) {
            Row(
                modifier = Modifier.fillMaxWidth().testTag(PollCardTestTags.ERROR),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = error.message,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error,
                    modifier = Modifier.weight(1f),
                )
                // Retry the first option of the errored question as a best-effort affordance.
                val firstOption = poll.questions.firstOrNull { it.id == error.questionId }?.options?.firstOrNull()
                if (firstOption != null) {
                    TextButton(
                        onClick = { onRetry(error.questionId, firstOption.id) },
                        modifier = Modifier.testTag(PollCardTestTags.RETRY),
                    ) { Text(stringResource(R.string.poll_retry)) }
                }
            }
        }
    }
}

@Composable
private fun PollQuestionBlock(
    question: PollQuestion,
    readOnly: Boolean,
    pendingOptionId: String?,
    onOptionClick: (optionId: String) -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.selectableGroup()) {
        if (question.text.isNotBlank()) {
            Text(
                text = question.text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
        question.options.forEach { option ->
            PollOptionRow(
                question = question,
                option = option,
                readOnly = readOnly,
                pending = option.id == pendingOptionId,
                onClick = { onOptionClick(option.id) },
            )
        }
    }
}

@Composable
private fun PollOptionRow(
    question: PollQuestion,
    option: PollOption,
    readOnly: Boolean,
    pending: Boolean,
    onClick: () -> Unit,
) {
    val selected = question.isOptionSelected(option.id)
    val percent = question.percentFor(option.id)
    val count = question.countFor(option.id)
    val animatedFraction by animateFloatAsState(
        targetValue = percent / 100f,
        label = "pollBar",
    )
    val selectedLabel = stringResource(
        if (selected) R.string.poll_option_selected else R.string.poll_option_not_selected,
    )
    val rowDesc = stringResource(R.string.poll_option_desc, option.text, percent, selectedLabel)

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surface)
            .selectable(
                selected = selected,
                enabled = !readOnly,
                role = Role.RadioButton,
                onClick = onClick,
            )
            .testTag(PollCardTestTags.option(option.id))
            .clearAndSetSemantics { contentDescription = rowDesc },
    ) {
        // Results bar fill behind the label.
        Box(
            modifier = Modifier
                .fillMaxWidth(animatedFraction)
                .height(44.dp)
                .background(
                    if (selected) {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
                    } else {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                    },
                ),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).height(44.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = option.text,
                style = MaterialTheme.typography.bodyMedium,
                fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                modifier = Modifier.weight(1f),
            )
            if (pending) {
                CircularProgressIndicator(strokeWidth = 2.dp, modifier = Modifier.size(16.dp))
            } else {
                Text(
                    text = "$percent% ($count)",
                    style = MaterialTheme.typography.labelMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
        }
    }
}
