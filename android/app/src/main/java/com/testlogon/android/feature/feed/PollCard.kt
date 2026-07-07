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
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.pluralStringResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.clearAndSetSemantics
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.testlogon.android.R
import com.testlogon.android.data.feed.PollOption
import com.testlogon.android.data.feed.PollQuestion

/** Stable test tags for the poll card (AND-179 + write-in). */
object PollCardTestTags {
    const val CARD = "poll_card"
    const val TOTAL = "poll_total"
    const val CLOSED = "poll_closed"
    const val ERROR = "poll_error"
    const val RETRY = "poll_retry"
    fun option(optionId: String): String = "poll_option_$optionId"
    fun writeInAdd(questionId: String) = "poll_writein_add_$questionId"
    fun writeInInput(questionId: String) = "poll_writein_input_$questionId"
    fun writeInSubmit(questionId: String) = "poll_writein_submit_$questionId"
    fun more(questionId: String) = "poll_more_$questionId"
}

/** Options shown before the "show more" control for write-in questions (matches the backend top_n=5). */
private const val WRITE_IN_TOP_N = 5

/**
 * AND-179 (+ multi-select + write-in) — renders a poll embedded in a post. Each question's options are
 * selectable rows with a results bar + count/percent; the poll-wide total; a "Poll closed" / inline
 * error+retry affordance. FULL multi-select: a MULTI question stays interactive and each tap toggles an
 * option; a single question can change its vote when the poll allows it. WRITE-IN questions render the
 * top 5 options by count, a "+" to add your own answer and a "Show more" control that pages the rest.
 * Vote state arrives via [state]; write-in text + reveal is kept locally.
 */
@Composable
fun PollCard(
    state: PollCardState,
    onOptionClick: (questionId: String, optionId: String) -> Unit,
    onRetry: (questionId: String, optionId: String) -> Unit,
    modifier: Modifier = Modifier,
    onWriteIn: (questionId: String, text: String) -> Unit = { _, _ -> },
    onShowMore: (questionId: String, offset: Int) -> Unit = { _, _ -> },
) {
    val poll = state.poll
    val cardInteractive = state is PollCardState.Idle && poll.isInteractive
    val voting = state as? PollCardState.Voting
    val error = state as? PollCardState.Error

    // Local per-question write-in UI state (survives recomposition; keyed to this poll's post id).
    val revealed = remember(poll.postId) { mutableStateMapOf<String, Int>() }
    val writeInOpen = remember(poll.postId) { mutableStateMapOf<String, Boolean>() }
    val writeInText = remember(poll.postId) { mutableStateMapOf<String, String>() }

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
            // Per-question interactivity: an OPEN card; a single already-voted question locks unless the
            // poll allows vote changes (multi always re-toggles; the backend is the final authority).
            val questionInteractive = cardInteractive &&
                (question.isMulti || !question.hasVoted || poll.allowVoteChange)
            PollQuestionBlock(
                question = question,
                interactive = questionInteractive,
                pendingOptionId = voting?.takeIf { it.questionId == question.id }?.pendingOptionId,
                revealed = revealed[question.id] ?: WRITE_IN_TOP_N,
                writeInOpen = writeInOpen[question.id] == true,
                writeInText = writeInText[question.id] ?: "",
                onOptionClick = { optionId -> onOptionClick(question.id, optionId) },
                onToggleWriteIn = { writeInOpen[question.id] = !(writeInOpen[question.id] ?: false) },
                onWriteInTextChange = { writeInText[question.id] = it },
                onSubmitWriteIn = {
                    val text = (writeInText[question.id] ?: "").trim()
                    if (text.isNotEmpty()) {
                        onWriteIn(question.id, text)
                        writeInText[question.id] = ""
                        writeInOpen[question.id] = false
                        // Reveal everything so the just-added answer is visible in the list.
                        revealed[question.id] = Int.MAX_VALUE
                    }
                },
                onShowMore = {
                    val current = revealed[question.id] ?: WRITE_IN_TOP_N
                    onShowMore(question.id, current)
                    revealed[question.id] = current + WRITE_IN_TOP_N
                },
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
    interactive: Boolean,
    pendingOptionId: String?,
    revealed: Int,
    writeInOpen: Boolean,
    writeInText: String,
    onOptionClick: (optionId: String) -> Unit,
    onToggleWriteIn: () -> Unit,
    onWriteInTextChange: (String) -> Unit,
    onSubmitWriteIn: () -> Unit,
    onShowMore: () -> Unit,
) {
    Column(verticalArrangement = Arrangement.spacedBy(6.dp), modifier = Modifier.selectableGroup()) {
        if (question.text.isNotBlank()) {
            Text(
                text = question.text,
                style = MaterialTheme.typography.titleSmall,
                fontWeight = FontWeight.SemiBold,
            )
        }
        if (question.isMulti) {
            Text(
                text = "Select one or more",
                style = MaterialTheme.typography.labelSmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }

        // Write-in questions render the TOP N by count then page the rest; fixed polls render as-is.
        val displayOptions = if (question.allowWriteIn) {
            question.optionsByCount.take(revealed.coerceAtLeast(WRITE_IN_TOP_N))
        } else {
            question.options
        }
        displayOptions.forEach { option ->
            PollOptionRow(
                question = question,
                option = option,
                readOnly = !interactive,
                pending = option.id == pendingOptionId,
                onClick = { onOptionClick(option.id) },
            )
        }

        if (question.allowWriteIn) {
            val remaining = question.options.size - displayOptions.size
            if (remaining > 0) {
                TextButton(
                    onClick = onShowMore,
                    modifier = Modifier.testTag(PollCardTestTags.more(question.id)),
                ) { Text("Show more ($remaining)") }
            }

            if (interactive) {
                if (writeInOpen) {
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        OutlinedTextField(
                            value = writeInText,
                            onValueChange = onWriteInTextChange,
                            singleLine = true,
                            label = { Text("Your answer") },
                            keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
                            keyboardActions = KeyboardActions(onDone = { onSubmitWriteIn() }),
                            modifier = Modifier
                                .weight(1f)
                                .testTag(PollCardTestTags.writeInInput(question.id)),
                        )
                        TextButton(
                            onClick = onSubmitWriteIn,
                            enabled = writeInText.isNotBlank(),
                            modifier = Modifier.testTag(PollCardTestTags.writeInSubmit(question.id)),
                        ) { Text("Add") }
                    }
                } else {
                    TextButton(
                        onClick = onToggleWriteIn,
                        modifier = Modifier.testTag(PollCardTestTags.writeInAdd(question.id)),
                    ) {
                        Icon(Icons.Filled.Add, contentDescription = null, modifier = Modifier.size(18.dp))
                        Text("Add your own answer", modifier = Modifier.padding(start = 6.dp))
                    }
                }
            }
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
    val writeInSuffix = if (option.isWriteIn) " (added by a voter)" else ""
    val rowDesc = stringResource(R.string.poll_option_desc, option.text, percent, selectedLabel) + writeInSuffix

    Box(
        modifier = Modifier
            .fillMaxWidth()
            .height(if (option.isWriteIn) 52.dp else 44.dp)
            .clip(RoundedCornerShape(8.dp))
            .background(MaterialTheme.colorScheme.surface)
            .selectable(
                selected = selected,
                enabled = !readOnly,
                role = if (question.isMulti) Role.Checkbox else Role.RadioButton,
                onClick = onClick,
            )
            .testTag(PollCardTestTags.option(option.id))
            .clearAndSetSemantics { contentDescription = rowDesc },
    ) {
        // Results bar fill behind the label.
        Box(
            modifier = Modifier
                .fillMaxWidth(animatedFraction)
                .height(if (option.isWriteIn) 52.dp else 44.dp)
                .background(
                    if (selected) {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.25f)
                    } else {
                        MaterialTheme.colorScheme.primary.copy(alpha = 0.10f)
                    },
                ),
        )
        Row(
            modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp).height(if (option.isWriteIn) 52.dp else 44.dp),
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = option.text,
                    style = MaterialTheme.typography.bodyMedium,
                    fontWeight = if (selected) FontWeight.SemiBold else FontWeight.Normal,
                )
                if (option.isWriteIn) {
                    Text(
                        text = "Added by a voter",
                        style = MaterialTheme.typography.labelSmall,
                        fontStyle = FontStyle.Italic,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                }
            }
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
