package com.testlogon.android.data.bots

import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Framework-free bots domain models + total DTO -> domain mappers.
 *
 * Timestamps are epoch-seconds; mapping is total (absent optionals default per the schema). [BotStatus]
 * / [AutoReplyMatchType] / [TemplateCategory] fold the server strings into closed enums (+ UNKNOWN /
 * CUSTOM). Time formatting uses SimpleDateFormat/Date (core-library desugaring is off, so java.time is
 * unavailable) and stays JVM-unit-testable.
 */
enum class BotStatus {
    ACTIVE,
    PAUSED,
    DISABLED,
    UNKNOWN;

    /** The raw value the server expects when toggling. */
    val wire: String
        get() = when (this) {
            ACTIVE -> "active"
            PAUSED -> "paused"
            DISABLED -> "disabled"
            UNKNOWN -> "active"
        }

    companion object {
        fun from(raw: String?): BotStatus = when (raw?.lowercase(Locale.US)) {
            "active" -> ACTIVE
            "paused" -> PAUSED
            "disabled" -> DISABLED
            else -> UNKNOWN
        }
    }
}

data class Bot(
    val id: String,
    val name: String,
    val description: String?,
    val personality: String?,
    val status: BotStatus,
    val messageCount: Int,
    val createdAtSeconds: Long,
) {
    /** Active bots can be paused; paused/disabled bots can be (re)activated. */
    val isActive: Boolean get() = status == BotStatus.ACTIVE

    fun formattedCreated(): String =
        if (createdAtSeconds <= 0L) "" else DATE_FORMAT.format(Date(createdAtSeconds * 1000L))

    private companion object {
        private val DATE_FORMAT = SimpleDateFormat("MMM d, yyyy", Locale.getDefault())
    }
}

enum class AutoReplyMatchType {
    KEYWORD,
    CONTAINS,
    EXACT,
    REGEX;

    val wire: String
        get() = when (this) {
            KEYWORD -> "keyword"
            CONTAINS -> "contains"
            EXACT -> "exact"
            REGEX -> "regex"
        }

    companion object {
        fun from(raw: String?): AutoReplyMatchType = when (raw?.lowercase(Locale.US)) {
            "contains" -> CONTAINS
            "exact" -> EXACT
            "regex" -> REGEX
            else -> KEYWORD
        }
    }
}

data class AutoReplyRule(
    val id: String,
    val triggerPattern: String,
    val responseTemplate: String,
    val matchType: AutoReplyMatchType,
    val priority: Int,
    val enabled: Boolean,
    val matchCount: Int,
)

enum class TemplateCategory {
    GREETING,
    SUPPORT,
    PROMOTION,
    FAREWELL,
    AWAY,
    CUSTOM;

    val wire: String
        get() = when (this) {
            GREETING -> "greeting"
            SUPPORT -> "support"
            PROMOTION -> "promotion"
            FAREWELL -> "farewell"
            AWAY -> "away"
            CUSTOM -> "custom"
        }

    companion object {
        fun from(raw: String?): TemplateCategory = when (raw?.lowercase(Locale.US)) {
            "greeting" -> GREETING
            "support" -> SUPPORT
            "promotion" -> PROMOTION
            "farewell" -> FAREWELL
            "away" -> AWAY
            else -> CUSTOM
        }
    }
}

data class BotTemplate(
    val id: String,
    val name: String,
    val text: String,
    val category: TemplateCategory,
    val bodyFormat: String,
)

// ---- Mappers (DTO -> domain) ----

internal fun BotDto.toDomain(): Bot = Bot(
    id = botId,
    name = name,
    description = description?.takeIf { it.isNotBlank() },
    personality = personality?.takeIf { it.isNotBlank() },
    status = BotStatus.from(status),
    messageCount = messageCount,
    createdAtSeconds = createdAt,
)

internal fun BotListDto.toDomain(): List<Bot> = bots.map { it.toDomain() }

internal fun AutoReplyRuleDto.toDomain(): AutoReplyRule = AutoReplyRule(
    id = ruleId,
    triggerPattern = triggerPattern,
    responseTemplate = responseTemplate,
    matchType = AutoReplyMatchType.from(matchType),
    priority = priority,
    enabled = enabled,
    matchCount = matchCount,
)

internal fun AutoReplyListDto.toDomain(): List<AutoReplyRule> = rules.map { it.toDomain() }

internal fun TemplateDto.toDomain(): BotTemplate = BotTemplate(
    id = templateId,
    name = name,
    text = text,
    category = TemplateCategory.from(category),
    bodyFormat = bodyFormat,
)
