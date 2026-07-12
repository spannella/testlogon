package com.testlogon.android.data.bots

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Pure JVM unit tests for the bots domain mappers + enum string folding ([BotsDomain]).
 * No coroutines / Android framework -- just total DTO -> domain mapping.
 */
class BotsDomainTest {

    // ---- BotStatus mapping ----

    @Test
    fun botStatus_from_mapsKnownStrings() {
        assertEquals(BotStatus.ACTIVE, BotStatus.from("active"))
        assertEquals(BotStatus.PAUSED, BotStatus.from("paused"))
        assertEquals(BotStatus.DISABLED, BotStatus.from("disabled"))
    }

    @Test
    fun botStatus_from_isCaseInsensitive() {
        assertEquals(BotStatus.ACTIVE, BotStatus.from("ACTIVE"))
        assertEquals(BotStatus.PAUSED, BotStatus.from("Paused"))
    }

    @Test
    fun botStatus_from_unknownOrNull_foldsToUnknown() {
        assertEquals(BotStatus.UNKNOWN, BotStatus.from("archived"))
        assertEquals(BotStatus.UNKNOWN, BotStatus.from(null))
        assertEquals(BotStatus.UNKNOWN, BotStatus.from(""))
    }

    @Test
    fun botStatus_wire_roundTripsKnownAndUnknownDefaultsToActive() {
        assertEquals("active", BotStatus.ACTIVE.wire)
        assertEquals("paused", BotStatus.PAUSED.wire)
        assertEquals("disabled", BotStatus.DISABLED.wire)
        assertEquals("active", BotStatus.UNKNOWN.wire)
    }

    // ---- AutoReplyMatchType mapping ----

    @Test
    fun matchType_from_mapsKnownStrings() {
        assertEquals(AutoReplyMatchType.KEYWORD, AutoReplyMatchType.from("keyword"))
        assertEquals(AutoReplyMatchType.CONTAINS, AutoReplyMatchType.from("contains"))
        assertEquals(AutoReplyMatchType.EXACT, AutoReplyMatchType.from("exact"))
        assertEquals(AutoReplyMatchType.REGEX, AutoReplyMatchType.from("regex"))
    }

    @Test
    fun matchType_from_unknownOrNull_defaultsToKeyword() {
        assertEquals(AutoReplyMatchType.KEYWORD, AutoReplyMatchType.from("fuzzy"))
        assertEquals(AutoReplyMatchType.KEYWORD, AutoReplyMatchType.from(null))
    }

    @Test
    fun matchType_wire_matchesServerStrings() {
        assertEquals("keyword", AutoReplyMatchType.KEYWORD.wire)
        assertEquals("contains", AutoReplyMatchType.CONTAINS.wire)
        assertEquals("exact", AutoReplyMatchType.EXACT.wire)
        assertEquals("regex", AutoReplyMatchType.REGEX.wire)
    }

    // ---- TemplateCategory mapping ----

    @Test
    fun templateCategory_from_mapsKnownStrings() {
        assertEquals(TemplateCategory.GREETING, TemplateCategory.from("greeting"))
        assertEquals(TemplateCategory.SUPPORT, TemplateCategory.from("support"))
        assertEquals(TemplateCategory.PROMOTION, TemplateCategory.from("promotion"))
        assertEquals(TemplateCategory.FAREWELL, TemplateCategory.from("farewell"))
        assertEquals(TemplateCategory.AWAY, TemplateCategory.from("away"))
    }

    @Test
    fun templateCategory_from_unknownOrNull_foldsToCustom() {
        assertEquals(TemplateCategory.CUSTOM, TemplateCategory.from("custom"))
        assertEquals(TemplateCategory.CUSTOM, TemplateCategory.from("weird"))
        assertEquals(TemplateCategory.CUSTOM, TemplateCategory.from(null))
    }

    @Test
    fun templateCategory_wire_matchesServerStrings() {
        assertEquals("greeting", TemplateCategory.GREETING.wire)
        assertEquals("custom", TemplateCategory.CUSTOM.wire)
    }

    // ---- BotDto -> Bot ----

    @Test
    fun botDto_toDomain_mapsAllFields() {
        val dto = BotDto(
            botId = "bot_7",
            creatorId = "c1",
            name = "Helper",
            description = "does things",
            personality = "kind",
            status = "paused",
            createdAt = 1_700_000_000L,
            messageCount = 12,
        )
        val bot = dto.toDomain()
        assertEquals("bot_7", bot.id)
        assertEquals("Helper", bot.name)
        assertEquals("does things", bot.description)
        assertEquals("kind", bot.personality)
        assertEquals(BotStatus.PAUSED, bot.status)
        assertEquals(12, bot.messageCount)
        assertEquals(1_700_000_000L, bot.createdAtSeconds)
    }

    @Test
    fun botDto_toDomain_blankOptionalsBecomeNull() {
        val dto = BotDto(botId = "bot_1", description = "  ", personality = "")
        val bot = dto.toDomain()
        assertNull(bot.description)
        assertNull(bot.personality)
    }

    @Test
    fun botDto_toDomain_unknownStatusFoldsToUnknown() {
        val bot = BotDto(botId = "bot_1", status = "archived").toDomain()
        assertEquals(BotStatus.UNKNOWN, bot.status)
        assertEquals("", bot.formattedCreated()) // createdAt defaults 0 -> empty
    }

    @Test
    fun bot_isActive_reflectsStatus() {
        assertTrue(BotDto(botId = "b", status = "active").toDomain().isActive)
        assertTrue(!BotDto(botId = "b", status = "paused").toDomain().isActive)
    }

    @Test
    fun botListDto_toDomain_mapsEachBot() {
        val list = BotListDto(
            bots = listOf(
                BotDto(botId = "a", status = "active"),
                BotDto(botId = "b", status = "disabled"),
            ),
        ).toDomain()
        assertEquals(2, list.size)
        assertEquals("a", list[0].id)
        assertEquals(BotStatus.ACTIVE, list[0].status)
        assertEquals(BotStatus.DISABLED, list[1].status)
    }

    @Test
    fun botListDto_toDomain_emptyList_mapsToEmpty() {
        assertTrue(BotListDto().toDomain().isEmpty())
    }

    // ---- AutoReplyRuleDto -> AutoReplyRule ----

    @Test
    fun autoReplyRuleDto_toDomain_mapsAllFields() {
        val dto = AutoReplyRuleDto(
            ruleId = "rule_3",
            botId = "bot_1",
            triggerPattern = "hello",
            responseTemplate = "hi",
            matchType = "regex",
            priority = 55,
            enabled = false,
            matchCount = 9,
        )
        val rule = dto.toDomain()
        assertEquals("rule_3", rule.id)
        assertEquals("hello", rule.triggerPattern)
        assertEquals("hi", rule.responseTemplate)
        assertEquals(AutoReplyMatchType.REGEX, rule.matchType)
        assertEquals(55, rule.priority)
        assertEquals(false, rule.enabled)
        assertEquals(9, rule.matchCount)
    }

    @Test
    fun autoReplyRuleDto_toDomain_unknownMatchTypeDefaultsToKeyword() {
        val rule = AutoReplyRuleDto(ruleId = "r", matchType = "???").toDomain()
        assertEquals(AutoReplyMatchType.KEYWORD, rule.matchType)
    }

    @Test
    fun autoReplyListDto_toDomain_mapsEachRule() {
        val rules = AutoReplyListDto(
            rules = listOf(
                AutoReplyRuleDto(ruleId = "r1", matchType = "exact"),
                AutoReplyRuleDto(ruleId = "r2", matchType = "contains"),
            ),
        ).toDomain()
        assertEquals(2, rules.size)
        assertEquals(AutoReplyMatchType.EXACT, rules[0].matchType)
        assertEquals(AutoReplyMatchType.CONTAINS, rules[1].matchType)
    }

    // ---- TemplateDto -> BotTemplate ----

    @Test
    fun templateDto_toDomain_mapsAllFields() {
        val dto = TemplateDto(
            templateId = "tpl_2",
            botId = "bot_1",
            name = "Welcome",
            text = "Hi there",
            category = "support",
            bodyFormat = "markdown",
        )
        val tpl = dto.toDomain()
        assertEquals("tpl_2", tpl.id)
        assertEquals("Welcome", tpl.name)
        assertEquals("Hi there", tpl.text)
        assertEquals(TemplateCategory.SUPPORT, tpl.category)
        assertEquals("markdown", tpl.bodyFormat)
    }

    @Test
    fun templateDto_toDomain_unknownCategoryFoldsToCustom() {
        val tpl = TemplateDto(templateId = "t", category = "promo-blast").toDomain()
        assertEquals(TemplateCategory.CUSTOM, tpl.category)
    }
}
