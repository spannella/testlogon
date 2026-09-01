package com.testlogon.android.core.network.workflow

import com.squareup.moshi.Moshi
import com.squareup.moshi.kotlin.reflect.KotlinJsonAdapterFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/** WFL — DTO-level Moshi decode tests for the workflow-rule list envelope (loosely-typed payloads). */
class WorkflowRuleDtoJsonTest {

    private val moshi: Moshi = Moshi.Builder().add(KotlinJsonAdapterFactory()).build()

    @Test
    fun ruleList_decodesRulesWithNestedPayloads() {
        val json = """
            {
              "rules": [
                {
                  "rule_id": "r1",
                  "name": "Escalate urgent tickets",
                  "description": "auto-assign",
                  "target_module": "ticket",
                  "trigger_type": "on_save",
                  "trigger_config": {"debounce": 5},
                  "conditions": [{"field": "priority", "operator": "eq", "value": "urgent"}],
                  "actions": [{"action_type": "modify_field", "config": {"field": "owner"}}],
                  "enabled": true,
                  "created_by": "admin",
                  "created_at": 1700000000,
                  "updated_at": 1700000100
                }
              ],
              "cursor": null
            }
        """.trimIndent()
        val dto = moshi.adapter(WorkflowRuleListDto::class.java).fromJson(json)!!
        assertEquals(1, dto.rules.size)
        val rule = dto.rules.first()
        assertEquals("r1", rule.ruleId)
        assertEquals("ticket", rule.targetModule)
        assertEquals(1, rule.conditions.size)
        assertEquals(1, rule.actions.size)
        assertTrue(rule.enabled)
    }

    @Test
    fun sparseRule_usesDefaults() {
        val json = """{"rules":[{"rule_id":"r2","name":"n"}]}"""
        val dto = moshi.adapter(WorkflowRuleListDto::class.java).fromJson(json)!!
        val rule = dto.rules.first()
        assertEquals("", rule.description)
        assertEquals(0, rule.conditions.size)
        assertEquals(false, rule.enabled)
    }
}
