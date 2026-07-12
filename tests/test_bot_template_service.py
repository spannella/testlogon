"""Offline hermetic tests for the bot template service (BOT-002).

Covers create/get/list/update/delete CRUD, variable resolution, render_template,
A/B selection via select_ab_template/get_templates_for_trigger, and impression /
response tracking via record_impression / record_response.

Hermetic / offline:
* Real in-memory DynamoDB ``bot_templates`` and ``profiles`` tables via moto,
  bound to the exact frozen ``T.bot_templates`` / ``T.profile`` handles through
  ``object.__setattr__`` (restored on cleanup).
* ``app.services.chat_bot.get_bot_for_owner`` is stubbed with
  ``unittest.mock.patch`` so no real DynamoDB bot table is needed.
* No real AWS / network is ever touched.
"""
from __future__ import annotations

import unittest
from contextlib import ExitStack
from unittest.mock import patch

import boto3

try:
    from moto import mock_aws
except Exception:  # pragma: no cover
    mock_aws = None

from app.core.tables import T
import app.services.bot_template as bt


# ---------------------------------------------------------------------------
# Table factory helpers
# ---------------------------------------------------------------------------

def _make_bot_templates_table(ddb):
    """Create the bot_templates table with GSI1 (GSI1SK numeric)."""
    return ddb.create_table(
        TableName="bot_templates",
        KeySchema=[
            {"AttributeName": "pk", "KeyType": "HASH"},
            {"AttributeName": "sk", "KeyType": "RANGE"},
        ],
        AttributeDefinitions=[
            {"AttributeName": "pk", "AttributeType": "S"},
            {"AttributeName": "sk", "AttributeType": "S"},
            {"AttributeName": "GSI1PK", "AttributeType": "S"},
            {"AttributeName": "GSI1SK", "AttributeType": "N"},
        ],
        GlobalSecondaryIndexes=[
            {
                "IndexName": "GSI1",
                "KeySchema": [
                    {"AttributeName": "GSI1PK", "KeyType": "HASH"},
                    {"AttributeName": "GSI1SK", "KeyType": "RANGE"},
                ],
                "Projection": {"ProjectionType": "ALL"},
            }
        ],
        BillingMode="PAY_PER_REQUEST",
    )


def _make_profile_table(ddb):
    """Create the profiles table with PK user_sub."""
    return ddb.create_table(
        TableName="profiles",
        KeySchema=[{"AttributeName": "user_sub", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "user_sub", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )


# ---------------------------------------------------------------------------
# Shared test fixture mixin
# ---------------------------------------------------------------------------

_FAKE_BOT = {"bot_id": "bot1", "name": "TestBot", "creator_id": "creator1"}


class _BotTemplateBase(unittest.TestCase):
    """Base class that sets up moto + table bindings for each test."""

    def setUp(self):
        if mock_aws is None:
            self.skipTest("moto not available")

        self._stack = ExitStack()
        self._stack.enter_context(mock_aws())

        ddb = boto3.resource("dynamodb", region_name="us-east-1")
        self.tbl = _make_bot_templates_table(ddb)
        self.profile_tbl = _make_profile_table(ddb)

        # Bind to frozen T handles
        self._orig_bot_templates = T.bot_templates
        self._orig_profile = T.profile
        object.__setattr__(T, "bot_templates", self.tbl)
        object.__setattr__(T, "profile", self.profile_tbl)

    def tearDown(self):
        object.__setattr__(T, "bot_templates", self._orig_bot_templates)
        object.__setattr__(T, "profile", self._orig_profile)
        self._stack.close()

    # ---------- helpers ----------

    def _create_one(
        self,
        bot_id="bot1",
        creator_id="creator1",
        name="Hello",
        text="Hi {user_name}!",
        category="greeting",
        **kw,
    ):
        """Create a template with get_bot_for_owner mocked to return a bot."""
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            return bt.create_template(
                bot_id=bot_id,
                creator_id=creator_id,
                name=name,
                text=text,
                category=category,
                **kw,
            )


# ===========================================================================
# 1. create_template — happy path
# ===========================================================================

class TestCreateTemplateHappyPath(_BotTemplateBase):

    def test_returns_template_dict_with_expected_fields(self):
        tmpl = self._create_one()
        self.assertIn("template_id", tmpl)
        self.assertEqual(tmpl["bot_id"], "bot1")
        self.assertEqual(tmpl["name"], "Hello")
        self.assertEqual(tmpl["text"], "Hi {user_name}!")
        self.assertEqual(tmpl["category"], "greeting")
        self.assertEqual(tmpl["body_format"], "plain")
        self.assertEqual(tmpl["impression_count"], 0)
        self.assertEqual(tmpl["response_count"], 0)
        self.assertGreater(tmpl["created_at"], 0)

    def test_variables_auto_detected(self):
        tmpl = self._create_one(text="Hello {user_name}, from {bot_name}!")
        self.assertEqual(sorted(tmpl["variables_used"]), ["bot_name", "user_name"])

    def test_text_without_variables_gives_empty_list(self):
        tmpl = self._create_one(text="No variables here.")
        self.assertEqual(tmpl["variables_used"], [])

    def test_quick_replies_stored(self):
        qr = [{"label": "Yes", "value": "yes"}, {"label": "No", "value": "no"}]
        tmpl = self._create_one(quick_replies=qr)
        self.assertEqual(len(tmpl["quick_replies"]), 2)
        self.assertEqual(tmpl["quick_replies"][0]["label"], "Yes")

    def test_ab_group_stored(self):
        tmpl = self._create_one(ab_group="experiment_a", ab_weight=3)
        self.assertEqual(tmpl["ab_group"], "experiment_a")
        self.assertEqual(tmpl["ab_weight"], 3)

    def test_item_persisted_in_ddb(self):
        tmpl = self._create_one()
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["template_id"], tmpl["template_id"])


# ===========================================================================
# 2. create_template — BotNotFound
# ===========================================================================

class TestCreateTemplateBotNotFound(_BotTemplateBase):

    def test_raises_bot_not_found_when_owner_check_returns_none(self):
        from app.services.chat_bot import BotNotFound

        with patch("app.services.chat_bot.get_bot_for_owner", return_value=None):
            with self.assertRaises(BotNotFound):
                bt.create_template(
                    bot_id="no_bot",
                    creator_id="creator1",
                    name="X",
                    text="Hi",
                )

    def test_nothing_written_to_ddb_on_bot_not_found(self):
        from app.services.chat_bot import BotNotFound

        with patch("app.services.chat_bot.get_bot_for_owner", return_value=None):
            try:
                bt.create_template(
                    bot_id="no_bot", creator_id="creator1", name="X", text="Hi"
                )
            except BotNotFound:
                pass

        result = self.tbl.query(
            KeyConditionExpression="pk = :pk",
            ExpressionAttributeValues={":pk": "BOT#no_bot"},
        )
        self.assertEqual(result.get("Count", 0), 0)


# ===========================================================================
# 3. create_template — TemplateLimitExceeded (50 templates already)
# ===========================================================================

class TestCreateTemplateLimit(_BotTemplateBase):

    def test_raises_when_50_templates_exist(self):
        # Pre-seed 50 items directly into DDB without going through create_template
        for i in range(bt.MAX_TEMPLATES_PER_BOT):
            self.tbl.put_item(
                Item={
                    "pk": "BOT#bot1",
                    "sk": f"TEMPLATE#tmpl{i:04d}",
                    "template_id": f"tmpl{i:04d}",
                    "bot_id": "bot1",
                    "name": f"T{i}",
                    "text": "hello",
                    "category": "custom",
                    "body_format": "plain",
                    "impression_count": 0,
                    "response_count": 0,
                    "ab_weight": 1,
                    "created_at": 1000 + i,
                    "updated_at": 1000 + i,
                    "GSI1PK": "BOT#bot1#CAT#custom",
                    "GSI1SK": 1000 + i,
                }
            )

        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            with self.assertRaises(bt.TemplateLimitExceeded):
                bt.create_template(
                    bot_id="bot1",
                    creator_id="creator1",
                    name="OneMore",
                    text="Too many",
                )


# ===========================================================================
# 4. get_template — found / not-found
# ===========================================================================

class TestGetTemplate(_BotTemplateBase):

    def test_returns_dict_when_found(self):
        tmpl = self._create_one()
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertIsNotNone(fetched)
        self.assertEqual(fetched["template_id"], tmpl["template_id"])
        self.assertEqual(fetched["name"], "Hello")

    def test_returns_none_when_not_found(self):
        result = bt.get_template(bot_id="bot1", template_id="nonexistent_id")
        self.assertIsNone(result)

    def test_returns_none_for_wrong_bot_id(self):
        tmpl = self._create_one(bot_id="bot1")
        result = bt.get_template(bot_id="bot2", template_id=tmpl["template_id"])
        self.assertIsNone(result)


# ===========================================================================
# 5. list_templates — by bot, by category
# ===========================================================================

class TestListTemplates(_BotTemplateBase):

    def setUp(self):
        super().setUp()
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            self.t_greeting = bt.create_template(
                bot_id="bot1", creator_id="creator1",
                name="Greet", text="Hello!", category="greeting",
            )
            self.t_support = bt.create_template(
                bot_id="bot1", creator_id="creator1",
                name="Support", text="How can I help?", category="support",
            )
            self.t_support2 = bt.create_template(
                bot_id="bot1", creator_id="creator1",
                name="Support2", text="Please describe your issue.", category="support",
            )

    def test_list_all_returns_all_bot_templates(self):
        templates = bt.list_templates(bot_id="bot1")
        ids = {t["template_id"] for t in templates}
        self.assertIn(self.t_greeting["template_id"], ids)
        self.assertIn(self.t_support["template_id"], ids)
        self.assertIn(self.t_support2["template_id"], ids)
        self.assertEqual(len(templates), 3)

    def test_list_by_category_filters_correctly(self):
        support_templates = bt.list_templates(bot_id="bot1", category="support")
        ids = {t["template_id"] for t in support_templates}
        self.assertIn(self.t_support["template_id"], ids)
        self.assertIn(self.t_support2["template_id"], ids)
        self.assertNotIn(self.t_greeting["template_id"], ids)

    def test_list_by_category_greeting(self):
        greeting_templates = bt.list_templates(bot_id="bot1", category="greeting")
        self.assertEqual(len(greeting_templates), 1)
        self.assertEqual(greeting_templates[0]["template_id"], self.t_greeting["template_id"])

    def test_list_empty_for_unknown_bot(self):
        templates = bt.list_templates(bot_id="unknown_bot")
        self.assertEqual(templates, [])

    def test_list_empty_category_for_no_match(self):
        templates = bt.list_templates(bot_id="bot1", category="farewell")
        self.assertEqual(templates, [])

    def test_list_isolated_across_bots(self):
        # bot2 templates should not appear in bot1's list
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            bt.create_template(
                bot_id="bot2", creator_id="creator1",
                name="Bot2 tmpl", text="Hi from bot2", category="greeting",
            )
        bot1_templates = bt.list_templates(bot_id="bot1")
        self.assertEqual(len(bot1_templates), 3)


# ===========================================================================
# 6. update_template — happy path
# ===========================================================================

class TestUpdateTemplateHappyPath(_BotTemplateBase):

    def setUp(self):
        super().setUp()
        self.tmpl = self._create_one(text="Original text")

    def test_update_name(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            updated = bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                name="New Name",
            )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["name"], "New Name")
        # text unchanged
        self.assertEqual(updated["text"], "Original text")

    def test_update_text_changes_variables_used(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            updated = bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                text="Hello {user_name} and {bot_name}",
            )
        self.assertIsNotNone(updated)
        self.assertEqual(sorted(updated["variables_used"]), ["bot_name", "user_name"])

    def test_update_text_clears_variables_when_none_present(self):
        # First give it a variable
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                text="Hello {user_name}",
            )
        # Then remove all variables
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            updated = bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                text="Plain text now",
            )
        self.assertIsNotNone(updated)
        # variables_used should be falsy (None serialised to [] by _template_dict)
        self.assertEqual(updated.get("variables_used") or [], [])

    def test_update_category_updates_gsi1pk(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            updated = bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                category="farewell",
            )
        self.assertIsNotNone(updated)
        self.assertEqual(updated["category"], "farewell")
        # Verify DDB item directly
        item = self.tbl.get_item(
            Key={"pk": "BOT#bot1", "sk": f"TEMPLATE#{self.tmpl['template_id']}"}
        ).get("Item")
        self.assertEqual(item["GSI1PK"], "BOT#bot1#CAT#farewell")

    def test_update_with_valid_quick_replies(self):
        qr = [{"label": "OK", "value": "ok"}]
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            updated = bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                quick_replies=qr,
            )
        self.assertIsNotNone(updated)
        self.assertEqual(len(updated["quick_replies"]), 1)

    def test_update_persisted_to_ddb(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            bt.update_template(
                bot_id="bot1",
                template_id=self.tmpl["template_id"],
                creator_id="creator1",
                name="Persisted Name",
            )
        fetched = bt.get_template(bot_id="bot1", template_id=self.tmpl["template_id"])
        self.assertEqual(fetched["name"], "Persisted Name")


# ===========================================================================
# 7. update_template — not found / bot not found
# ===========================================================================

class TestUpdateTemplateNotFound(_BotTemplateBase):

    def test_returns_none_when_template_does_not_exist(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            result = bt.update_template(
                bot_id="bot1",
                template_id="nonexistent",
                creator_id="creator1",
                name="Ghost",
            )
        self.assertIsNone(result)

    def test_returns_none_when_bot_not_owned(self):
        tmpl = self._create_one()
        # Patch get_bot_for_owner to return None (bot ownership check fails)
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=None):
            result = bt.update_template(
                bot_id="bot1",
                template_id=tmpl["template_id"],
                creator_id="stranger",
                name="Ghost",
            )
        self.assertIsNone(result)

    def test_no_op_fields_returns_existing_template(self):
        """Passing no allowed fields returns the existing template unchanged."""
        tmpl = self._create_one(name="Stable")
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            result = bt.update_template(
                bot_id="bot1",
                template_id=tmpl["template_id"],
                creator_id="creator1",
                # passing only None values — no real update
                name=None,
            )
        # Should return the existing template unchanged
        self.assertIsNotNone(result)
        self.assertEqual(result["name"], "Stable")


# ===========================================================================
# 8. delete_template — happy path and not-found
# ===========================================================================

class TestDeleteTemplate(_BotTemplateBase):

    def test_delete_happy_path_returns_true(self):
        tmpl = self._create_one()
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            result = bt.delete_template(
                bot_id="bot1",
                template_id=tmpl["template_id"],
                creator_id="creator1",
            )
        self.assertTrue(result)

    def test_deleted_template_no_longer_fetchable(self):
        tmpl = self._create_one()
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            bt.delete_template(
                bot_id="bot1",
                template_id=tmpl["template_id"],
                creator_id="creator1",
            )
        self.assertIsNone(bt.get_template(bot_id="bot1", template_id=tmpl["template_id"]))

    def test_delete_nonexistent_returns_false(self):
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            result = bt.delete_template(
                bot_id="bot1",
                template_id="does_not_exist",
                creator_id="creator1",
            )
        self.assertFalse(result)

    def test_delete_returns_false_when_bot_not_owned(self):
        tmpl = self._create_one()
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=None):
            result = bt.delete_template(
                bot_id="bot1",
                template_id=tmpl["template_id"],
                creator_id="stranger",
            )
        self.assertFalse(result)
        # Template should still be there
        self.assertIsNotNone(bt.get_template(bot_id="bot1", template_id=tmpl["template_id"]))

    def test_deleted_template_absent_from_list(self):
        t1 = self._create_one(name="Keep")
        t2 = self._create_one(name="Delete")
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            bt.delete_template(
                bot_id="bot1",
                template_id=t2["template_id"],
                creator_id="creator1",
            )
        remaining = bt.list_templates(bot_id="bot1")
        ids = {t["template_id"] for t in remaining}
        self.assertIn(t1["template_id"], ids)
        self.assertNotIn(t2["template_id"], ids)


# ===========================================================================
# 9. resolve_variables
# ===========================================================================

class TestResolveVariables(unittest.TestCase):
    """Pure unit tests — no DDB needed."""

    def test_full_context_resolves_all_variables(self):
        text = "Hello {user_name}, bot is {bot_name}."
        ctx = {"user_name": "Alice", "bot_name": "TestBot"}
        resolved, unresolved = bt.resolve_variables(text, ctx)
        self.assertEqual(resolved, "Hello Alice, bot is TestBot.")
        self.assertEqual(unresolved, [])

    def test_partial_context_leaves_missing_as_is(self):
        text = "Hello {user_name}, bot is {bot_name}."
        ctx = {"user_name": "Alice"}
        resolved, unresolved = bt.resolve_variables(text, ctx)
        self.assertEqual(resolved, "Hello Alice, bot is {bot_name}.")
        self.assertIn("bot_name", unresolved)

    def test_no_variables_returns_text_unchanged(self):
        text = "No placeholders here."
        resolved, unresolved = bt.resolve_variables(text, {"user_name": "Alice"})
        self.assertEqual(resolved, "No placeholders here.")
        self.assertEqual(unresolved, [])

    def test_empty_context_leaves_all_variables(self):
        text = "{a} and {b}"
        resolved, unresolved = bt.resolve_variables(text, {})
        self.assertEqual(resolved, "{a} and {b}")
        self.assertIn("a", unresolved)
        self.assertIn("b", unresolved)

    def test_empty_string_returns_empty(self):
        resolved, unresolved = bt.resolve_variables("", {})
        self.assertEqual(resolved, "")
        self.assertEqual(unresolved, [])

    def test_context_value_coerced_to_string(self):
        text = "Count: {n}"
        resolved, unresolved = bt.resolve_variables(text, {"n": 42})
        self.assertEqual(resolved, "Count: 42")
        self.assertEqual(unresolved, [])

    def test_repeated_variable_resolved_each_occurrence(self):
        text = "{user_name} says hi, {user_name}!"
        resolved, unresolved = bt.resolve_variables(text, {"user_name": "Alice"})
        self.assertEqual(resolved, "Alice says hi, Alice!")
        self.assertEqual(unresolved, [])


# ===========================================================================
# 10. render_template with sample_overrides
# ===========================================================================

class TestRenderTemplate(_BotTemplateBase):

    def test_sample_overrides_used_for_resolution(self):
        template = {
            "text": "Hello {user_name}!",
            "quick_replies": None,
        }
        result = bt.render_template(
            template=template,
            sample_overrides={"user_name": "OverriddenUser"},
        )
        self.assertEqual(result["rendered_text"], "Hello OverriddenUser!")
        self.assertEqual(result["unresolved_variables"], [])

    def test_renders_without_overrides_fetches_profile(self):
        # Seed a profile in DDB
        self.profile_tbl.put_item(Item={
            "user_sub": "user123",
            "display_name": "ProfileUser",
        })
        template = {"text": "Hi {user_name}!", "quick_replies": None}
        result = bt.render_template(
            template=template,
            sender_id="user123",
        )
        self.assertEqual(result["rendered_text"], "Hi ProfileUser!")

    def test_renders_unknown_sender_uses_fallback(self):
        template = {"text": "Hi {user_name}!", "quick_replies": None}
        result = bt.render_template(
            template=template,
            sender_id="no_such_user",
        )
        self.assertEqual(result["rendered_text"], "Hi User!")

    def test_render_includes_quick_replies_when_present(self):
        qr = [{"label": "Yes", "value": "yes"}]
        template = {"text": "Continue?", "quick_replies": qr}
        result = bt.render_template(template=template)
        self.assertIn("quick_replies", result)
        self.assertEqual(result["quick_replies"], qr)

    def test_render_omits_quick_replies_key_when_none(self):
        template = {"text": "Simple", "quick_replies": None}
        result = bt.render_template(template=template)
        self.assertNotIn("quick_replies", result)

    def test_render_bot_name_from_bot_dict(self):
        template = {"text": "I am {bot_name}.", "quick_replies": None}
        result = bt.render_template(
            template=template,
            bot={"name": "MyBot"},
        )
        self.assertEqual(result["rendered_text"], "I am MyBot.")

    def test_resolved_variables_in_result(self):
        template = {"text": "Hi {user_name}!", "quick_replies": None}
        result = bt.render_template(
            template=template,
            sample_overrides={"user_name": "Alice"},
        )
        self.assertIn("resolved_variables", result)
        self.assertEqual(result["resolved_variables"]["user_name"], "Alice")

    def test_unresolved_variables_reported(self):
        template = {"text": "Hi {user_name} and {missing_var}!", "quick_replies": None}
        result = bt.render_template(
            template=template,
            sample_overrides={"user_name": "Alice"},
        )
        self.assertIn("missing_var", result["unresolved_variables"])
        self.assertNotIn("user_name", result["unresolved_variables"])


# ===========================================================================
# 11. select_ab_template / get_templates_for_trigger
#     (covers "select_template_for_category returns None when no templates")
# ===========================================================================

class TestSelectTemplate(_BotTemplateBase):

    def test_get_templates_for_trigger_no_templates_returns_empty(self):
        """No templates in DDB → empty list."""
        trigger = {"response_template_id": "nonexistent"}
        result = bt.get_templates_for_trigger(bot_id="bot1", trigger=trigger)
        self.assertEqual(result, [])

    def test_get_templates_for_trigger_no_template_id_returns_empty(self):
        trigger = {}
        result = bt.get_templates_for_trigger(bot_id="bot1", trigger=trigger)
        self.assertEqual(result, [])

    def test_get_templates_for_trigger_single_no_ab_group(self):
        tmpl = self._create_one()
        trigger = {"response_template_id": tmpl["template_id"]}
        result = bt.get_templates_for_trigger(bot_id="bot1", trigger=trigger)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]["template_id"], tmpl["template_id"])

    def test_get_templates_for_trigger_returns_all_in_ab_group(self):
        t1 = self._create_one(name="A", ab_group="group_x", ab_weight=1)
        t2 = self._create_one(name="B", text="Hi B", ab_group="group_x", ab_weight=2)
        trigger = {"response_template_id": t1["template_id"]}
        result = bt.get_templates_for_trigger(bot_id="bot1", trigger=trigger)
        ids = {t["template_id"] for t in result}
        self.assertIn(t1["template_id"], ids)
        self.assertIn(t2["template_id"], ids)

    def test_select_ab_template_single_item(self):
        templates = [{"template_id": "only", "ab_weight": 1}]
        chosen = bt.select_ab_template(templates)
        self.assertEqual(chosen["template_id"], "only")

    def test_select_ab_template_returns_one_of_candidates(self):
        templates = [
            {"template_id": "a", "ab_weight": 1},
            {"template_id": "b", "ab_weight": 1},
        ]
        for _ in range(20):
            chosen = bt.select_ab_template(templates)
            self.assertIn(chosen["template_id"], {"a", "b"})

    def test_select_ab_template_weighted_heavily_toward_one(self):
        """With extreme weights, heavy candidate should dominate."""
        templates = [
            {"template_id": "heavy", "ab_weight": 1000},
            {"template_id": "light", "ab_weight": 1},
        ]
        results = [bt.select_ab_template(templates)["template_id"] for _ in range(50)]
        self.assertIn("heavy", results)
        # "light" may or may not appear — don't assert its absence (probabilistic)

    def test_list_templates_empty_when_no_templates_for_bot(self):
        """list_templates returns [] when bot has no templates (mirrors select_template_for_category None path)."""
        result = bt.list_templates(bot_id="bot_with_no_templates")
        self.assertEqual(result, [])

    def test_list_templates_empty_for_unused_category(self):
        self._create_one(category="greeting")
        result = bt.list_templates(bot_id="bot1", category="farewell")
        self.assertEqual(result, [])


# ===========================================================================
# 12. record_impression and record_response (called track_impression /
#     track_response in the task spec — the actual function names are
#     record_impression / record_response)
# ===========================================================================

class TestTrackImpressionResponse(_BotTemplateBase):

    def test_record_impression_increments_count(self):
        tmpl = self._create_one()
        bt.record_impression(bot_id="bot1", template_id=tmpl["template_id"])
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertEqual(fetched["impression_count"], 1)

    def test_record_impression_multiple_times(self):
        tmpl = self._create_one()
        for _ in range(5):
            bt.record_impression(bot_id="bot1", template_id=tmpl["template_id"])
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertEqual(fetched["impression_count"], 5)

    def test_record_response_increments_count(self):
        tmpl = self._create_one()
        bt.record_response(bot_id="bot1", template_id=tmpl["template_id"])
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertEqual(fetched["response_count"], 1)

    def test_record_response_multiple_times(self):
        tmpl = self._create_one()
        for _ in range(3):
            bt.record_response(bot_id="bot1", template_id=tmpl["template_id"])
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertEqual(fetched["response_count"], 3)

    def test_impression_and_response_tracked_independently(self):
        tmpl = self._create_one()
        bt.record_impression(bot_id="bot1", template_id=tmpl["template_id"])
        bt.record_impression(bot_id="bot1", template_id=tmpl["template_id"])
        bt.record_response(bot_id="bot1", template_id=tmpl["template_id"])
        fetched = bt.get_template(bot_id="bot1", template_id=tmpl["template_id"])
        self.assertEqual(fetched["impression_count"], 2)
        self.assertEqual(fetched["response_count"], 1)

    def test_record_impression_nonexistent_template_does_not_raise(self):
        """Non-critical — should swallow ClientError silently."""
        try:
            bt.record_impression(bot_id="bot1", template_id="ghost")
        except Exception as exc:  # pragma: no cover
            self.fail(f"record_impression raised unexpectedly: {exc}")

    def test_record_response_nonexistent_template_does_not_raise(self):
        try:
            bt.record_response(bot_id="bot1", template_id="ghost")
        except Exception as exc:  # pragma: no cover
            self.fail(f"record_response raised unexpectedly: {exc}")


# ===========================================================================
# 13. Quick reply validation (_validate_quick_replies)
# ===========================================================================

class TestQuickReplyValidation(_BotTemplateBase):

    def test_too_many_quick_replies_raises_value_error(self):
        qr = [{"label": f"L{i}", "value": f"v{i}"} for i in range(bt.MAX_QUICK_REPLIES + 1)]
        with self.assertRaises(ValueError):
            bt._validate_quick_replies(qr)

    def test_empty_label_raises_value_error(self):
        with self.assertRaises(ValueError):
            bt._validate_quick_replies([{"label": "", "value": "ok"}])

    def test_label_too_long_raises_value_error(self):
        with self.assertRaises(ValueError):
            bt._validate_quick_replies([{"label": "x" * 41, "value": "ok"}])

    def test_empty_value_raises_value_error(self):
        with self.assertRaises(ValueError):
            bt._validate_quick_replies([{"label": "OK", "value": ""}])

    def test_value_too_long_raises_value_error(self):
        with self.assertRaises(ValueError):
            bt._validate_quick_replies([{"label": "OK", "value": "x" * 201}])

    def test_valid_quick_replies_do_not_raise(self):
        qr = [{"label": "Yes", "value": "yes"}, {"label": "No", "value": "no"}]
        bt._validate_quick_replies(qr)  # should not raise

    def test_create_with_too_many_quick_replies_raises(self):
        qr = [{"label": f"L{i}", "value": f"v{i}"} for i in range(bt.MAX_QUICK_REPLIES + 1)]
        with patch("app.services.chat_bot.get_bot_for_owner", return_value=_FAKE_BOT):
            with self.assertRaises(ValueError):
                bt.create_template(
                    bot_id="bot1",
                    creator_id="creator1",
                    name="Bad",
                    text="hi",
                    quick_replies=qr,
                )


# ===========================================================================
# 14. build_variable_context
# ===========================================================================

class TestBuildVariableContext(_BotTemplateBase):

    def test_user_name_fetched_from_profile(self):
        self.profile_tbl.put_item(Item={
            "user_sub": "u1",
            "display_name": "Alice Smith",
        })
        ctx = bt.build_variable_context(
            template_text="Hello {user_name}",
            sender_id="u1",
        )
        self.assertEqual(ctx["user_name"], "Alice Smith")

    def test_user_name_falls_back_to_user_sub_when_no_display_name(self):
        self.profile_tbl.put_item(Item={"user_sub": "u2"})
        ctx = bt.build_variable_context(
            template_text="Hello {user_name}",
            sender_id="u2",
        )
        self.assertEqual(ctx["user_name"], "u2")

    def test_user_name_defaults_to_user_when_profile_missing(self):
        ctx = bt.build_variable_context(
            template_text="Hello {user_name}",
            sender_id="no_profile_user",
        )
        self.assertEqual(ctx["user_name"], "User")

    def test_bot_name_from_bot_dict(self):
        ctx = bt.build_variable_context(
            template_text="{bot_name} ready",
            bot={"name": "ChattyBot"},
        )
        self.assertEqual(ctx["bot_name"], "ChattyBot")

    def test_sample_overrides_win_over_profile(self):
        self.profile_tbl.put_item(Item={
            "user_sub": "u3",
            "display_name": "RealName",
        })
        ctx = bt.build_variable_context(
            template_text="{user_name}",
            sender_id="u3",
            sample_overrides={"user_name": "OverrideName"},
        )
        self.assertEqual(ctx["user_name"], "OverrideName")

    def test_current_time_and_date_populated(self):
        ctx = bt.build_variable_context(
            template_text="{current_time} on {current_date}",
        )
        self.assertIn("current_time", ctx)
        self.assertIn("current_date", ctx)

    def test_variables_not_in_text_not_fetched(self):
        """user_name is not in template → profile should not be looked up."""
        ctx = bt.build_variable_context(
            template_text="No vars here",
            sender_id="u1",
        )
        self.assertNotIn("user_name", ctx)


if __name__ == "__main__":
    unittest.main()
