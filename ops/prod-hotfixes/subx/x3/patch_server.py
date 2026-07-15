import io, sys

p = "app/routers/subscription_server.py"
s = open(p, encoding="utf-8").read()
orig = s

def repl(old, new, count=1):
    global s
    n = s.count(old)
    if n < count:
        raise SystemExit(f"ANCHOR NOT FOUND ({n}<{count}): {old[:60]!r}")
    s = s.replace(old, new, count)

# 1. import get_plan_level
repl(
    "from app.services.subscription_access import get_subscription_settings, set_subscription_settings, is_platform_admin",
    "from app.services.subscription_access import get_subscription_settings, set_subscription_settings, is_platform_admin, get_plan_level",
)

# 2. PlanCreateIn.level
repl(
    "    # SUB-E0: structured tier benefits/perks (list of {label, detail}).\n    benefits: conlist(PlanBenefit, max_length=50) = Field(default_factory=list)",
    "    # SUB-E0: structured tier benefits/perks (list of {label, detail}).\n    benefits: conlist(PlanBenefit, max_length=50) = Field(default_factory=list)\n    # SUBX-30: optional explicit ordered tier level (>=1; higher = more premium).\n    # When omitted the level is DERIVED by price rank (subscription_access.get_plan_level).\n    level: Optional[conint(ge=1, le=100)] = None",
)

# 3. PlanUpdateIn.level
repl(
    "    # SUB-E0: replace the plan's structured benefits/perks (None = leave unchanged).\n    benefits: Optional[conlist(PlanBenefit, max_length=50)] = None",
    "    # SUB-E0: replace the plan's structured benefits/perks (None = leave unchanged).\n    benefits: Optional[conlist(PlanBenefit, max_length=50)] = None\n    # SUBX-30: set/replace the plan's explicit tier level (None = leave unchanged).\n    level: Optional[conint(ge=1, le=100)] = None",
)

# 4. PlanOut.level
repl(
    "    interval: str = \"month\"\n    annual_price_cents: Optional[int] = None\n    # Tolerant defaults:",
    "    interval: str = \"month\"\n    annual_price_cents: Optional[int] = None\n    # SUBX-30: ordered tier level (>=1); absent on older/seeded plans -> None (derived).\n    level: Optional[int] = None\n    # Tolerant defaults:",
)

# 5. create_plan persist level
repl(
    "        \"annual_price_cents\": int(body.annual_price_cents) if body.annual_price_cents else None,\n        \"status\": \"active\",",
    "        \"annual_price_cents\": int(body.annual_price_cents) if body.annual_price_cents else None,\n        # SUBX-30: explicit ordered tier level (None -> derived by price rank at read time).\n        \"level\": int(body.level) if body.level else None,\n        \"status\": \"active\",",
)

# 6. update_plan handle level
repl(
    "    if body.annual_price_cents is not None:\n        updated[\"annual_price_cents\"] = int(body.annual_price_cents)\n    if body.benefits is not None:",
    "    if body.annual_price_cents is not None:\n        updated[\"annual_price_cents\"] = int(body.annual_price_cents)\n    if body.level is not None:\n        updated[\"level\"] = int(body.level)  # SUBX-30\n    if body.benefits is not None:",
)

# 7. subscribe sub dict tier_level
repl(
    "        \"subscriber_id\": subscriber_id,\n        \"interval\": interval,\n        \"provider\": \"stripe\" if payment_intent_id else \"stub\",",
    "        \"subscriber_id\": subscriber_id,\n        # SUBX-30: persist the resolved tier level so the tier gate is stable against\n        # later re-ranking, and legacy/other readers get a level without a lookup.\n        \"tier_level\": get_plan_level(plan[\"creator_id\"], plan_id),\n        \"interval\": interval,\n        \"provider\": \"stripe\" if payment_intent_id else \"stub\",",
)

# 8. gift sub dict tier_level
repl(
    "        \"subscriber_id\": recipient_id,\n        \"interval\": interval,\n        \"provider\": \"stripe\" if payment_intent_id else \"stub\",",
    "        \"subscriber_id\": recipient_id,\n        # SUBX-30: gifted sub records its tier level too (unlocks that tier's content).\n        \"tier_level\": get_plan_level(plan[\"creator_id\"], plan_id),\n        \"interval\": interval,\n        \"provider\": \"stripe\" if payment_intent_id else \"stub\",",
)

# 9. change_subscription_plan upgrade tier_level
repl(
    "    sub[\"plan_id\"] = body.plan_id\n    sub[\"interval\"] = interval\n    sub[\"price_cents\"] = int(new_price)\n    sub[\"proration_policy\"] = body.proration_policy",
    "    sub[\"plan_id\"] = body.plan_id\n    sub[\"interval\"] = interval\n    sub[\"price_cents\"] = int(new_price)\n    # SUBX-30/33: an UPGRADE unlocks the higher tier IMMEDIATELY -> re-resolve and\n    # persist the new tier level now. (A scheduled DOWNGRADE keeps the current\n    # higher tier_level until _apply_pending_change re-resolves it at period end,\n    # so paid-for access is never lost early.)\n    sub[\"tier_level\"] = get_plan_level(sub[\"creator_id\"], body.plan_id)\n    sub[\"proration_policy\"] = body.proration_policy",
)

open(p, "w", encoding="utf-8").write(s)
print("PATCHED subscription_server.py; delta bytes:", len(s) - len(orig))
