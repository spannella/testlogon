# SEC-019: DynamoDB Expression Built via f-string (injection pattern)

**Ticket**: SEC-019 · **Status**: Open · **Priority**: Medium · **Date**: 2026-06-04
**Source**: docs/security-audit-2026-06.md (Wave 3)

## Problem
`app/services/commerce_entitlement_orchestrator.py:105` builds a
`KeyConditionExpression` with an f-string:
`query(KeyConditionExpression=f"pk = '{self._dead_letter_pk(source_system)}'")`.
The input is currently internal, but the **pattern is unsafe** — if `source_system`
(or any similarly-built expression elsewhere) ever takes user input, an attacker can
inject expression syntax to read/modify unintended items or bypass conditions.

## Fix
- Use the parameterized API everywhere: `KeyConditionExpression=Key("pk").eq(...)`
  with `ExpressionAttributeNames/Values`.
- Sweep the codebase for any `KeyConditionExpression=`/`FilterExpression=`/
  `UpdateExpression=`/`ConditionExpression=` built with f-strings or `+` on
  non-constant (user-derived) values and convert them.

## Testing
pytest: the dead-letter query returns correct rows via `Key().eq`; a `source_system`
containing quote/expression metacharacters is treated as a literal (no injection).
