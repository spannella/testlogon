## Summary
- [ ] Describe what changed.
- [ ] Describe why the change is needed.

## Messaging Contract Drift Checklist (temporary)
> Complete this section for any PR that changes messaging endpoints, payloads, or models.

- [ ] I verified canonical request/response shapes against `docs/swagger.json`.
- [ ] I updated frontend messaging API types/clients to match canonical backend fields.
- [ ] I updated backend messaging models/routes when contract changes were intentional.
- [ ] I added/updated tests for high-risk messaging requests:
  - [ ] start conversation
  - [ ] send text
  - [ ] mark read
  - [ ] mute conversation
  - [ ] edit message
- [ ] I documented migration notes (if compatibility aliases/deprecations were introduced).

## Testing
- [ ] Tests added/updated
- [ ] Local tests run
- [ ] Include exact commands and outcomes below

```
# e.g.
pytest -q tests/test_messaging_contract_drift.py
```
