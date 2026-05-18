# Google Calendar Mapping Item Contract (GCAL-007)

Partition/key model (DynamoDB in `calendar` table):
- `calendar_id = gcal_map#{user_sub}`
- `sk = map#{mapping_id}`
- `type = calendar_provider_mapping`

Core fields:
- `mapping_id`, `provider` (`google`), `user_sub`
- `internal_calendar_id` (app calendar id)
- `google_calendar_id` (provider calendar id)
- `active`
- `created_at_utc`, `updated_at_utc`, `unmapped_at_utc`

Validation rules:
- mapping writes require internal calendar ownership (`owner_user_sub == user_sub`)
- same internal calendar cannot have multiple active mappings
- remapping an inactive historical mapping reactivates same record id
- unmapping is soft (record preserved for audit history)

Repository/service API:
- `create_calendar_provider_mapping`
- `list_calendar_provider_mappings`
- `unmap_calendar_provider_mapping`
