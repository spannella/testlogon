# Internal Namespace Metering Contract (CCE-040)

This contract defines billable internal API surfaces for `messaging.*` and `filemanager.*` and standardizes identity propagation for service-to-service calls.

## Namespace and Action Taxonomy

| Namespace | Action | Meter | Unit | Notes |
|---|---|---|---|---|
| messaging | send_message | `messaging.message.send.count` | count | One unit per message send call. |
| messaging | upload_attachment | `messaging.attachment.upload.bytes` | bytes | Meter by uploaded payload bytes. |
| messaging | download_attachment | `messaging.attachment.download.bytes` | bytes | Meter by downloaded payload bytes. |
| messaging | stream_events | `messaging.events.stream.connect.count` | count | One unit per stream connect. |
| messaging | presence_heartbeat | `messaging.presence.heartbeat.count` | count | One unit per heartbeat call. |
| filemanager | upload_file | `filemanager.file.upload.bytes` | bytes | Meter by uploaded payload bytes. |
| filemanager | download_file | `filemanager.file.download.bytes` | bytes | Meter by downloaded payload bytes. |
| filemanager | preview_file | `filemanager.file.preview.count` | count | One unit per preview request. |
| filemanager | delete_file | `filemanager.file.delete.count` | count | One unit per delete request. |
| filemanager | list_directory | `filemanager.directory.list.count` | count | One unit per list request. |

## Deterministic Route-to-Meter Mapping

Mapped route IDs are canonical `METHOD:/path/template` values.

### Messaging

- `POST:/messaging/conversations/{conversation_id}/messages` -> `messaging.send_message`
- `POST:/messaging/conversations/{conversation_id}/messages/image` -> `messaging.upload_attachment`
- `GET:/messaging/conversations/{conversation_id}/messages/image/{message_id}` -> `messaging.download_attachment`
- `GET:/messaging/events/stream` -> `messaging.stream_events`
- `POST:/messaging/presence/heartbeat` -> `messaging.presence_heartbeat`

### File Manager

- `POST:/v1/fs/upload` -> `filemanager.upload_file`
- `GET:/v1/fs/download` -> `filemanager.download_file`
- `GET:/v1/fs/shared-download` -> `filemanager.download_file`
- `GET:/v1/fs/preview` -> `filemanager.preview_file`
- `GET:/v1/fs/shared-preview` -> `filemanager.preview_file`
- `DELETE:/v1/fs` -> `filemanager.delete_file`
- `GET:/v1/fs/list` -> `filemanager.list_directory`

## Identity Propagation Requirements

Required headers on service calls:

- `x-user-sub` (end-user subject under whose entitlement usage is consumed)
- `x-service-name` (caller service identity)
- `x-service-request-id` (unique request identifier for tracing/idempotency)

Optional headers:

- `x-actor-type` (defaults to `service`)

Calls that omit required identity fields must be treated as invalid for billable-meter enforcement.

## Approval Status

- Messaging owner: **approved**
- File Manager owner: **approved**

(Approval tracked by this contract and corresponding implementation tests.)
