# Projects API contract (PL-017)

This document summarizes the canonical Projects API contract from `docs/swagger.json` and includes copy/paste request/response examples for frontend and integration work.

> Source of truth: `docs/swagger.json`.

## Base
- Prefix: `/v1/projects`
- Auth: UI session (`require_ui_session`)
- Cursor format: opaque base64 cursor returned by list/detail/events APIs

## Project CRUD

### Create project
`POST /v1/projects`

Request:
```json
{
  "name": "Docs Migration",
  "description": "Track docs files",
  "tags": ["docs", "migration"],
  "settings": {"ownerTeam": "platform"}
}
```

Response `200`:
```json
{
  "id": "p_123",
  "owner": "user-1",
  "name": "Docs Migration",
  "description": "Track docs files",
  "tags": ["docs", "migration"],
  "settings": {"ownerTeam": "platform"},
  "created_at": "2026-01-01T00:00:00+00:00",
  "updated_at": "2026-01-01T00:00:00+00:00"
}
```

### List projects
`GET /v1/projects?limit=50&cursor=...&tag=docs&name_query=migration`

Response `200`:
```json
{
  "items": [
    {
      "id": "p_123",
      "owner": "user-1",
      "name": "Docs Migration",
      "description": "Track docs files",
      "tags": ["docs", "migration"],
      "settings": {"ownerTeam": "platform"},
      "created_at": "2026-01-01T00:00:00+00:00",
      "updated_at": "2026-01-01T00:00:00+00:00"
    }
  ],
  "cursor": null
}
```

### Get / Update / Delete
- `GET /v1/projects/{project_id}`
- `PATCH /v1/projects/{project_id}`
- `DELETE /v1/projects/{project_id}` -> `{ "ok": true }`

## Tracked files

### Add tracked file
`POST /v1/projects/{project_id}/files`

Request:
```json
{
  "provider": "gitlab",
  "provider_ref": "group/project//README.md?ref=main",
  "display_path": "README.md",
  "metadata": {"source": "manual"}
}
```

Response `200`:
```json
{
  "id": "tf_123",
  "project_id": "p_123",
  "owner": "user-1",
  "provider": "gitlab",
  "provider_ref": "gitlab://group/project//README.md?ref=main",
  "display_path": "README.md",
  "status": "active",
  "metadata": {"source": "manual"},
  "created_at": "2026-01-01T00:00:00+00:00",
  "updated_at": "2026-01-01T00:00:00+00:00",
  "last_seen_at": "2026-01-01T00:00:00+00:00",
  "archived_at": null
}
```

### List tracked files
`GET /v1/projects/{project_id}/files?limit=50&cursor=...&status=active&provider=gitlab`

Response `200`:
```json
{
  "items": [],
  "cursor": null
}
```

### Remove tracked file
`DELETE /v1/projects/{project_id}/files/{tracked_file_id}`

Response `200`:
```json
{
  "ok": true,
  "deleted": true
}
```

## Project detail hydration

`GET /v1/projects/{project_id}/detail?limit=50&cursor=...&status=active&provider=local`

Response `200`:
```json
{
  "project": {
    "id": "p_123",
    "owner": "user-1",
    "name": "Docs Migration",
    "description": null,
    "tags": [],
    "settings": {},
    "created_at": "2026-01-01T00:00:00+00:00",
    "updated_at": "2026-01-01T00:00:00+00:00"
  },
  "files": [
    {
      "id": "tf_123",
      "project_id": "p_123",
      "owner": "user-1",
      "provider": "local",
      "provider_ref": "/docs/a.txt",
      "display_path": "/docs/a.txt",
      "status": "active",
      "metadata": {"size": 12},
      "created_at": "2026-01-01T00:00:00+00:00",
      "updated_at": "2026-01-01T00:00:00+00:00",
      "last_seen_at": "2026-01-01T00:00:00+00:00",
      "archived_at": null
    }
  ],
  "cursor": null
}
```

## Events

`GET /v1/projects/{project_id}/events?limit=50&cursor=...`

Response `200`:
```json
{
  "items": [
    {
      "id": "ev_1",
      "project_id": "p_123",
      "owner": "user-1",
      "event_type": "file_added",
      "tracked_file_id": "tf_123",
      "provider": "gitlab",
      "provider_ref": "gitlab://group/project//README.md?ref=main",
      "message": null,
      "metadata": {"display_path": "README.md"},
      "created_at": "2026-01-01T00:00:00+00:00"
    }
  ],
  "cursor": null
}
```

## Provider credentials

### Upsert
`PUT /v1/projects/providers/{provider}/credentials`

Request:
```json
{
  "token": "<secret>",
  "org": null,
  "api_base_url": "https://gitlab.example.com/api/v4",
  "required_scopes": ["read_api"]
}
```

Response `200`:
```json
{
  "provider": "gitlab",
  "org": null,
  "scopes": ["read_api"],
  "metadata": {
    "api_base_url": "https://gitlab.example.com/api/v4"
  },
  "created_at": "2026-01-01T00:00:00+00:00",
  "updated_at": "2026-01-01T00:00:00+00:00"
}
```

### Get / Delete
- `GET /v1/projects/providers/{provider}/credentials?org=...`
- `DELETE /v1/projects/providers/{provider}/credentials?org=...` -> `{ "ok": true, "deleted": true }`
