# Project Layer Plan on Top of File Manager

## Goal
Add a lightweight **Project** concept above the existing file manager so users can group, describe, and track files as a logical unit, while keeping room for future external providers (GitHub/GitLab).

## Guiding Principles
- Keep the current file manager as the source of truth for local file operations.
- Treat projects as metadata + references, not as a new filesystem.
- Start local-first; design provider boundaries now so remote tracking can be added without rework.
- Preserve backward compatibility: users can still use the file manager without projects.

## Proposed Data Model

### Project
- `id` (UUID/string)
- `name`
- `description` (optional)
- `tags` (optional)
- `created_at`, `updated_at`
- `owner` (optional, if multi-user exists)
- `settings` (JSON map for extensibility)

### TrackedFile
- `id`
- `project_id`
- `provider` (`local`, `github`, `gitlab`, etc.)
- `provider_ref` (provider-specific identity, e.g., local absolute/virtual path, repo+path+ref)
- `display_path` (normalized path shown in UI)
- `status` (active, missing, archived)
- `last_seen_at`
- `metadata` (size, mime, hash, commit sha, etc. as available)

### Optional ProjectEvent (future-safe)
- `id`
- `project_id`
- `type` (file_added, file_removed, sync_ran, provider_error)
- `payload`
- `created_at`

## API/Service Layer Design

### Project Management
- `createProject(input)`
- `updateProject(projectId, patch)`
- `deleteProject(projectId)`
- `getProject(projectId)`
- `listProjects(filters, pagination)`

### File Tracking
- `addFileToProject(projectId, fileRef)`
- `removeFileFromProject(projectId, trackedFileId|fileRef)`
- `listProjectFiles(projectId, filters, pagination)`
- `refreshProjectFileState(projectId, options)` (revalidate existence/metadata)

### Provider Abstraction (critical for GitHub/GitLab)
Define an interface such as:
- `resolve(ref) -> canonicalRef`
- `exists(canonicalRef) -> boolean`
- `getMetadata(canonicalRef) -> metadata`
- `listChildren(canonicalRef) -> refs` (optional)

Start with `LocalFileProvider`; add `GitHubProvider` and `GitLabProvider` later behind the same interface.

## Integration with Existing File Manager
1. Keep all read/write file actions in the file manager.
2. When adding tracked files, validate references through the relevant provider.
3. For local files, map file manager path identifiers directly into `provider_ref`.
4. Project views should query tracked files and then hydrate metadata via provider/file-manager calls.

## Permissions & Access Control
- Reuse existing file manager auth checks for local resources.
- Project-level authorization should gate project CRUD and membership visibility.
- For external providers, store credentials/tokens per user/org and scope access to least privilege.

## Sync & Consistency Strategy
- Synchronous validation on add/remove operations.
- Asynchronous background reconciliation job:
  - marks missing files,
  - updates metadata/hash,
  - emits events for project activity feed.
- Define retry/backoff and dead-letter handling for external API failures.

## UX Rollout Plan

### Phase 1 (MVP: local only)
- Create/list/update/delete projects.
- Add/remove local files from a project.
- Project details page showing tracked files and missing-file warnings.

### Phase 2 (quality and scale)
- Bulk add/remove.
- Search/filter by tags and file status.
- Background reconciliation and simple activity events.

### Phase 3 (external providers)
- GitHub file references (repo/path/ref)
- GitLab file references
- Token management + provider health/error display

## Migration & Compatibility
- No migration needed for existing non-project users.
- If needed, provide utility to create a project from a selected folder/file-manager query.
- Feature-flag project functionality for gradual rollout.

## Suggested Implementation Steps
1. Introduce DB tables/models for `Project` and `TrackedFile`.
2. Add provider interface and implement `LocalFileProvider`.
3. Build project service methods and REST/GraphQL endpoints.
4. Add UI components: project list, project detail, add/remove tracked file flows.
5. Add background reconciliation job + status indicators.
6. Add tests (unit: service/provider; integration: API; e2e: basic project workflows).
7. Instrument metrics/logging (project count, sync failures, provider latency).

## Risks and Mitigations
- **Path identity drift (renames/moves):** rely on periodic reconciliation and hash/metadata matching where feasible.
- **External API rate limits:** cache metadata and use incremental sync.
- **Permission mismatches:** enforce checks at provider boundary and project boundary.
- **Model bloat:** keep `metadata/settings` flexible, but document reserved keys.

## Open Questions
- Should projects allow folder-level tracking (auto-include children), or file-only for MVP?
- Should tracked files be snapshots (immutable ref) or floating refs (e.g., branch head)?
- Do projects require collaboration roles (owner/editor/viewer) now or later?
- What retention/audit requirements exist for project events?
## Execution Backlog
- Implementation tickets are tracked in `docs/project-layer-implementation-tickets.md`.

