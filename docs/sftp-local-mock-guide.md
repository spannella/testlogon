# Local SFTP/SCP/FTP Mocking Guide

Use the built-in mock backend to develop mounted-path flows for `sftp`, `scp`, and `ftp` mounts without running a real remote server.

## Enable mock backend

Set environment variables before starting the API:

- `FILEMGR_SFTP_BACKEND=mock`
- `FILEMGR_SFTP_MOCK_ROOT_DIR=/tmp/filemgr-sftp-mock` (or any local writable path)

When enabled, `SftpConnectionPool` uses a local filesystem-backed mock backend for all supported protocols instead of dialing Paramiko/FTP.

## How it works

- Each mount maps to a local directory:
  - `${FILEMGR_SFTP_MOCK_ROOT_DIR}/{owner}/{mount_id}`
- File operations (`listdir_attr`, `stat`, `open`, `mkdir`, `remove`, `rmdir`, `rename`) are executed against that directory for `sftp`, `scp`, and `ftp` mounts.
- Connection pooling/reuse, retry/circuit logic, and router/provider behavior remain active, so local behavior approximates production control flow.

## Quick bootstrap

Example local fixture setup for owner `u1`, mount `m1`:

```bash
export FILEMGR_SFTP_BACKEND=mock
export FILEMGR_SFTP_MOCK_ROOT_DIR=/tmp/filemgr-sftp-mock
mkdir -p /tmp/filemgr-sftp-mock/u1/m1/team
printf 'hello from mock sftp\n' > /tmp/filemgr-sftp-mock/u1/m1/team/readme.txt
```

Then create/update mount `m1` with `remote_root=/team` and browse `/mounts/m1/` in the file manager.

## Notes

- Destination allowlist and mount policy checks are still enforced before connection.
- This mock backend is for local/dev validation and should not be enabled in production.


## Dev UI inspection

In the File Manager mount panel, each mount row now includes a **Mock files** action.
This calls `GET /v1/fs/mounts/{mount_id}/mock-files?path=/` and shows the current mock remote directory listing in a modal for quick local debugging.


## Endpoint contract (`GET /v1/fs/mounts/{mount_id}/mock-files`)

Query params:
- `path` (optional, default `/`): mock remote directory to list.
- `limit` (optional, default `200`, min `1`, max `1000`): max items returned.
- `cursor` (optional): opaque pagination cursor returned from a previous response.

Success response shape:
```json
{
  "mount_id": "m1",
  "owner": "u1",
  "backend": "mock",
  "path": "/team",
  "items": [
    {"name": "docs", "path": "/team/docs/", "type": "folder", "size": 0, "modified_at": 1715000000},
    {"name": "readme.txt", "path": "/team/readme.txt", "type": "file", "size": 42, "modified_at": 1715000012}
  ],
  "limit": 200,
  "cursor": "eyJtb2RlIjoib2Zmc2V0Iiwib2Zmc2V0IjoyMDB9"
}
```

Stable error payloads:
- `409 sftp_mock_backend_disabled`: mock backend is not enabled.
- `400 mock_path_invalid`: invalid path traversal or malformed path.
- `404 mock_path_not_found`: requested mock path does not exist.
- `400 mock_path_not_directory`: requested path exists but is not a directory.
- `400 mock_path_invalid_cursor`: cursor is malformed/invalid.
- `400 mock_path_invalid_limit`: limit is outside allowed bounds.

All error payloads follow:
```json
{
  "code": "mock_path_not_found",
  "message": "mock path not found",
  "path": "/team/missing"
}
```


## Mock browser usability notes

- The modal now supports client-side sort/filter controls (`name`, `type`, `size`, `modified`) to keep large folders usable.
- Breadcrumbs, folder drill-down, up navigation, and refresh operate within the current mount/path context.
- For common errors (`sftp_mock_backend_disabled`, `mock_path_not_found`, `mock_path_not_directory`), the modal shows remediation copy and a copyable mount-relative path helper.
- When available, a copy helper for the resolved local mock filesystem path is displayed.
