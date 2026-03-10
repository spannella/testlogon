import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { listSftpMounts, listMountMockFiles } from "@/api/endpoints/files";
import { ApiError } from "@/api/client";
import type { MountMockFileItem } from "@/api/types";

type MockSortBy = "name" | "type" | "size" | "mtime";
type MockSortDir = "asc" | "desc";
type MockFilterType = "all" | "file" | "folder";

function normalizeMockPath(path: string): string {
  const raw = (path || "/").trim() || "/";
  const parts: string[] = [];
  raw.split("/").forEach((part) => {
    if (!part || part === ".") return;
    if (part === "..") {
      parts.pop();
      return;
    }
    parts.push(part);
  });
  return parts.length ? `/${parts.join("/")}/` : "/";
}

function parentMockPath(path: string): string {
  const parts = normalizeMockPath(path).split("/").filter(Boolean);
  if (!parts.length) return "/";
  parts.pop();
  return parts.length ? `/${parts.join("/")}/` : "/";
}

function mockBreadcrumbs(path: string): Array<{ label: string; path: string }> {
  const parts = normalizeMockPath(path).split("/").filter(Boolean);
  const crumbs: Array<{ label: string; path: string }> = [{ label: "root", path: "/" }];
  let acc = "";
  for (const part of parts) {
    acc += `/${part}`;
    crumbs.push({ label: part, path: `${acc}/` });
  }
  return crumbs;
}

function extractMockErrorCode(err: unknown): string {
  const body =
    err instanceof ApiError
      ? err.body
      : err && typeof err === "object" && "body" in (err as Record<string, unknown>)
        ? (err as { body?: unknown }).body
        : null;
  if (body && typeof body === "object") {
    const detail = (body as { detail?: unknown }).detail;
    if (detail && typeof detail === "object") {
      const code = (detail as { code?: unknown }).code;
      if (typeof code === "string") return code;
    }
  }
  return "";
}

function mockErrorRemediation(code: string, path: string): string {
  if (code === "sftp_mock_backend_disabled") {
    return "Enable FILEMGR_SFTP_BACKEND=mock and restart the backend, then retry.";
  }
  if (code === "mock_path_not_found") {
    return `Path ${path} was not found. Navigate from root or create it under the local mock directory.`;
  }
  if (code === "mock_path_not_directory") {
    return `Path ${path} is a file. Browse to a folder path (try Up) before listing.`;
  }
  return "Verify mount/path settings and try again.";
}

function formatBytesCompact(bytes: number): string {
  if (!bytes) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

export default function SftpMockBrowserTab() {
  const [mountId, setMountId] = React.useState("");
  const [path, setPath] = React.useState("/");
  const [pathInput, setPathInput] = React.useState("/");
  const [filterText, setFilterText] = React.useState("");
  const [filterType, setFilterType] = React.useState<MockFilterType>("all");
  const [sortBy, setSortBy] = React.useState<MockSortBy>("name");
  const [sortDir, setSortDir] = React.useState<MockSortDir>("asc");
  const [cursor, setCursor] = React.useState<string | undefined>(undefined);
  const [items, setItems] = React.useState<MountMockFileItem[]>([]);
  const [filesystemPath, setFilesystemPath] = React.useState<string>("");
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState<string>("");

  const mountsQuery = useQuery({
    queryKey: ["files-sftp-mounts"],
    queryFn: () => listSftpMounts(),
  });

  const loadFiles = React.useCallback(
    async (opts?: { append?: boolean; cursor?: string; path?: string }) => {
      const id = String(mountId || "").trim();
      if (!id) return;
      const browsePath = normalizeMockPath(opts?.path ?? path);
      setLoading(true);
      setError("");
      try {
        const resp = await listMountMockFiles(id, {
          path: browsePath,
          limit: 200,
          cursor: opts?.cursor,
        });
        const next = Array.isArray(resp.items) ? resp.items : [];
        setItems((prev) => (opts?.append ? [...prev, ...next] : next));
        setPath(resp.path || browsePath);
        setPathInput(resp.path || browsePath);
        setCursor(resp.cursor || undefined);
        setFilesystemPath(resp.filesystem_path || "");
      } catch (err) {
        const code = extractMockErrorCode(err);
        setError(mockErrorRemediation(code, browsePath));
        setItems([]);
        setCursor(undefined);
        setFilesystemPath("");
      } finally {
        setLoading(false);
      }
    },
    [mountId, path],
  );

  React.useEffect(() => {
    if (!mountId) return;
    void loadFiles({ path });
  }, [mountId, path, loadFiles]);

  // Auto-select first mount
  React.useEffect(() => {
    const mounts = mountsQuery.data?.items ?? [];
    if (!mountId && mounts.length > 0) {
      setMountId(String(mounts[0]?.id || ""));
    }
  }, [mountsQuery.data, mountId]);

  const displayItems = React.useMemo(() => {
    const q = filterText.trim().toLowerCase();
    const filtered = items.filter((it) => {
      if (filterType !== "all" && it.type !== filterType) return false;
      if (!q) return true;
      return `${it.name} ${it.path} ${it.type}`.toLowerCase().includes(q);
    });
    filtered.sort((a, b) => {
      let av: string | number;
      let bv: string | number;
      if (sortBy === "size") {
        av = Number(a.size || 0);
        bv = Number(b.size || 0);
      } else if (sortBy === "mtime") {
        av = Number(a.modified_at || 0);
        bv = Number(b.modified_at || 0);
      } else if (sortBy === "type") {
        av = String(a.type || "");
        bv = String(b.type || "");
      } else {
        av = String(a.name || "").toLowerCase();
        bv = String(b.name || "").toLowerCase();
      }
      if (av < bv) return sortDir === "asc" ? -1 : 1;
      if (av > bv) return sortDir === "asc" ? 1 : -1;
      return 0;
    });
    return filtered;
  }, [filterText, filterType, items, sortBy, sortDir]);

  const crumbs = React.useMemo(() => mockBreadcrumbs(path), [path]);

  return (
    <div className="space-y-3">
      <p className="text-sm text-muted-foreground">
        Browse mock SFTP mount paths. Requires{" "}
        <code className="rounded bg-muted px-1">FILEMGR_SFTP_BACKEND=mock</code> on the backend.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <Label htmlFor="mock-mount-id">Mount</Label>
        <select
          id="mock-mount-id"
          className="h-9 rounded-md border px-2 text-sm"
          value={mountId}
          onChange={(e) => {
            setMountId(e.target.value);
            setPath("/");
            setPathInput("/");
            setCursor(undefined);
          }}
        >
          <option value="">Select mount…</option>
          {(mountsQuery.data?.items ?? []).map((m) => (
            <option key={m.id} value={m.id}>
              {m.id} ({m.protocol || "sftp"})
            </option>
          ))}
        </select>

        <Label htmlFor="mock-path-input">Path</Label>
        <Input
          id="mock-path-input"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          className="max-w-xs"
        />
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            const next = normalizeMockPath(pathInput);
            setPath(next);
            setCursor(undefined);
          }}
          disabled={!mountId || loading}
        >
          Go
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => {
            const next = parentMockPath(path);
            setPath(next);
            setPathInput(next);
            setCursor(undefined);
          }}
          disabled={!mountId || loading}
        >
          Up
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={() => void loadFiles({ path })}
          disabled={!mountId || loading}
        >
          Refresh
        </Button>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        {crumbs.map((c, idx) => (
          <React.Fragment key={c.path}>
            {idx > 0 && <span className="text-muted-foreground">/</span>}
            <button
              className="underline"
              onClick={() => {
                setPath(c.path);
                setPathInput(c.path);
                setCursor(undefined);
              }}
            >
              {c.label}
            </button>
          </React.Fragment>
        ))}
      </div>

      <div className="flex flex-wrap items-center gap-2">
        <Input
          placeholder="Filter by name or path"
          value={filterText}
          onChange={(e) => setFilterText(e.target.value)}
          className="max-w-xs"
        />
        <select
          className="h-9 rounded-md border px-2 text-sm"
          value={filterType}
          onChange={(e) => setFilterType(e.target.value as MockFilterType)}
        >
          <option value="all">All types</option>
          <option value="folder">Folders</option>
          <option value="file">Files</option>
        </select>
        <select
          className="h-9 rounded-md border px-2 text-sm"
          value={sortBy}
          onChange={(e) => setSortBy(e.target.value as MockSortBy)}
        >
          <option value="name">Sort: name</option>
          <option value="type">Sort: type</option>
          <option value="size">Sort: size</option>
          <option value="mtime">Sort: modified</option>
        </select>
        <select
          className="h-9 rounded-md border px-2 text-sm"
          value={sortDir}
          onChange={(e) => setSortDir(e.target.value as MockSortDir)}
        >
          <option value="asc">Ascending</option>
          <option value="desc">Descending</option>
        </select>
      </div>

      <div className="flex flex-wrap items-center gap-2 text-xs">
        <Button
          variant="ghost"
          size="sm"
          onClick={() =>
            navigator.clipboard
              ?.writeText(`/mounts/${mountId}${path}`)
              .then(() => toast.success("Copied mount-relative path"))
          }
          disabled={!mountId}
        >
          Copy mount-relative path
        </Button>
        {filesystemPath && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() =>
              navigator.clipboard
                ?.writeText(filesystemPath)
                .then(() => toast.success("Copied filesystem path"))
            }
          >
            Copy filesystem path
          </Button>
        )}
        <span className="text-muted-foreground">
          /mounts/{mountId || "<mount>"}
          {path}
        </span>
      </div>

      {filesystemPath && (
        <div className="rounded border bg-muted/40 px-2 py-1 text-xs text-muted-foreground">
          Filesystem path: <span className="font-mono">{filesystemPath}</span>
        </div>
      )}

      {error && (
        <div className="rounded border border-amber-300 bg-amber-50 p-2 text-sm text-amber-900">
          {error}
        </div>
      )}

      <div className="max-h-96 overflow-auto rounded border">
        {loading ? (
          <div className="p-3 text-sm text-muted-foreground">Loading…</div>
        ) : displayItems.length === 0 ? (
          <div className="p-3 text-sm text-muted-foreground">
            {mountId ? "No items match current filters." : "Select a mount to browse."}
          </div>
        ) : (
          <div className="divide-y">
            {displayItems.map((it) => (
              <div
                key={`${it.path}-${it.modified_at}`}
                className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
              >
                <div className="min-w-0">
                  <div className="truncate font-mono">{it.path}</div>
                  <div className="text-xs text-muted-foreground">
                    {it.type}
                    {it.type === "file" ? ` • ${formatBytesCompact(Number(it.size || 0))}` : ""}
                  </div>
                </div>
                {it.type === "folder" && (
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => {
                      const next = normalizeMockPath(it.path);
                      setPath(next);
                      setPathInput(next);
                      setCursor(undefined);
                    }}
                  >
                    Open
                  </Button>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {cursor && !loading && (
        <div className="flex justify-end">
          <Button
            variant="outline"
            size="sm"
            onClick={() => void loadFiles({ append: true, cursor, path })}
          >
            Load more
          </Button>
        </div>
      )}
    </div>
  );
}
