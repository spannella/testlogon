import * as React from "react";
import { useQuery } from "@tanstack/react-query";
import { Folder, FileText, ImageIcon, Music, Video, Lock, Search, X, ChevronRight } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { cn } from "@/lib/utils";
import { listFiles, searchFiles } from "@/api/endpoints/files";
import type { FileEntry } from "@/api/types";

interface FilePickerDialogProps {
  open: boolean;
  onClose: () => void;
  onSelect: (entry: FileEntry, permission: "read" | "write") => void;
  /** Hide the permission toggle (e.g. when picking media for a post rather than sharing) */
  showPermission?: boolean;
}

function fileIcon(entry: FileEntry) {
  if (entry.type === "folder") return <Folder className="h-5 w-5 text-amber-500 shrink-0" />;
  const ct = entry.content_type ?? "";
  if (ct.startsWith("image/")) return <ImageIcon className="h-5 w-5 text-blue-500 shrink-0" />;
  if (ct.startsWith("audio/")) return <Music className="h-5 w-5 text-purple-500 shrink-0" />;
  if (ct.startsWith("video/")) return <Video className="h-5 w-5 text-green-500 shrink-0" />;
  return <FileText className="h-5 w-5 text-muted-foreground shrink-0" />;
}

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 ** 2).toFixed(1)} MB`;
}

function pathParts(path: string): string[] {
  const parts = path.split("/").filter(Boolean);
  return parts;
}

export function FilePickerDialog({ open, onClose, onSelect, showPermission = true }: FilePickerDialogProps) {
  const [currentPath, setCurrentPath] = React.useState("/");
  const [selected, setSelected] = React.useState<FileEntry | null>(null);
  const [permission, setPermission] = React.useState<"read" | "write">("read");
  const [search, setSearch] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");

  // Reset state when dialog opens
  React.useEffect(() => {
    if (open) {
      setCurrentPath("/");
      setSelected(null);
      setPermission("read");
      setSearch("");
      setDebouncedSearch("");
    }
  }, [open]);

  // Debounce search input
  React.useEffect(() => {
    const id = window.setTimeout(() => setDebouncedSearch(search), 300);
    return () => window.clearTimeout(id);
  }, [search]);

  const isSearching = debouncedSearch.trim().length > 0;

  const { data: listData, isLoading: listLoading } = useQuery({
    queryKey: ["files", "list", currentPath],
    queryFn: () => listFiles(currentPath, { limit: 100 }),
    enabled: open && !isSearching,
  });

  const { data: searchData, isLoading: searchLoading } = useQuery({
    queryKey: ["files", "search", debouncedSearch],
    queryFn: () => searchFiles(debouncedSearch.trim()),
    enabled: open && isSearching,
  });

  const entries: FileEntry[] = isSearching
    ? (searchData?.results ?? [])
    : (listData?.items ?? []);

  const isLoading = isSearching ? searchLoading : listLoading;

  const navigate = (entry: FileEntry) => {
    if (entry.type === "folder") {
      setCurrentPath(entry.path.endsWith("/") ? entry.path : entry.path + "/");
      setSelected(null);
    } else {
      setSelected(entry);
    }
  };

  const navigateToCrumb = (index: number) => {
    if (index < 0) {
      setCurrentPath("/");
    } else {
      const parts = pathParts(currentPath);
      const newPath = "/" + parts.slice(0, index + 1).join("/") + "/";
      setCurrentPath(newPath);
    }
    setSelected(null);
  };

  const crumbs = pathParts(currentPath);

  const handleConfirm = () => {
    if (selected) {
      onSelect(selected, permission);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose(); }}>
      <DialogContent className="max-w-lg max-h-[80vh] flex flex-col gap-0 p-0">
        <DialogHeader className="px-4 pt-4 pb-2">
          <DialogTitle>Select a file from your Files</DialogTitle>
        </DialogHeader>

        {/* Search bar */}
        <div className="relative mx-4 mb-2">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search files..."
            value={search}
            onChange={(e) => { setSearch(e.target.value); setSelected(null); }}
            className="w-full rounded-md border border-input bg-background pl-8 pr-8 py-1.5 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          {search && (
            <button
              type="button"
              onClick={() => { setSearch(""); setDebouncedSearch(""); }}
              className="absolute right-2 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
            >
              <X className="h-3.5 w-3.5" />
            </button>
          )}
        </div>

        {/* Breadcrumb */}
        {!isSearching && (
          <div className="flex items-center gap-0.5 px-4 pb-1 text-xs text-muted-foreground flex-wrap">
            <button
              type="button"
              onClick={() => navigateToCrumb(-1)}
              className="hover:text-foreground font-medium"
            >
              Home
            </button>
            {crumbs.map((crumb, i) => (
              <React.Fragment key={i}>
                <ChevronRight className="h-3 w-3 shrink-0" />
                <button
                  type="button"
                  onClick={() => navigateToCrumb(i)}
                  className={cn(
                    "hover:text-foreground",
                    i === crumbs.length - 1 ? "font-medium text-foreground" : "",
                  )}
                >
                  {crumb}
                </button>
              </React.Fragment>
            ))}
          </div>
        )}

        {/* File list */}
        <div className="flex-1 overflow-y-auto min-h-0 border-t border-border mx-0">
          {isLoading ? (
            <div className="p-4 text-center text-sm text-muted-foreground">Loading...</div>
          ) : entries.length === 0 ? (
            <div className="p-4 text-center text-sm text-muted-foreground">
              {isSearching ? "No files match your search." : "This folder is empty."}
            </div>
          ) : (
            <ul className="divide-y divide-border">
              {entries.map((entry) => {
                const isSelected = selected?.path === entry.path;
                return (
                  <li key={entry.path}>
                    <button
                      type="button"
                      onClick={() => navigate(entry)}
                      className={cn(
                        "flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors hover:bg-muted/60",
                        isSelected && "bg-primary/10",
                      )}
                    >
                      {fileIcon(entry)}
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium">{entry.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {entry.type === "folder" ? "Folder" : [
                            entry.size != null ? formatBytes(entry.size) : null,
                            entry.content_type,
                          ].filter(Boolean).join(" · ")}
                        </p>
                      </div>
                      {entry.is_encrypted && (
                        <Lock className="h-3.5 w-3.5 shrink-0 text-amber-500" aria-label="Encrypted" />
                      )}
                      {entry.type === "folder" && (
                        <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                      )}
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </div>

        {/* Bottom controls */}
        <div className="border-t border-border px-4 py-3 space-y-3">
          {selected && (
            <div className="rounded-md border border-border bg-muted/40 px-3 py-2 text-xs">
              <p className="font-medium truncate">{selected.name}</p>
              {selected.size != null && (
                <p className="text-muted-foreground">{formatBytes(selected.size)}</p>
              )}
              {selected.is_encrypted && (
                <p className="flex items-center gap-1 text-amber-600 mt-1">
                  <Lock className="h-3 w-3" /> Encrypted file — password shared separately
                </p>
              )}
            </div>
          )}

          {/* Permission toggle */}
          {showPermission && (
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground shrink-0">Permission:</span>
              <div className="flex rounded-md border border-input overflow-hidden text-xs">
                <button
                  type="button"
                  onClick={() => setPermission("read")}
                  className={cn(
                    "px-3 py-1 transition-colors",
                    permission === "read"
                      ? "bg-primary text-primary-foreground"
                      : "bg-background text-muted-foreground hover:bg-muted",
                  )}
                >
                  View only
                </button>
                <button
                  type="button"
                  onClick={() => setPermission("write")}
                  className={cn(
                    "px-3 py-1 transition-colors border-l border-input",
                    permission === "write"
                      ? "bg-primary text-primary-foreground"
                      : "bg-background text-muted-foreground hover:bg-muted",
                  )}
                >
                  View + Edit
                </button>
              </div>
            </div>
          )}
        </div>

        <DialogFooter className="px-4 pb-4 gap-2">
          <Button variant="outline" onClick={onClose} type="button">
            Cancel
          </Button>
          <Button onClick={handleConfirm} disabled={!selected} type="button">
            Attach file
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
