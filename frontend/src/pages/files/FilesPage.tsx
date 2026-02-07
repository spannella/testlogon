import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Upload,
  FolderPlus,
  Trash2,
  Search,
  FolderOpen,
  ChevronRight,
} from "lucide-react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { ConfirmDialog } from "@/components/shared/ConfirmDialog";
import type { SortState } from "@/components/shared/DataTable";
import type { FileEntry, SharedItem } from "@/api/types";

import {
  listFiles,
  searchFiles,
  searchText,
  createFolder,
  uploadFile,
  deleteFile,
  deleteFolder,
  renameFile,
  renameFolder,
} from "@/api/endpoints/files";
import { FileTable } from "./FileTable";
import { FilePreview } from "./FilePreview";
import { SharedWithMe } from "./SharedWithMe";
import { ShareDialog } from "./ShareDialog";
import { UploadZone } from "./UploadZone";

type SearchMode = "name" | "content";

export default function FilesPage() {
  const queryClient = useQueryClient();
  const fileInputRef = React.useRef<HTMLInputElement>(null);

  // ── State ───────────────────────────────────────────────────────

  const [currentPath, setCurrentPath] = React.useState("/");
  const [sort, setSort] = React.useState<SortState>({ column: "name", direction: "asc" });
  const [selectedKeys, setSelectedKeys] = React.useState<Set<string>>(new Set());
  const [searchValue, setSearchValue] = React.useState("");
  const [isSearching, setIsSearching] = React.useState(false);
  const [searchMode, setSearchMode] = React.useState<SearchMode>("name");
  const [activeTab, setActiveTab] = React.useState("my-files");

  // Dialog state
  const [newFolderOpen, setNewFolderOpen] = React.useState(false);
  const [newFolderName, setNewFolderName] = React.useState("");
  const [renameTarget, setRenameTarget] = React.useState<FileEntry | null>(null);
  const [renameName, setRenameName] = React.useState("");
  const [shareTarget, setShareTarget] = React.useState<FileEntry | null>(null);
  const [deleteTarget, setDeleteTarget] = React.useState<FileEntry | null>(null);

  // Preview state
  const [previewFile, setPreviewFile] = React.useState<FileEntry | null>(null);

  // ── Queries ─────────────────────────────────────────────────────

  const filesQuery = useQuery({
    queryKey: ["files", currentPath, sort.column, sort.direction],
    queryFn: () => listFiles(currentPath, { sort_by: sort.column, sort_dir: sort.direction }),
    enabled: !isSearching && activeTab === "my-files",
  });

  const nameSearchQuery = useQuery({
    queryKey: ["files-search", searchValue],
    queryFn: () => searchFiles(searchValue),
    enabled: isSearching && searchMode === "name" && searchValue.length > 0,
  });

  const contentSearchQuery = useQuery({
    queryKey: ["files-search-text", searchValue],
    queryFn: () => searchText(searchValue),
    enabled: isSearching && searchMode === "content" && searchValue.length > 0,
  });

  const displayItems: FileEntry[] = isSearching
    ? searchMode === "name"
      ? (nameSearchQuery.data?.results ?? [])
      : (contentSearchQuery.data?.results ?? [])
    : (filesQuery.data?.items ?? []);

  const isLoading = isSearching
    ? searchMode === "name"
      ? nameSearchQuery.isLoading
      : contentSearchQuery.isLoading
    : filesQuery.isLoading;

  // ── Mutations ───────────────────────────────────────────────────

  const createFolderMut = useMutation({
    mutationFn: (name: string) => {
      const folderPath = currentPath.endsWith("/")
        ? currentPath + name
        : currentPath + "/" + name;
      return createFolder(folderPath);
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setNewFolderOpen(false);
      setNewFolderName("");
      toast.success("Folder created");
    },
    onError: () => toast.error("Failed to create folder"),
  });

  const deleteMut = useMutation({
    mutationFn: (entry: FileEntry) =>
      entry.type === "folder" ? deleteFolder(entry.path) : deleteFile(entry.path),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setDeleteTarget(null);
      setSelectedKeys(new Set());
      toast.success("Deleted successfully");
    },
    onError: () => toast.error("Failed to delete"),
  });

  const renameMut = useMutation({
    mutationFn: ({ entry, newName }: { entry: FileEntry; newName: string }) =>
      entry.type === "folder" ? renameFolder(entry.path, newName) : renameFile(entry.path, newName),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
      setRenameTarget(null);
      setRenameName("");
      toast.success("Renamed successfully");
    },
    onError: () => toast.error("Failed to rename"),
  });

  // ── Breadcrumbs ─────────────────────────────────────────────────

  const pathSegments = React.useMemo(() => {
    const parts = currentPath.split("/").filter(Boolean);
    const segments: { label: string; path: string }[] = [{ label: "Root", path: "/" }];
    let acc = "";
    for (const part of parts) {
      acc += "/" + part;
      segments.push({ label: part, path: acc });
    }
    return segments;
  }, [currentPath]);

  // ── Search ──────────────────────────────────────────────────────

  const handleSearchChange = (value: string) => {
    setSearchValue(value);
    setIsSearching(value.length > 0);
  };

  const toggleSearchMode = () => {
    setSearchMode((m) => (m === "name" ? "content" : "name"));
  };

  // ── Navigation ──────────────────────────────────────────────────

  const handleNavigate = (folder: FileEntry) => {
    setCurrentPath(folder.path);
    setSelectedKeys(new Set());
    setIsSearching(false);
    setSearchValue("");
  };

  const handleBreadcrumb = (path: string) => {
    setCurrentPath(path);
    setSelectedKeys(new Set());
    setIsSearching(false);
    setSearchValue("");
  };

  // ── Preview ───────────────────────────────────────────────────

  const handlePreview = (file: FileEntry) => {
    setPreviewFile(file);
  };

  const handlePreviewShared = (_item: SharedItem) => {
    // Convert SharedItem to a minimal FileEntry for preview
    const segments = _item.path.split("/").filter(Boolean);
    const name = segments.length > 0 ? (segments[segments.length - 1] ?? _item.path) : _item.path;
    const entry: FileEntry = {
      name,
      path: _item.path,
      type: "file",
    };
    setPreviewFile(entry);
  };

  // ── Upload (button) ─────────────────────────────────────────────

  const handleFileInput = async (e: React.ChangeEvent<HTMLInputElement>) => {
    if (!e.target.files || e.target.files.length === 0) return;
    const files = Array.from(e.target.files);
    for (const file of files) {
      const targetPath = currentPath.endsWith("/")
        ? currentPath + file.name
        : currentPath + "/" + file.name;
      const toastId = toast.loading(`Uploading ${file.name}...`);
      try {
        await uploadFile(file, targetPath);
        toast.success(`Uploaded ${file.name}`, { id: toastId });
      } catch {
        toast.error(`Failed to upload ${file.name}`, { id: toastId });
      }
    }
    queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
    e.target.value = "";
  };

  const handleUploadComplete = () => {
    queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
  };

  // ── Bulk delete ─────────────────────────────────────────────────

  const handleBulkDelete = async () => {
    const toDelete = displayItems.filter((f) => selectedKeys.has(f.path));
    for (const entry of toDelete) {
      try {
        if (entry.type === "folder") {
          await deleteFolder(entry.path);
        } else {
          await deleteFile(entry.path);
        }
      } catch {
        toast.error(`Failed to delete ${entry.name}`);
      }
    }
    queryClient.invalidateQueries({ queryKey: ["files", currentPath] });
    setSelectedKeys(new Set());
    toast.success("Deleted selected items");
  };

  // ── Render ──────────────────────────────────────────────────────

  return (
    <div className="p-4 md:p-6 lg:p-8 space-y-4">
      <PageHeader
        title="Files"
        description="Manage your files and folders"
      />

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="my-files">My Files</TabsTrigger>
          <TabsTrigger value="shared">Shared With Me</TabsTrigger>
        </TabsList>

        <TabsContent value="my-files" className="mt-4 space-y-4">
          {/* Breadcrumbs */}
          <nav className="flex items-center gap-1 text-sm overflow-x-auto">
            {pathSegments.map((seg, i) => (
              <React.Fragment key={seg.path}>
                {i > 0 && <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />}
                <button
                  className="shrink-0 rounded px-1.5 py-0.5 text-muted-foreground hover:bg-accent hover:text-foreground transition-colors"
                  onClick={() => handleBreadcrumb(seg.path)}
                >
                  {seg.label}
                </button>
              </React.Fragment>
            ))}
          </nav>

          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder={searchMode === "name" ? "Search by name..." : "Search file contents..."}
                value={searchValue}
                onChange={(e) => handleSearchChange(e.target.value)}
                className="pl-9"
              />
            </div>

            {/* Search mode toggle */}
            <button
              type="button"
              onClick={toggleSearchMode}
              className="rounded-full border px-3 py-1 text-xs font-medium transition-colors hover:bg-accent"
            >
              {searchMode === "name" ? "Name" : "Content"}
            </button>

            <div className="flex-1" />

            <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
              <Upload className="h-4 w-4" />
              <span className="hidden sm:inline ml-1">Upload</span>
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              className="hidden"
              onChange={handleFileInput}
            />
            <Button variant="outline" size="sm" onClick={() => setNewFolderOpen(true)}>
              <FolderPlus className="h-4 w-4" />
              <span className="hidden sm:inline ml-1">New Folder</span>
            </Button>

            {selectedKeys.size > 0 && (
              <Button variant="destructive" size="sm" onClick={handleBulkDelete}>
                <Trash2 className="h-4 w-4" />
                <span className="ml-1">Delete ({selectedKeys.size})</span>
              </Button>
            )}
          </div>

          {/* File table with drag-and-drop upload */}
          <UploadZone currentPath={currentPath} onUploadComplete={handleUploadComplete}>
            {isLoading ? (
              <div className="space-y-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <Skeleton key={i} className="h-10 w-full" />
                ))}
              </div>
            ) : (
              <FileTable
                data={displayItems}
                sort={sort}
                onSort={setSort}
                selectedKeys={selectedKeys}
                onSelectionChange={setSelectedKeys}
                onNavigate={handleNavigate}
                onPreview={handlePreview}
                onShare={(f) => setShareTarget(f)}
                onRename={(f) => { setRenameTarget(f); setRenameName(f.name); }}
                onMove={() => toast.info("Move dialog coming in a future step")}
                onDelete={(f) => setDeleteTarget(f)}
                emptyState={
                  <EmptyState
                    icon={<FolderOpen className="h-6 w-6" />}
                    title={isSearching ? "No results" : "Empty folder"}
                    description={isSearching ? "Try a different search term" : "Upload files or create a folder to get started"}
                  />
                }
              />
            )}
          </UploadZone>
        </TabsContent>

        <TabsContent value="shared" className="mt-4">
          <SharedWithMe onPreviewShared={handlePreviewShared} />
        </TabsContent>
      </Tabs>

      {/* New folder dialog */}
      <Dialog open={newFolderOpen} onOpenChange={setNewFolderOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>New Folder</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="folder-name">Folder name</Label>
            <Input
              id="folder-name"
              placeholder="Enter folder name"
              value={newFolderName}
              onChange={(e) => setNewFolderName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && newFolderName.trim()) createFolderMut.mutate(newFolderName.trim());
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              onClick={() => createFolderMut.mutate(newFolderName.trim())}
              disabled={!newFolderName.trim() || createFolderMut.isPending}
            >
              {createFolderMut.isPending ? "Creating..." : "Create"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Rename dialog */}
      <Dialog open={!!renameTarget} onOpenChange={(open) => { if (!open) setRenameTarget(null); }}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Rename</DialogTitle>
          </DialogHeader>
          <div className="space-y-2 py-2">
            <Label htmlFor="rename-input">New name</Label>
            <Input
              id="rename-input"
              value={renameName}
              onChange={(e) => setRenameName(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === "Enter" && renameName.trim() && renameTarget) {
                  renameMut.mutate({ entry: renameTarget, newName: renameName.trim() });
                }
              }}
              autoFocus
            />
          </div>
          <DialogFooter>
            <Button
              onClick={() => renameTarget && renameMut.mutate({ entry: renameTarget, newName: renameName.trim() })}
              disabled={!renameName.trim() || renameMut.isPending}
            >
              {renameMut.isPending ? "Renaming..." : "Rename"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Delete confirm */}
      <ConfirmDialog
        open={!!deleteTarget}
        onOpenChange={(open) => { if (!open) setDeleteTarget(null); }}
        title={`Delete ${deleteTarget?.type === "folder" ? "folder" : "file"}?`}
        description={`Are you sure you want to delete "${deleteTarget?.name}"? This action cannot be undone.`}
        confirmLabel="Delete"
        variant="danger"
        onConfirm={() => deleteTarget && deleteMut.mutate(deleteTarget)}
        loading={deleteMut.isPending}
      />

      {/* Share dialog */}
      {shareTarget && (
        <ShareDialog
          open={!!shareTarget}
          onOpenChange={(open) => { if (!open) setShareTarget(null); }}
          filePath={shareTarget.path}
        />
      )}

      {/* File preview modal */}
      {previewFile && (
        <FilePreview
          file={previewFile}
          files={displayItems}
          onClose={() => setPreviewFile(null)}
          onNavigate={(f) => setPreviewFile(f)}
        />
      )}
    </div>
  );
}
