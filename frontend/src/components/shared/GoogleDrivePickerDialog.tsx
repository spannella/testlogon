import * as React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  Folder,
  FileText,
  Image,
  Video,
  ChevronRight,
  Loader2,
  HardDrive,
} from "lucide-react";
import { toast } from "sonner";
import {
  browseGoogleDriveFiles,
  importDriveFile,
  type DriveFile,
} from "@/api/endpoints/googleDrive";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Checkbox } from "@/components/ui/checkbox";
import { Skeleton } from "@/components/ui/skeleton";

const FOLDER_MIME = "application/vnd.google-apps.folder";

interface BreadcrumbEntry {
  id: string;
  name: string;
}

interface GoogleDrivePickerDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onImportComplete?: (path: string) => void;
  currentPath?: string;
}

function formatSize(sizeStr?: string): string {
  if (!sizeStr) return "";
  const bytes = parseInt(sizeStr, 10);
  if (isNaN(bytes) || bytes === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let idx = 0;
  while (value >= 1024 && idx < units.length - 1) {
    value /= 1024;
    idx += 1;
  }
  return `${value.toFixed(value >= 10 || idx === 0 ? 0 : 1)} ${units[idx]}`;
}

function formatDate(iso?: string): string {
  if (!iso) return "";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      year: "numeric",
      month: "short",
      day: "numeric",
    });
  } catch {
    return "";
  }
}

function driveFileIcon(mimeType: string) {
  if (mimeType === FOLDER_MIME)
    return <Folder className="h-4 w-4 text-blue-500 shrink-0" />;
  if (mimeType.startsWith("image/"))
    return <Image className="h-4 w-4 text-green-500 shrink-0" />;
  if (mimeType.startsWith("video/"))
    return <Video className="h-4 w-4 text-purple-500 shrink-0" />;
  if (mimeType === "application/pdf")
    return <FileText className="h-4 w-4 text-red-500 shrink-0" />;
  return <FileText className="h-4 w-4 text-muted-foreground shrink-0" />;
}

export function GoogleDrivePickerDialog({
  open,
  onOpenChange,
  onImportComplete,
  currentPath = "/",
}: GoogleDrivePickerDialogProps) {
  const queryClient = useQueryClient();
  const [breadcrumbs, setBreadcrumbs] = React.useState<BreadcrumbEntry[]>([
    { id: "root", name: "My Drive" },
  ]);
  const [searchQuery, setSearchQuery] = React.useState("");
  const [debouncedSearch, setDebouncedSearch] = React.useState("");
  const [selectedFiles, setSelectedFiles] = React.useState<Set<string>>(
    new Set(),
  );
  const [importing, setImporting] = React.useState(false);

  const currentFolderId = breadcrumbs[breadcrumbs.length - 1]?.id ?? "root";

  // Debounce search input
  React.useEffect(() => {
    const timer = setTimeout(() => setDebouncedSearch(searchQuery), 300);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  // Reset state when dialog opens
  React.useEffect(() => {
    if (open) {
      setBreadcrumbs([{ id: "root", name: "My Drive" }]);
      setSearchQuery("");
      setDebouncedSearch("");
      setSelectedFiles(new Set());
      setImporting(false);
    }
  }, [open]);

  const filesQuery = useQuery({
    queryKey: ["drive-files", currentFolderId, debouncedSearch],
    queryFn: () =>
      browseGoogleDriveFiles({
        folder_id: currentFolderId,
        q: debouncedSearch || undefined,
        page_size: 100,
      }),
    enabled: open,
    staleTime: 30_000,
  });

  const files = filesQuery.data?.files ?? [];

  // Sort: folders first, then alphabetically
  const sortedFiles = React.useMemo(() => {
    return [...files].sort((a, b) => {
      const aIsFolder = a.mimeType === FOLDER_MIME ? 0 : 1;
      const bIsFolder = b.mimeType === FOLDER_MIME ? 0 : 1;
      if (aIsFolder !== bIsFolder) return aIsFolder - bIsFolder;
      return a.name.localeCompare(b.name);
    });
  }, [files]);

  const navigateToFolder = React.useCallback(
    (folderId: string, folderName: string) => {
      setBreadcrumbs((prev) => [...prev, { id: folderId, name: folderName }]);
      setSelectedFiles(new Set());
      setSearchQuery("");
      setDebouncedSearch("");
    },
    [],
  );

  const navigateToBreadcrumb = React.useCallback((index: number) => {
    setBreadcrumbs((prev) => prev.slice(0, index + 1));
    setSelectedFiles(new Set());
  }, []);

  const toggleFileSelection = React.useCallback((fileId: string) => {
    setSelectedFiles((prev) => {
      const next = new Set(prev);
      if (next.has(fileId)) {
        next.delete(fileId);
      } else {
        next.add(fileId);
      }
      return next;
    });
  }, []);

  const handleImport = React.useCallback(async () => {
    if (selectedFiles.size === 0) return;
    setImporting(true);
    let successCount = 0;
    let lastPath = "";

    for (const fileId of selectedFiles) {
      const file = files.find((f) => f.id === fileId);
      if (!file) continue;
      const destPath = currentPath.endsWith("/")
        ? `${currentPath}${file.name}`
        : `${currentPath}/${file.name}`;
      try {
        const result = await importDriveFile(fileId, destPath);
        successCount++;
        lastPath = result.path;
      } catch {
        toast.error(`Failed to import ${file.name}`);
      }
    }

    setImporting(false);
    if (successCount > 0) {
      toast.success(
        `Imported ${successCount} file${successCount > 1 ? "s" : ""}`,
      );
      queryClient.invalidateQueries({ queryKey: ["files"] });
      onImportComplete?.(lastPath);
      onOpenChange(false);
    }
  }, [
    selectedFiles,
    files,
    currentPath,
    queryClient,
    onImportComplete,
    onOpenChange,
  ]);

  const selectedCount = selectedFiles.size;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-w-2xl" data-testid="drive-picker-dialog">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <HardDrive className="h-5 w-5" />
            Google Drive
          </DialogTitle>
        </DialogHeader>

        {/* Search */}
        <div className="px-1">
          <Input
            placeholder="Search files..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            data-testid="drive-search-input"
          />
        </div>

        {/* Breadcrumbs */}
        <div
          className="flex items-center gap-1 overflow-x-auto text-sm px-1"
          data-testid="drive-breadcrumbs"
        >
          {breadcrumbs.map((crumb, index) => (
            <React.Fragment key={crumb.id}>
              {index > 0 && (
                <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
              )}
              <button
                className={`shrink-0 hover:underline ${
                  index === breadcrumbs.length - 1
                    ? "font-semibold"
                    : "text-muted-foreground"
                }`}
                onClick={() => navigateToBreadcrumb(index)}
                data-testid={`breadcrumb-${index}`}
              >
                {crumb.name}
              </button>
            </React.Fragment>
          ))}
        </div>

        {/* File list */}
        <ScrollArea className="h-[350px] rounded-md border">
          {filesQuery.isLoading ? (
            <div className="space-y-2 p-3">
              {[1, 2, 3].map((i) => (
                <Skeleton key={i} className="h-10 w-full" />
              ))}
            </div>
          ) : sortedFiles.length === 0 ? (
            <div
              className="flex items-center justify-center h-full text-sm text-muted-foreground"
              data-testid="drive-empty-state"
            >
              No files in this folder
            </div>
          ) : (
            <div className="divide-y" data-testid="drive-file-list">
              {sortedFiles.map((file) => {
                const isFolder = file.mimeType === FOLDER_MIME;
                const isSelected = selectedFiles.has(file.id);
                return (
                  <div
                    key={file.id}
                    className={`flex items-center gap-3 px-3 py-2 text-sm hover:bg-muted/50 ${
                      isSelected ? "bg-muted/30" : ""
                    } ${isFolder ? "cursor-pointer" : ""}`}
                    data-testid={`drive-file-row-${file.id}`}
                    onClick={() => {
                      if (isFolder) {
                        navigateToFolder(file.id, file.name);
                      }
                    }}
                  >
                    {/* Checkbox for files only */}
                    {!isFolder ? (
                      <Checkbox
                        checked={isSelected}
                        onCheckedChange={() => toggleFileSelection(file.id)}
                        onClick={(e) => e.stopPropagation()}
                        data-testid={`drive-select-${file.id}`}
                      />
                    ) : (
                      <div className="w-4" />
                    )}

                    {driveFileIcon(file.mimeType)}

                    <span className="flex-1 truncate" data-testid="drive-file-name">
                      {file.name}
                    </span>

                    <span className="text-xs text-muted-foreground hidden sm:block w-20 text-right">
                      {!isFolder && formatSize(file.size)}
                    </span>

                    <span className="text-xs text-muted-foreground hidden sm:block w-24 text-right">
                      {formatDate(file.modifiedTime)}
                    </span>

                    {isFolder && (
                      <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </ScrollArea>

        <DialogFooter className="gap-2 sm:gap-0">
          <Button
            variant="outline"
            onClick={() => onOpenChange(false)}
            disabled={importing}
          >
            Cancel
          </Button>
          <Button
            onClick={handleImport}
            disabled={selectedCount === 0 || importing}
            data-testid="drive-import-button"
          >
            {importing ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Importing...
              </>
            ) : (
              `Import${selectedCount > 0 ? ` (${selectedCount})` : ""}`
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
