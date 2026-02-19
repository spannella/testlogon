import { useState } from "react";
import { File, Folder, MoreHorizontal, Download, Share2, Pencil, Move, Trash2, Eye, Image } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DataTable, type ColumnDef, type SortState } from "@/components/shared/DataTable";
import type { FileEntry } from "@/api/types";
import { downloadUrl, previewUrl } from "@/api/endpoints/files";
import { cn } from "@/lib/utils";
import { isEditableImageFile } from "./imageEdit";

// ─── Helpers ─────────────────────────────────────────────────────

function formatBytes(bytes?: number): string {
  if (bytes == null) return "—";
  if (bytes === 0) return "0 B";
  const k = 1024;
  const sizes = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + " " + sizes[i];
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
  });
}

function isImage(ct?: string): boolean {
  return !!ct && ct.startsWith("image/");
}

// ─── Thumbnail ──────────────────────────────────────────────────

function Thumbnail({ path }: { path: string }) {
  const [failed, setFailed] = useState(false);

  if (failed) {
    return <File className="h-4 w-4 shrink-0 text-muted-foreground" />;
  }

  return (
    <div className="relative h-8 w-8 shrink-0 overflow-hidden rounded">
      <Skeleton className="absolute inset-0" />
      <img
        src={previewUrl(path)}
        alt=""
        className="relative h-8 w-8 rounded object-cover"
        loading="lazy"
        onError={() => setFailed(true)}
      />
    </div>
  );
}

// ─── Types ───────────────────────────────────────────────────────

interface FileTableProps {
  data: FileEntry[];
  sort?: SortState;
  onSort?: (sort: SortState) => void;
  selectedKeys: Set<string>;
  onSelectionChange: (keys: Set<string>) => void;
  onNavigate: (folder: FileEntry) => void;
  onPreview?: (file: FileEntry) => void;
  onDownload?: (file: FileEntry) => void;
  onEditImage?: (file: FileEntry) => void;
  onShare: (file: FileEntry) => void;
  onRename: (file: FileEntry) => void;
  onMove: (file: FileEntry) => void;
  onDelete: (file: FileEntry) => void;
  hasMore?: boolean;
  onLoadMore?: () => void;
  loadingMore?: boolean;
  emptyState?: React.ReactNode;
}

// ─── FileTable Component ────────────────────────────────────────

export function FileTable({
  data,
  sort,
  onSort,
  selectedKeys,
  onSelectionChange,
  onNavigate,
  onPreview,
  onDownload,
  onEditImage,
  onShare,
  onRename,
  onMove,
  onDelete,
  hasMore,
  onLoadMore,
  loadingMore,
  emptyState,
}: FileTableProps) {
  const columns: ColumnDef<FileEntry>[] = [
    {
      id: "name",
      header: "Name",
      sortable: true,
      cell: (row) => (
        <div className="flex items-center gap-2">
          {row.type === "folder" ? (
            <Folder className="h-4 w-4 shrink-0 text-primary" />
          ) : isImage(row.content_type) && !row.is_encrypted ? (
            <Thumbnail path={row.path} />
          ) : (
            <File className="h-4 w-4 shrink-0 text-muted-foreground" />
          )}
          <span
            className={cn(
              "truncate text-sm",
              row.type === "folder" && "font-medium text-primary cursor-pointer hover:underline",
            )}
            onClick={(e) => {
              if (row.type === "folder") {
                e.stopPropagation();
                onNavigate(row);
              }
            }}
          >
            {row.name}
          </span>
        </div>
      ),
    },
    {
      id: "type",
      header: "Type",
      cell: (row) => (
        <span className="text-xs text-muted-foreground">
          {row.type === "folder" ? "Folder" : (row.content_type ?? "File")}
        </span>
      ),
    },
    {
      id: "size",
      header: "Size",
      sortable: true,
      cell: (row) => (
        <span className="text-xs text-muted-foreground">
          {row.type === "folder" ? "—" : formatBytes(row.size)}
        </span>
      ),
      className: "hidden sm:table-cell",
    },
    {
      id: "updated_at",
      header: "Modified",
      sortable: true,
      cell: (row) => (
        <span className="text-xs text-muted-foreground">{formatDate(row.updated_at)}</span>
      ),
      className: "hidden md:table-cell",
    },
    {
      id: "actions",
      header: "",
      cell: (row) => (
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button
              variant="ghost"
              size="icon"
              className="h-7 w-7"
              onClick={(e) => e.stopPropagation()}
            >
              <MoreHorizontal className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            {row.type === "file" && onPreview && !row.is_encrypted && (
              <DropdownMenuItem onClick={() => onPreview(row)}>
                <Eye className="h-4 w-4" />
                Preview
              </DropdownMenuItem>
            )}
            {row.type === "file" && (
              <DropdownMenuItem onClick={() => onDownload ? onDownload(row) : window.open(downloadUrl(row.path), "_blank")}>
                <Download className="h-4 w-4" />
                Download
              </DropdownMenuItem>
            )}
            {row.type === "file" && onEditImage && isEditableImageFile(row) && (
              <DropdownMenuItem onClick={() => onEditImage(row)}>
                <Image className="h-4 w-4" />
                Edit image
              </DropdownMenuItem>
            )}
            <DropdownMenuItem onClick={() => onShare(row)}>
              <Share2 className="h-4 w-4" />
              Share
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onRename(row)}>
              <Pencil className="h-4 w-4" />
              Rename
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onMove(row)}>
              <Move className="h-4 w-4" />
              Move
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => onDelete(row)}
              className="text-destructive focus:text-destructive"
            >
              <Trash2 className="h-4 w-4" />
              Delete
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      ),
      className: "w-10",
    },
  ];

  return (
    <DataTable
      columns={columns}
      data={data}
      rowKey={(row) => row.path}
      sort={sort}
      onSort={onSort}
      selectable
      selectedKeys={selectedKeys}
      onSelectionChange={onSelectionChange}
      onRowClick={(row) => {
        if (row.type === "folder") {
          onNavigate(row);
        } else if (onPreview && !row.is_encrypted) {
          onPreview(row);
        } else if (onDownload) {
          onDownload(row);
        }
      }}
      hasMore={hasMore}
      onLoadMore={onLoadMore}
      loadingMore={loadingMore}
      emptyState={emptyState}
    />
  );
}
