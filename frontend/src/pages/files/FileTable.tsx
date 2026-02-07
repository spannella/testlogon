import { File, Folder, MoreHorizontal, Download, Share2, Pencil, Move, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { DataTable, type ColumnDef, type SortState } from "@/components/shared/DataTable";
import type { FileEntry } from "@/api/types";
import { downloadUrl } from "@/api/endpoints/files";
import { cn } from "@/lib/utils";

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

// ─── Types ───────────────────────────────────────────────────────

interface FileTableProps {
  data: FileEntry[];
  sort?: SortState;
  onSort?: (sort: SortState) => void;
  selectedKeys: Set<string>;
  onSelectionChange: (keys: Set<string>) => void;
  onNavigate: (folder: FileEntry) => void;
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
            {row.type === "file" && (
              <DropdownMenuItem asChild>
                <a href={downloadUrl(row.path)} download>
                  <Download className="h-4 w-4" />
                  Download
                </a>
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
        if (row.type === "folder") onNavigate(row);
      }}
      hasMore={hasMore}
      onLoadMore={onLoadMore}
      loadingMore={loadingMore}
      emptyState={emptyState}
    />
  );
}
