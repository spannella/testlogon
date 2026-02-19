import { useQuery } from "@tanstack/react-query";
import { Download, Eye, FileText, FolderOpen, Lock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { DataTable, type ColumnDef } from "@/components/shared/DataTable";
import { EmptyState } from "@/components/shared/EmptyState";
import { getSharedWithMe } from "@/api/endpoints/files";
import type { SharedItem } from "@/api/types";
import { MediaPreviewThumb } from "./MediaPreviewThumb";

function nameFromPath(path: string): string {
  const segments = path.split("/").filter(Boolean);
  return segments.length > 0 ? (segments[segments.length - 1] ?? path) : path;
}

function isFolder(path: string): boolean {
  return path.endsWith("/");
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
}


interface SharedWithMeProps {
  onPreviewShared: (item: SharedItem) => void;
  onDownloadShared: (item: SharedItem) => void;
}

export function SharedWithMe({ onPreviewShared, onDownloadShared }: SharedWithMeProps) {
  const query = useQuery({
    queryKey: ["shared-with-me"],
    queryFn: getSharedWithMe,
  });

  const items = query.data?.items ?? [];

  const columns: ColumnDef<SharedItem>[] = [
    {
      id: "name",
      header: "Name",
      cell: (row) => (
        <div className="flex items-center gap-2">
          {isFolder(row.path) ? (
            <FolderOpen className="h-4 w-4 shrink-0 text-primary" />
          ) : row.preview_kind === "video" || row.preview_kind === "audio" ? (
            <MediaPreviewThumb item={row} />
          ) : (
            <FileText className="h-4 w-4 shrink-0 text-muted-foreground" />
          )}
          <span className="truncate text-sm">{row.name || nameFromPath(row.path)}</span>
          {row.is_encrypted && (
            <Badge variant="outline" className="ml-1 gap-1 text-[10px] uppercase tracking-wide">
              <Lock className="h-3 w-3" /> Encrypted
            </Badge>
          )}
        </div>
      ),
    },
    {
      id: "owner",
      header: "Shared By",
      cell: (row) => (
        <span className="text-sm text-muted-foreground">{row.owner}</span>
      ),
    },
    {
      id: "permission",
      header: "Permission",
      cell: (row) => (
        <Badge variant={row.permission === "write" ? "default" : "secondary"}>
          {row.permission}
        </Badge>
      ),
      className: "hidden sm:table-cell",
    },
    {
      id: "shared_at",
      header: "Shared",
      cell: (row) => (
        <span className="text-xs text-muted-foreground">{formatDate(row.shared_at)}</span>
      ),
      className: "hidden md:table-cell",
    },
    {
      id: "actions",
      header: "",
      cell: (row) => (
        <div className="flex items-center gap-1">
          {!isFolder(row.path) && (
            <>
              {!row.is_encrypted && (
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7"
                  onClick={(e) => {
                    e.stopPropagation();
                    onPreviewShared(row);
                  }}
                >
                  <Eye className="h-3.5 w-3.5" />
                </Button>
              )}
              <Button
                variant="ghost"
                size="icon"
                className="h-7 w-7"
                onClick={(e) => {
                  e.stopPropagation();
                  onDownloadShared(row);
                }}
              >
                <Download className="h-3.5 w-3.5" />
              </Button>
            </>
          )}
        </div>
      ),
      className: "w-20",
    },
  ];

  if (query.isLoading) {
    return (
      <div className="space-y-2">
        {Array.from({ length: 4 }).map((_, i) => (
          <Skeleton key={i} className="h-10 w-full" />
        ))}
      </div>
    );
  }

  return (
    <DataTable
      columns={columns}
      data={items}
      rowKey={(row) => `${row.owner}:${row.path}`}
      onRowClick={(row) => {
        if (!isFolder(row.path)) {
          if (row.is_encrypted) {
            onDownloadShared(row);
            return;
          }
          onPreviewShared(row);
        }
      }}
      emptyState={
        <EmptyState
          icon={<FolderOpen className="h-6 w-6" />}
          title="Nothing shared with you"
          description="Files and folders shared by others will appear here"
        />
      }
    />
  );
}
