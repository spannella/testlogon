import React from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Link2, Copy, Trash2, RefreshCw } from "lucide-react";

import { PageHeader } from "@/components/shared/PageHeader";
import { EmptyState } from "@/components/shared/EmptyState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { listShareLinks, revokeShareLink } from "@/api/endpoints/fileShareLinks";
import type { ShareLink } from "@/api/types";

function formatBytes(bytes?: number): string {
  if (!bytes || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i++;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${units[i]}`;
}

function fmtTs(ts: number): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

type FilterMode = "active" | "expired" | "revoked" | "all";

function statusOf(link: ShareLink): { label: string; mode: FilterMode } {
  const now = Math.floor(Date.now() / 1000);
  if (link.is_revoked) return { label: "Revoked", mode: "revoked" };
  if (now >= link.expires_at) return { label: "Expired", mode: "expired" };
  if (link.download_count >= link.max_downloads)
    return { label: "Used", mode: "expired" };
  return { label: "Active", mode: "active" };
}

export default function ShareLinksPage() {
  const qc = useQueryClient();
  const [filter, setFilter] = React.useState<FilterMode>("all");

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["share-links"],
    queryFn: listShareLinks,
  });

  const revokeMut = useMutation({
    mutationFn: (linkId: string) => revokeShareLink(linkId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["share-links"] });
      toast.success("Share link revoked");
    },
    onError: () => toast.error("Failed to revoke link"),
  });

  const links = data?.items ?? [];
  const filtered = links.filter((l) =>
    filter === "all" ? true : statusOf(l).mode === filter,
  );

  const copy = async (url: string) => {
    try {
      await navigator.clipboard.writeText(url);
      toast.success("Link copied");
    } catch {
      toast.error("Copy failed");
    }
  };

  return (
    <div className="space-y-4" data-testid="share-links-page">
      <PageHeader
        title="Share Links"
        description="Encrypted one-time download links for your files."
        actions={
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />

      <div className="flex gap-2">
        {(["all", "active", "expired", "revoked"] as FilterMode[]).map((m) => (
          <Button
            key={m}
            size="sm"
            variant={filter === m ? "default" : "outline"}
            className="rounded-full capitalize"
            onClick={() => setFilter(m)}
            data-testid={`share-links-filter-${m}`}
          >
            {m}
          </Button>
        ))}
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">Loading…</p>
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Link2 className="h-6 w-6" />}
          title="No share links"
          description="Create a share link from the file manager to share files externally."
        />
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>File</TableHead>
                <TableHead>Size</TableHead>
                <TableHead>Created</TableHead>
                <TableHead>Expires</TableHead>
                <TableHead>Downloads</TableHead>
                <TableHead>Status</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((link) => {
                const status = statusOf(link);
                return (
                  <TableRow key={link.link_id} data-testid="share-link-row">
                    <TableCell className="font-medium">
                      {link.file_name}
                      {link.has_password && (
                        <Badge variant="outline" className="ml-2">
                          Password
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell>{formatBytes(link.file_size_bytes)}</TableCell>
                    <TableCell>{fmtTs(link.created_at)}</TableCell>
                    <TableCell>{fmtTs(link.expires_at)}</TableCell>
                    <TableCell>
                      {link.download_count} / {link.max_downloads}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={status.label === "Active" ? "default" : "secondary"}
                      >
                        {status.label}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          aria-label="Copy link"
                          onClick={() => copy(link.share_url)}
                        >
                          <Copy className="h-4 w-4" />
                        </Button>
                        {!link.is_revoked && (
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label="Revoke link"
                            data-testid="share-link-revoke"
                            disabled={revokeMut.isPending}
                            onClick={() => revokeMut.mutate(link.link_id)}
                          >
                            <Trash2 className="h-4 w-4 text-destructive" />
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
