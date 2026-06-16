import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Download, Paperclip, Trash2, Upload } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ApiError } from "@/api/client";
import { useAuthStore } from "@/stores/authStore";
import { getRoleFromAccessToken } from "@/lib/adminCapabilities";
import {
  deleteTicketAttachment,
  getTicketAttachmentDownloadUrl,
  listTicketAttachments,
  uploadTicketAttachment,
  type TicketAttachmentOut,
} from "@/api/endpoints/ticketAttachments";

function formatBytes(bytes: number): string {
  if (!bytes || bytes < 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let v = bytes;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${i === 0 ? v : v.toFixed(1)} ${units[i]}`;
}

function fmtDate(ts?: number | null): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString();
}

function isDisabled(err: unknown): boolean {
  return err instanceof ApiError && err.status === 404;
}

export function TicketAttachmentsPanel({ ticketId }: { ticketId: string }) {
  const qc = useQueryClient();
  const fileInputRef = useRef<HTMLInputElement>(null);
  const [uploading, setUploading] = useState(false);

  const token = useAuthStore((s) => s.accessToken);
  const currentUserSub = useAuthStore((s) => s.userId);
  const role = getRoleFromAccessToken(token);
  const isAdmin = role === "admin" || role === "root";

  const attachmentsQuery = useQuery({
    queryKey: ["ticket-attachments", ticketId],
    queryFn: () => listTicketAttachments(ticketId),
    enabled: !!ticketId,
    retry: (count, err) => !isDisabled(err) && count < 2,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ["ticket-attachments", ticketId] });

  const uploadMut = useMutation({
    mutationFn: (file: File) => uploadTicketAttachment(ticketId, file),
    onMutate: () => setUploading(true),
    onSuccess: () => {
      toast.success("Attachment uploaded");
      invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to upload attachment"),
    onSettled: () => {
      setUploading(false);
      if (fileInputRef.current) fileInputRef.current.value = "";
    },
  });

  const deleteMut = useMutation({
    mutationFn: (attachmentId: string) => deleteTicketAttachment(ticketId, attachmentId),
    onSuccess: () => {
      toast.success("Attachment deleted");
      invalidate();
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to delete attachment"),
  });

  const downloadMut = useMutation({
    mutationFn: (attachmentId: string) =>
      getTicketAttachmentDownloadUrl(ticketId, attachmentId),
    onSuccess: (res) => {
      window.open(res.download_url, "_blank", "noopener,noreferrer");
    },
    onError: (err: unknown) =>
      toast.error(err instanceof ApiError ? err.detail : "Failed to get download link"),
  });

  // Feature off — hide entirely.
  if (isDisabled(attachmentsQuery.error)) return null;

  const attachments: TicketAttachmentOut[] = attachmentsQuery.data?.attachments ?? [];

  const canDelete = (a: TicketAttachmentOut) =>
    isAdmin || (!!currentUserSub && a.uploaded_by === currentUserSub);

  return (
    <Card>
      <CardHeader className="flex flex-row items-start justify-between gap-2 space-y-0">
        <div>
          <CardTitle className="flex items-center gap-2 text-base">
            <Paperclip className="h-4 w-4" /> Attachments
          </CardTitle>
          <CardDescription>Files attached to this ticket.</CardDescription>
        </div>
        <div>
          <input
            ref={fileInputRef}
            type="file"
            className="hidden"
            onChange={(e) => {
              const file = e.target.files?.[0];
              if (file) uploadMut.mutate(file);
            }}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={uploading}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="mr-1 h-4 w-4" />
            {uploading ? "Uploading…" : "Upload"}
          </Button>
        </div>
      </CardHeader>
      <CardContent>
        {attachmentsQuery.isLoading ? (
          <Skeleton className="h-16 w-full" />
        ) : attachments.length === 0 ? (
          <p className="text-sm text-muted-foreground">No attachments yet.</p>
        ) : (
          <ul className="space-y-2">
            {attachments.map((a) => (
              <li
                key={a.attachment_id}
                className="flex items-center justify-between gap-2 rounded-md border p-2"
              >
                <div className="min-w-0">
                  <div className="truncate text-sm font-medium">{a.filename}</div>
                  <div className="text-xs text-muted-foreground">
                    {formatBytes(a.size_bytes)} · {fmtDate(a.created_at)}
                  </div>
                </div>
                <div className="flex shrink-0 items-center gap-1">
                  <Button
                    size="sm"
                    variant="ghost"
                    disabled={downloadMut.isPending}
                    onClick={() => downloadMut.mutate(a.attachment_id)}
                  >
                    <Download className="mr-1 h-3.5 w-3.5" />
                    Download
                  </Button>
                  {canDelete(a) && (
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-7 w-7 text-destructive"
                      title="Delete attachment"
                      disabled={deleteMut.isPending}
                      onClick={() => deleteMut.mutate(a.attachment_id)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
