import { useQuery } from "@tanstack/react-query";
import { Sheet, SheetContent, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { Skeleton } from "@/components/ui/skeleton";
import { getViewers } from "@/api/endpoints/messaging";
import type { Message } from "@/api/types";

interface MessageDetailsSheetProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  message: Message;
  conversationId: string;
}

function formatTs(ts: number | undefined): string {
  if (!ts) return "—";
  return new Date(ts * 1000).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "numeric",
    minute: "2-digit",
    timeZoneName: "short",
  });
}

function formatBytes(bytes: number | undefined): string {
  if (!bytes) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
}

export function MessageDetailsSheet({
  open,
  onOpenChange,
  message,
  conversationId,
}: MessageDetailsSheetProps) {
  const isOptimistic = message.message_id.startsWith("optimistic-");

  const { data: viewers, isLoading } = useQuery({
    queryKey: ["message-views", conversationId, message.message_id],
    queryFn: () => getViewers(conversationId, message.message_id),
    enabled: open && !isOptimistic,
    staleTime: 30_000,
  });

  const imageDetails = message.kind === "image" ? message.image : null;
  const fileDetails = message.kind === "file" || message.kind === "audio" || message.kind === "video"
    ? message.file
    : null;

  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent side="right" className="w-80 overflow-y-auto sm:w-96">
        <SheetHeader>
          <SheetTitle>Message Details</SheetTitle>
        </SheetHeader>

        <div className="mt-6 space-y-6">
          {/* Sent time */}
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Sent</p>
            <p className="text-sm">{formatTs(message.created_at)}</p>
          </div>

          {/* Image details */}
          {imageDetails && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Image Info</p>
              <div className="space-y-1 text-sm">
                {(imageDetails as { filename?: string }).filename && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">Filename</span>
                    <span className="max-w-[60%] truncate text-right">{(imageDetails as { filename?: string }).filename}</span>
                  </div>
                )}
                {imageDetails.width && imageDetails.height && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">Dimensions</span>
                    <span>{imageDetails.width} × {imageDetails.height} px</span>
                  </div>
                )}
                {(imageDetails as { filesize?: number }).filesize && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">File size</span>
                    <span>{formatBytes((imageDetails as { filesize?: number }).filesize)}</span>
                  </div>
                )}
                {imageDetails.content_type && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">Type</span>
                    <span>{imageDetails.content_type}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* File/audio/video details */}
          {fileDetails && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">File Info</p>
              <div className="space-y-1 text-sm">
                {fileDetails.name && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">Filename</span>
                    <span className="max-w-[60%] truncate text-right">{fileDetails.name}</span>
                  </div>
                )}
                {fileDetails.size && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">File size</span>
                    <span>{formatBytes(fileDetails.size)}</span>
                  </div>
                )}
                {fileDetails.content_type && (
                  <div className="flex justify-between gap-2">
                    <span className="text-muted-foreground">Type</span>
                    <span>{fileDetails.content_type}</span>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Edited */}
          {(message.edited_at || message.edited) && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Last Edited</p>
              <p className="text-sm">{formatTs(message.edited_at)}</p>
            </div>
          )}

          {/* Expiry */}
          {message.expires_at && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Expires</p>
              <p className="text-sm">{formatTs(message.expires_at)}</p>
            </div>
          )}

          {/* Tip */}
          {message.tip_amount_cents && message.tip_amount_cents > 0 && (
            <div>
              <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Tip Received</p>
              <p className="text-sm">${(message.tip_amount_cents / 100).toFixed(2)} {message.tip_currency ?? "USD"}</p>
            </div>
          )}

          {/* Delivered to */}
          {message.delivered_to_user_ids && message.delivered_to_user_ids.length > 0 && (
            <div>
              <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
                Delivered to ({message.delivered_to_user_ids.length})
              </p>
              <div className="space-y-1.5">
                {message.delivered_to_user_ids.map((uid) => (
                  <div key={uid} className="flex items-center gap-2">
                    <Avatar className="h-6 w-6">
                      <AvatarFallback className="text-[9px]">{uid.slice(0, 2).toUpperCase()}</AvatarFallback>
                    </Avatar>
                    <span className="text-sm">{uid}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Read / Viewed by */}
          <div>
            <p className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">
              {message.kind === "image" ? "Viewed / Downloaded" : "Read"} by{" "}
              {viewers && viewers.length > 0 ? `(${viewers.length})` : ""}
            </p>
            {isOptimistic ? (
              <p className="text-xs text-muted-foreground">Message not yet delivered.</p>
            ) : isLoading ? (
              <div className="space-y-1.5">
                {[1, 2].map((i) => <Skeleton key={i} className="h-6 w-full" />)}
              </div>
            ) : !viewers || viewers.length === 0 ? (
              <p className="text-xs text-muted-foreground">Not yet read.</p>
            ) : (
              <div className="space-y-1.5">
                {viewers.map((v) => (
                  <div key={v.user_id} className="flex items-center justify-between gap-2">
                    <div className="flex items-center gap-2">
                      <Avatar className="h-6 w-6">
                        <AvatarFallback className="text-[9px]">{v.user_id.slice(0, 2).toUpperCase()}</AvatarFallback>
                      </Avatar>
                      <span className="text-sm">{v.user_id}</span>
                    </div>
                    <div className="text-right">
                      {v.last_viewed_at && (
                        <span className="block text-[11px] text-muted-foreground">{formatTs(v.last_viewed_at)}</span>
                      )}
                      {v.view_count > 1 && (
                        <span className="text-[11px] text-muted-foreground">{v.view_count}× viewed</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Message ID */}
          <div>
            <p className="mb-1 text-xs font-semibold uppercase tracking-wide text-muted-foreground">Message ID</p>
            <p className="break-all font-mono text-[11px] text-muted-foreground">{message.message_id}</p>
          </div>
        </div>
      </SheetContent>
    </Sheet>
  );
}
