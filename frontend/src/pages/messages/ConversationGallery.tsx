import * as React from "react";
import { Download, ExternalLink } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import type { ConversationGalleryItem, MessageGalleryType } from "@/api/types";
import { useConversationGallery } from "@/hooks/useConversationGallery";

const TAB_ORDER: MessageGalleryType[] = ["image", "video", "file", "link"];

function tabLabel(type: MessageGalleryType): string {
  if (type === "image") return "Images";
  if (type === "video") return "Videos";
  if (type === "file") return "Files";
  return "Links";
}

function formatTimestamp(ts: number): string {
  return new Date(ts * 1000).toLocaleString();
}

function ItemFooter({ item, onJump }: { item: ConversationGalleryItem; onJump: (messageId: string) => void }) {
  return (
    <div className="mt-2 flex items-center justify-between gap-2">
      <p className="text-xs text-muted-foreground">Sent by {item.sender_id} • {formatTimestamp(item.created_at)}</p>
      <div className="flex items-center gap-1">
        <a href={item.url} target="_blank" rel="noreferrer" className="inline-flex">
          <Button size="sm" variant="outline" className="h-7 px-2 text-xs">
            <ExternalLink className="mr-1 h-3.5 w-3.5" /> Open
          </Button>
        </a>
        {item.type === "file" && (
          <a href={item.url} download className="inline-flex">
            <Button size="sm" variant="outline" className="h-7 px-2 text-xs">
              <Download className="mr-1 h-3.5 w-3.5" /> Download
            </Button>
          </a>
        )}
        <Button size="sm" variant="outline" className="h-7 px-2 text-xs" onClick={() => onJump(item.message_id)}>
          Jump to message
        </Button>
      </div>
    </div>
  );
}

function BrokenMedia({ label, onRetry }: { label: string; onRetry: () => void }) {
  return (
    <div className="flex h-40 items-center justify-center rounded-md border border-dashed bg-muted/30 text-xs text-muted-foreground">
      {label} preview unavailable
      <div className="mt-2">
        <Button size="sm" variant="outline" onClick={onRetry}>Retry preview</Button>
      </div>
    </div>
  );
}

function ImageCard({ item, onJump }: { item: ConversationGalleryItem; onJump: (messageId: string) => void }) {
  const [broken, setBroken] = React.useState(false);
  const [retryToken, setRetryToken] = React.useState(0);
  return (
    <div className="rounded-md border p-3">
      {broken ? (
        <BrokenMedia label="Image" onRetry={() => { setBroken(false); setRetryToken((x) => x + 1); }} />
      ) : (
        <img
          src={`${item.url}${item.url.includes("?") ? "&" : "?"}retry=${retryToken}`}
          alt={item.title || item.file_name || "Shared image"}
          className="h-40 w-full rounded-md object-cover"
          onError={() => setBroken(true)}
        />
      )}
      <ItemFooter item={item} onJump={onJump} />
    </div>
  );
}

function VideoCard({ item, onJump }: { item: ConversationGalleryItem; onJump: (messageId: string) => void }) {
  const [broken, setBroken] = React.useState(false);
  const [retryToken, setRetryToken] = React.useState(0);
  return (
    <div className="rounded-md border p-3">
      {broken ? (
        <BrokenMedia label="Video" onRetry={() => { setBroken(false); setRetryToken((x) => x + 1); }} />
      ) : (
        <video
          controls
          poster={item.thumbnail_url}
          className="h-40 w-full rounded-md bg-black/70"
          onError={() => setBroken(true)}
        >
          <source src={`${item.url}${item.url.includes("?") ? "&" : "?"}retry=${retryToken}`} type={item.content_type || "video/mp4"} />
        </video>
      )}
      <p className="mt-2 truncate text-sm font-medium">{item.file_name || item.title || "Video"}</p>
      <ItemFooter item={item} onJump={onJump} />
    </div>
  );
}

function FileRow({ item, onJump }: { item: ConversationGalleryItem; onJump: (messageId: string) => void }) {
  return (
    <div className="rounded-md border p-3">
      <p className="truncate text-sm font-medium">{item.file_name || item.url}</p>
      <p className="text-xs text-muted-foreground">
        {item.content_type || "Unknown type"}
        {typeof item.size === "number" ? ` • ${item.size.toLocaleString()} bytes` : ""}
      </p>
      <ItemFooter item={item} onJump={onJump} />
    </div>
  );
}

function LinkRow({ item, onJump }: { item: ConversationGalleryItem; onJump: (messageId: string) => void }) {
  return (
    <div className="rounded-md border p-3">
      <p className="truncate text-sm font-medium">{item.title || item.url}</p>
      <p className="truncate text-xs text-muted-foreground">{item.url}</p>
      <ItemFooter item={item} onJump={onJump} />
    </div>
  );
}

function EmptyState({ type }: { type: MessageGalleryType }) {
  return (
    <div className="rounded-md border border-dashed p-6 text-center text-sm text-muted-foreground">
      No {tabLabel(type).toLowerCase()} yet in this conversation.
    </div>
  );
}

function ErrorState({ type, onRetry }: { type: MessageGalleryType; onRetry: () => void }) {
  return (
    <div className="space-y-3 rounded-md border border-destructive/30 p-4">
      <p className="text-sm text-destructive">
        Couldn&apos;t load {tabLabel(type).toLowerCase()} right now. Please try again.
      </p>
      <Button variant="outline" size="sm" onClick={onRetry}>Retry</Button>
    </div>
  );
}

function TabBody({ type, items, onJump }: { type: MessageGalleryType; items: ConversationGalleryItem[]; onJump: (messageId: string) => void }) {
  if (type === "image") {
    return <div className="grid grid-cols-1 gap-2 md:grid-cols-2">{items.map((item) => <ImageCard key={item.message_id} item={item} onJump={onJump} />)}</div>;
  }
  if (type === "video") {
    return <div className="grid grid-cols-1 gap-2 md:grid-cols-2">{items.map((item) => <VideoCard key={item.message_id} item={item} onJump={onJump} />)}</div>;
  }
  if (type === "file") {
    return <div className="space-y-2">{items.map((item) => <FileRow key={item.message_id} item={item} onJump={onJump} />)}</div>;
  }
  return <div className="space-y-2">{items.map((item) => <LinkRow key={item.message_id} item={item} onJump={onJump} />)}</div>;
}

export function ConversationGallery({
  open,
  onOpenChange,
  conversationId,
  onJumpToMessage,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  conversationId: string;
  onJumpToMessage: (messageId: string) => void;
}) {
  const [activeTab, setActiveTab] = React.useState<MessageGalleryType>("image");

  const galleryQuery = useConversationGallery(conversationId, activeTab, open);

  const items = (galleryQuery.data?.pages ?? []).flatMap((page) => page.items ?? []);
  const isLoading = galleryQuery.isLoading && items.length === 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle>Media & Links</DialogTitle>
          <DialogDescription>
            Browse shared images, videos, files, and links from this conversation.
          </DialogDescription>
        </DialogHeader>

        <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as MessageGalleryType)}>
          <TabsList className="grid w-full grid-cols-4">
            {TAB_ORDER.map((type) => (
              <TabsTrigger key={type} value={type}>
                {tabLabel(type)}
              </TabsTrigger>
            ))}
          </TabsList>

          {TAB_ORDER.map((type) => (
            <TabsContent key={type} value={type} className="mt-4 max-h-[460px] overflow-y-auto space-y-2">
              {isLoading ? (
                <p className="text-sm text-muted-foreground">Loading {tabLabel(type).toLowerCase()}...</p>
              ) : galleryQuery.isError ? (
                <ErrorState type={type} onRetry={() => void galleryQuery.refetch()} />
              ) : items.length === 0 ? (
                <EmptyState type={type} />
              ) : (
                <>
                  <TabBody type={type} items={items} onJump={onJumpToMessage} />
                  {galleryQuery.hasNextPage && (
                    <div className="pt-2 text-center">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => galleryQuery.fetchNextPage()}
                        disabled={galleryQuery.isFetchingNextPage}
                      >
                        {galleryQuery.isFetchingNextPage ? "Loading..." : "Load more"}
                      </Button>
                    </div>
                  )}
                </>
              )}
            </TabsContent>
          ))}
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}
