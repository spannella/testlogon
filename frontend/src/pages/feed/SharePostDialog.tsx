import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useNavigate } from "react-router-dom";
import { toast } from "sonner";
import { Search, Share2 } from "lucide-react";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";
import { getConversations, sendTextMessage } from "@/api/endpoints/messaging";
import type { Conversation, FeedPost } from "@/api/types";

interface SharePostDialogProps {
  open: boolean;
  onClose: () => void;
  post: FeedPost;
}

export function SharePostDialog({ open, onClose, post }: SharePostDialogProps) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [selectedId, setSelectedId] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["conversations"],
    queryFn: () => getConversations(),
    enabled: open,
  });

  const conversations = data?.conversations ?? [];

  const filtered = useMemo(() => {
    if (!search.trim()) return conversations;
    const q = search.toLowerCase();
    return conversations.filter((c: Conversation) => {
      const name = c.title ?? c.participants.map((p) => p.display_name ?? p.user_id).join(", ");
      return name.toLowerCase().includes(q);
    });
  }, [conversations, search]);

  const shareMutation = useMutation({
    mutationFn: (targetId: string) =>
      sendTextMessage(targetId, {
        preview: {
          url: `/posts/${post.post_id}`,
          title: post.body.slice(0, 120),
          image_url: post.image_urls?.[0],
          site_name: "Post",
        },
      }),
    onSuccess: () => {
      toast.success("Post shared");
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
      onClose();
      setSelectedId(null);
      setSearch("");
      navigate("/messages");
    },
    onError: () => toast.error("Failed to share post"),
  });

  const handleShare = () => {
    if (selectedId) shareMutation.mutate(selectedId);
  };

  const handleOpenChange = (open: boolean) => {
    if (!open) {
      onClose();
      setSelectedId(null);
      setSearch("");
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Share2 className="h-4 w-4" /> Share Post
          </DialogTitle>
        </DialogHeader>

        {/* Post preview */}
        <div className="rounded-lg bg-muted p-3">
          <p className="text-sm line-clamp-2">
            {post.body || "[No text]"}
          </p>
          {post.image_urls && post.image_urls.length > 0 && (
            <p className="mt-1 text-xs text-muted-foreground">
              {post.image_urls.length} image{post.image_urls.length > 1 ? "s" : ""}
            </p>
          )}
        </div>

        {/* Search */}
        <div className="relative">
          <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
          <Input
            placeholder="Search conversations..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>

        {/* Conversation list */}
        <div className="max-h-48 overflow-y-auto rounded-lg border">
          {filtered.length === 0 ? (
            <p className="p-3 text-center text-sm text-muted-foreground">No conversations</p>
          ) : (
            filtered.map((convo: Conversation) => {
              const name = convo.title ?? convo.participants.map((p) => p.display_name ?? p.user_id).join(", ");
              const selected = convo.conversation_id === selectedId;
              return (
                <button
                  key={convo.conversation_id}
                  type="button"
                  className={cn(
                    "flex w-full items-center gap-2 border-b border-border/50 px-3 py-2 text-left text-sm transition-colors last:border-b-0",
                    selected ? "bg-primary/10 font-medium" : "hover:bg-accent",
                  )}
                  onClick={() => setSelectedId(convo.conversation_id)}
                >
                  <div className="flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-muted text-xs font-medium">
                    {name.slice(0, 2).toUpperCase()}
                  </div>
                  <span className="truncate">{name || "Conversation"}</span>
                </button>
              );
            })
          )}
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            Cancel
          </Button>
          <Button
            onClick={handleShare}
            disabled={!selectedId || shareMutation.isPending}
          >
            {shareMutation.isPending ? "Sharing..." : "Share"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
