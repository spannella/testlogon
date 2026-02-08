import { useState, useMemo } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";
import { Search, Forward } from "lucide-react";
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
import { getConversations, forwardMessage } from "@/api/endpoints/messaging";
import type { Conversation, Message } from "@/api/types";

interface ForwardDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  message: Message;
  sourceConversationId: string;
}

export function ForwardDialog({
  open,
  onOpenChange,
  message,
  sourceConversationId,
}: ForwardDialogProps) {
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
    return conversations.filter((c) => {
      const name = c.title ?? c.participants.map((p) => p.display_name ?? p.user_id).join(", ");
      return name.toLowerCase().includes(q);
    });
  }, [conversations, search]);

  const fwdMutation = useMutation({
    mutationFn: (targetId: string) =>
      forwardMessage(targetId, {
        source_conversation_id: sourceConversationId,
        source_message_id: message.message_id,
      }),
    onSuccess: () => {
      toast.success("Message forwarded");
      void queryClient.invalidateQueries({ queryKey: ["conversations"] });
      onOpenChange(false);
      setSelectedId(null);
      setSearch("");
    },
    onError: () => toast.error("Failed to forward message"),
  });

  const handleForward = () => {
    if (selectedId) fwdMutation.mutate(selectedId);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Forward className="h-4 w-4" /> Forward Message
          </DialogTitle>
        </DialogHeader>

        {/* Message preview */}
        <div className="rounded-lg bg-muted p-3">
          <p className="text-xs text-muted-foreground">From: {message.sender_id}</p>
          <p className="mt-1 text-sm">
            {message.body
              ? (message.body.length > 100 ? message.body.slice(0, 100) + "..." : message.body)
              : `[${message.kind}]`}
          </p>
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
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Cancel
          </Button>
          <Button
            onClick={handleForward}
            disabled={!selectedId || fwdMutation.isPending}
          >
            {fwdMutation.isPending ? "Forwarding..." : "Forward"}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
