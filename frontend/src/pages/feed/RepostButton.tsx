import { useState } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Repeat2 } from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { repostPost, undoRepost } from "@/api/endpoints/newsfeed";

interface RepostButtonProps {
  postId: string;
  authorId: string;
  repostCount: number;
  repostedByMe: boolean;
  isLocked?: boolean;
  isOwn?: boolean;
}

export function RepostButton({
  postId,
  authorId: _authorId,
  repostCount,
  repostedByMe,
  isLocked,
  isOwn,
}: RepostButtonProps) {
  const queryClient = useQueryClient();
  const [popoverOpen, setPopoverOpen] = useState(false);
  const [quoteMode, setQuoteMode] = useState(false);
  const [quoteText, setQuoteText] = useState("");

  const repostMut = useMutation({
    mutationFn: (quote?: string) => repostPost(postId, quote ? { quote } : undefined),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success("Reposted");
      setPopoverOpen(false);
      setQuoteMode(false);
      setQuoteText("");
    },
    onError: () => {
      toast.error("Failed to repost");
    },
  });

  const undoMut = useMutation({
    mutationFn: () => undoRepost(postId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["feed"] });
      toast.success("Repost removed");
      setPopoverOpen(false);
    },
    onError: () => {
      toast.error("Failed to undo repost");
    },
  });

  const disabled = isOwn || isLocked;
  const title = isOwn
    ? "Cannot repost your own post"
    : isLocked
      ? "Cannot repost locked content"
      : repostedByMe
        ? "Undo repost"
        : "Repost";

  const handleSimpleRepost = () => {
    repostMut.mutate(undefined);
  };

  const handleQuoteRepost = () => {
    repostMut.mutate(quoteText.trim() || undefined);
  };

  if (disabled) {
    return (
      <button
        className="flex items-center gap-1 text-sm text-muted-foreground/50 cursor-not-allowed"
        disabled
        title={title}
        aria-label={title}
      >
        <Repeat2 className="h-4 w-4" />
        <span>{repostCount}</span>
      </button>
    );
  }

  return (
    <Popover open={popoverOpen} onOpenChange={setPopoverOpen}>
      <PopoverTrigger asChild>
        <button
          className={cn(
            "flex items-center gap-1 text-sm transition-colors",
            repostedByMe
              ? "text-green-600"
              : "text-muted-foreground hover:text-green-600",
          )}
          aria-label={title}
          data-testid="repost-button"
        >
          <Repeat2
            className={cn("h-4 w-4", repostedByMe && "fill-green-600")}
          />
          <span>{repostCount}</span>
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-64 p-2" align="start">
        {repostedByMe ? (
          <Button
            variant="ghost"
            className="w-full justify-start text-red-500 hover:text-red-600"
            onClick={() => undoMut.mutate()}
            disabled={undoMut.isPending}
          >
            <Repeat2 className="mr-2 h-4 w-4" />
            Undo Repost
          </Button>
        ) : quoteMode ? (
          <div className="space-y-2">
            <Textarea
              placeholder="Add a comment (optional)..."
              value={quoteText}
              onChange={(e) => setQuoteText(e.target.value)}
              maxLength={500}
              className="min-h-[80px] text-sm"
              autoFocus
            />
            <div className="flex justify-between items-center">
              <span className="text-xs text-muted-foreground">
                {quoteText.length}/500
              </span>
              <div className="flex gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => {
                    setQuoteMode(false);
                    setQuoteText("");
                  }}
                >
                  Cancel
                </Button>
                <Button
                  size="sm"
                  onClick={handleQuoteRepost}
                  disabled={repostMut.isPending}
                >
                  {repostMut.isPending ? "Posting..." : "Repost"}
                </Button>
              </div>
            </div>
          </div>
        ) : (
          <>
            <Button
              variant="ghost"
              className="w-full justify-start"
              onClick={handleSimpleRepost}
              disabled={repostMut.isPending}
            >
              <Repeat2 className="mr-2 h-4 w-4" />
              Repost
            </Button>
            <Button
              variant="ghost"
              className="w-full justify-start"
              onClick={() => setQuoteMode(true)}
            >
              <Repeat2 className="mr-2 h-4 w-4" />
              Quote Repost
            </Button>
          </>
        )}
      </PopoverContent>
    </Popover>
  );
}
