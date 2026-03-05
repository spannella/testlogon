import * as React from "react";

interface JumpToTimelineOptions {
  messageId: string;
  hasNextPage: () => boolean;
  fetchNextPage: () => Promise<unknown>;
  setHighlightMessageId: React.Dispatch<React.SetStateAction<string | null>>;
  clearJumpTarget: () => void;
  onMissingMessage?: (messageId: string) => void;
  maxAttempts?: number;
}

export async function jumpToMessageInTimeline({
  messageId,
  hasNextPage,
  fetchNextPage,
  setHighlightMessageId,
  clearJumpTarget,
  onMissingMessage,
  maxAttempts = 10,
}: JumpToTimelineOptions): Promise<boolean> {
  let attempts = 0;
  while (true) {
    const el = document.getElementById(`msg-${messageId}`);
    if (el) {
      el.scrollIntoView({ behavior: "smooth", block: "center" });
      setHighlightMessageId(messageId);
      window.setTimeout(() => {
        setHighlightMessageId((current) => (current === messageId ? null : current));
      }, 2000);
      clearJumpTarget();
      return true;
    }

    if (!hasNextPage() || attempts >= maxAttempts) {
      clearJumpTarget();
      onMissingMessage?.(messageId);
      return false;
    }

    attempts += 1;
    await fetchNextPage();
  }
}

interface UseMessageJumpParams {
  hasNextPage: boolean;
  fetchNextPage: () => Promise<unknown>;
  onMissingMessage?: (messageId: string) => void;
}

export function useMessageJump({ hasNextPage, fetchNextPage, onMissingMessage }: UseMessageJumpParams) {
  const [jumpTargetMessageId, setJumpTargetMessageId] = React.useState<string | null>(null);
  const [highlightMessageId, setHighlightMessageId] = React.useState<string | null>(null);

  React.useEffect(() => {
    if (!jumpTargetMessageId) return;

    let cancelled = false;
    const run = async () => {
      await jumpToMessageInTimeline({
        messageId: jumpTargetMessageId,
        hasNextPage: () => hasNextPage,
        fetchNextPage,
        setHighlightMessageId,
        clearJumpTarget: () => {
          if (!cancelled) setJumpTargetMessageId(null);
        },
        onMissingMessage,
      });
    };

    void run();
    return () => {
      cancelled = true;
    };
  }, [jumpTargetMessageId, hasNextPage, fetchNextPage, onMissingMessage]);

  return {
    jumpToMessage: setJumpTargetMessageId,
    highlightMessageId,
  };
}
