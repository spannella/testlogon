import { useState } from "react";
import { Lock, Unlock } from "lucide-react";
import { Button } from "@/components/ui/button";
import { unlockChatMessage } from "@/api/endpoints/broadcast-chat";

interface ChatLockedCardProps {
  sessionId: string;
  messageId: string;
  lockPriceCents: number;
  lockDescription?: string | null;
  isUnlocked: boolean;
  text?: string | null;
  onUnlocked?: (text: string) => void;
}

export function ChatLockedCard({
  sessionId,
  messageId,
  lockPriceCents,
  lockDescription,
  isUnlocked,
  text,
  onUnlocked,
}: ChatLockedCardProps) {
  const [unlocking, setUnlocking] = useState(false);
  const [localUnlocked, setLocalUnlocked] = useState(isUnlocked);
  const [revealedText, setRevealedText] = useState(text);

  const price = (lockPriceCents / 100).toFixed(2);

  const handleUnlock = async () => {
    setUnlocking(true);
    try {
      // Use a test PM for now -- in production this would open a PM selector dialog
      const result = await unlockChatMessage(sessionId, messageId, "pm_test");
      setLocalUnlocked(true);
      setRevealedText(result.text);
      onUnlocked?.(result.text);
    } catch {
      // Ignore
    } finally {
      setUnlocking(false);
    }
  };

  if (localUnlocked) {
    return (
      <div className="flex items-start gap-1" data-testid="chat-locked-card">
        <Unlock className="h-3 w-3 text-green-500 shrink-0 mt-0.5" />
        <span className="text-xs text-foreground break-words">
          {revealedText || text}
        </span>
      </div>
    );
  }

  return (
    <div
      className="flex flex-col gap-1 p-1.5 rounded bg-muted/60 border border-border"
      data-testid="chat-locked-card"
    >
      <div className="flex items-center gap-1">
        <Lock className="h-3 w-3 text-muted-foreground" />
        <span className="text-xs text-muted-foreground">
          {lockDescription || "Locked message"}
        </span>
      </div>
      <Button
        size="sm"
        variant="outline"
        className="h-6 text-[10px] w-fit"
        onClick={handleUnlock}
        disabled={unlocking}
        data-testid="chat-unlock-btn"
      >
        Unlock for ${price}
      </Button>
    </div>
  );
}
