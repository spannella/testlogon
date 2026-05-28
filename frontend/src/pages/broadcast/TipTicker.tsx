import { useEffect, useRef, useState } from "react";
import { DollarSign } from "lucide-react";

interface TipEvent {
  sender_display_name: string;
  amount_cents: number;
  message_id: string;
  text?: string;
}

interface TipTickerProps {
  sessionId: string;
  /** Feed recent tips from SSE or polling */
  tips: TipEvent[];
  maxVisible?: number;
}

export function TipTicker({ tips, maxVisible = 5 }: TipTickerProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const [visibleTips, setVisibleTips] = useState<TipEvent[]>([]);

  useEffect(() => {
    setVisibleTips((prev) => {
      const merged = [...tips.filter((t) => !prev.some((p) => p.message_id === t.message_id)), ...prev];
      return merged.slice(0, maxVisible);
    });
  }, [tips, maxVisible]);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [visibleTips]);

  if (visibleTips.length === 0) return null;

  return (
    <div
      ref={containerRef}
      className="absolute top-2 right-2 z-10 space-y-1 max-h-[200px] overflow-hidden pointer-events-none"
      data-testid="tip-ticker"
    >
      {visibleTips.map((tip) => (
        <div
          key={tip.message_id}
          className="flex items-center gap-1.5 bg-yellow-400/90 text-yellow-900 rounded-full px-3 py-1 text-xs font-semibold shadow animate-in slide-in-from-right-5 fade-in duration-300"
        >
          <DollarSign className="h-3 w-3" />
          <span className="truncate max-w-[120px]">{tip.sender_display_name}</span>
          <span>${(tip.amount_cents / 100).toFixed(2)}</span>
        </div>
      ))}
    </div>
  );
}
