import { useEffect, useRef, useState } from "react";
import { Lock, Sparkles } from "lucide-react";
import { cn } from "@/lib/utils";
import {
  isRevealable,
  revealCountdownLabel,
  secondsUntilReveal,
} from "@/lib/revealAt";

export interface RevealLockedCardProps {
  /** Reveal instant, epoch seconds. */
  revealAt: number;
  /** Invoked once when the local tick reaches the reveal time (used to
   *  invalidate the messages query so the server-projected content lands). */
  onReveal?: () => void;
  /** The real message content, rendered after the reveal fires. */
  children: React.ReactNode;
}

const nowSec = () => Math.floor(Date.now() / 1000);

/**
 * FE-120: the recipient-facing placeholder for a scheduled "drop".
 *
 * While locked it shows a blurred/obscured card (lock icon + "Scheduled
 * reveal") with a live 1s countdown. When the tick reaches `revealAt` it
 * fires `onReveal` and transitions (fade/scale) to render the actual content.
 */
export function RevealLockedCard({ revealAt, onReveal, children }: RevealLockedCardProps) {
  const [now, setNow] = useState<number>(() => nowSec());
  const [revealed, setRevealed] = useState<boolean>(() => isRevealable(revealAt, nowSec()));
  const [reducedMotion, setReducedMotion] = useState(false);
  const firedRef = useRef(false);

  useEffect(() => {
    const media = window.matchMedia("(prefers-reduced-motion: reduce)");
    const sync = () => setReducedMotion(media.matches);
    sync();
    media.addEventListener("change", sync);
    return () => media.removeEventListener("change", sync);
  }, []);

  // Fire onReveal at most once, whenever the reveal condition first holds.
  const fireReveal = () => {
    if (firedRef.current) return;
    firedRef.current = true;
    onReveal?.();
  };

  useEffect(() => {
    // Already past the reveal time on mount.
    if (isRevealable(revealAt, nowSec())) {
      setRevealed(true);
      fireReveal();
      return;
    }
    const id = window.setInterval(() => {
      const t = nowSec();
      setNow(t);
      if (isRevealable(revealAt, t)) {
        setRevealed(true);
        fireReveal();
        window.clearInterval(id);
      }
    }, 1000);
    return () => window.clearInterval(id);
    // revealAt is stable per message; onReveal captured via ref-guard.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [revealAt]);

  if (revealed) {
    return (
      <div
        data-testid="reveal-revealed"
        className={cn(!reducedMotion && "motion-safe:animate-in motion-safe:fade-in-0 motion-safe:zoom-in-95 motion-safe:duration-500")}
      >
        {children}
      </div>
    );
  }

  const remaining = secondsUntilReveal(revealAt, now);
  const label = revealCountdownLabel(revealAt, now);

  return (
    <div
      data-testid="reveal-locked-card"
      className="relative w-64 max-w-full overflow-hidden rounded-lg border border-indigo-300/70 bg-gradient-to-br from-indigo-50 to-purple-50 px-3 py-3"
    >
      {/* Blurred / obscured decorative fill standing in for hidden content */}
      <div
        aria-hidden
        className="pointer-events-none absolute inset-0 opacity-40"
        style={{ filter: "blur(6px)" }}
      >
        <div className="mt-6 space-y-2 px-4">
          <div className="h-3 w-3/4 rounded bg-indigo-300/60" />
          <div className="h-3 w-1/2 rounded bg-purple-300/60" />
          <div className="h-3 w-2/3 rounded bg-indigo-300/50" />
        </div>
      </div>

      <div className="relative flex flex-col items-center gap-1.5 text-center">
        <div className="inline-flex items-center gap-1.5 rounded-full bg-indigo-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-800">
          <Lock className="h-3 w-3" />
          Scheduled reveal
        </div>
        <div
          data-testid="reveal-countdown"
          className="mt-1 font-mono text-lg font-bold tracking-wider text-indigo-900"
        >
          {label}
        </div>
        <p className="flex items-center gap-1 text-[11px] text-indigo-700/80">
          <Sparkles className="h-3 w-3" />
          {remaining > 0
            ? "Content unlocks automatically"
            : "Revealing…"}
        </p>
      </div>
    </div>
  );
}

export default RevealLockedCard;
