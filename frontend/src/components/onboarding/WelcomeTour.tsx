// First-run Welcome tour: a stepper Dialog that introduces the new trading /
// investing surfaces. Auto-shows ONCE on the first authenticated load (gated on
// the persisted `onboarding.v1` seen-set + auth), and can be re-triggered from
// Settings ("Replay welcome tour") via the `openWelcomeTour()` imperative.
//
// Additive: mounted in HomePage; renders nothing unless it should show.

import { useCallback, useEffect, useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowRight, Sparkles } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useAuthStore } from "@/stores/authStore";
import {
  WELCOME_TOUR_ID,
  tourSteps,
  useOnboarding,
  shouldShow,
} from "@/lib/onboarding";

/** Same-tab event used to imperatively (re-)open the tour from Settings. */
const OPEN_WELCOME_TOUR_EVENT = "tl:openWelcomeTour";

/** Imperatively open the welcome tour (used by the Settings "Replay" button). */
export function openWelcomeTour(): void {
  try {
    window.dispatchEvent(new Event(OPEN_WELCOME_TOUR_EVENT));
  } catch {
    /* SSR — no-op */
  }
}

export default function WelcomeTour() {
  const navigate = useNavigate();
  const isAuthenticated = useAuthStore((s) => s.isAuthenticated);
  const { seen, mark } = useOnboarding();
  const steps = useMemo(() => tourSteps(), []);

  const [open, setOpen] = useState(false);
  const [idx, setIdx] = useState(0);

  // Auto-show once, on the first authenticated load, if not already completed.
  useEffect(() => {
    if (isAuthenticated && shouldShow(WELCOME_TOUR_ID, seen)) {
      setIdx(0);
      setOpen(true);
    }
    // Only react to auth flipping true / the seen-set changing; we intentionally
    // do not reopen after the user dismisses within the same session.
  }, [isAuthenticated, seen]);

  // Imperative re-open (Settings "Replay welcome tour").
  useEffect(() => {
    const onOpen = () => {
      setIdx(0);
      setOpen(true);
    };
    window.addEventListener(OPEN_WELCOME_TOUR_EVENT, onOpen);
    return () => window.removeEventListener(OPEN_WELCOME_TOUR_EVENT, onOpen);
  }, []);

  const complete = useCallback(() => {
    mark(WELCOME_TOUR_ID);
    setOpen(false);
  }, [mark]);

  const step = steps[idx];
  const isFirst = idx === 0;
  const isLast = idx === steps.length - 1;

  if (!step) return null;

  const goThere = () => {
    complete();
    if (step.route) navigate(step.route);
  };

  return (
    <Dialog
      open={open}
      onOpenChange={(v) => {
        // Closing via overlay / X counts as "skip" — persist so it won't re-nag.
        if (!v) complete();
        setOpen(v);
      }}
    >
      <DialogContent className="sm:max-w-md" data-testid="welcome-tour">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Sparkles className="h-5 w-5 text-primary" />
            {step.title}
          </DialogTitle>
          <DialogDescription className="pt-1 text-sm leading-relaxed">
            {step.body}
          </DialogDescription>
        </DialogHeader>

        {step.route ? (
          <div>
            <Button variant="outline" size="sm" onClick={goThere} data-testid="welcome-tour-go">
              Go there
              <ArrowRight className="ml-1.5 h-4 w-4" />
            </Button>
          </div>
        ) : null}

        {/* progress dots */}
        <div className="flex items-center justify-center gap-1.5 pt-1">
          {steps.map((s, i) => (
            <span
              key={s.id}
              className={
                i === idx
                  ? "h-1.5 w-4 rounded-full bg-primary transition-all"
                  : "h-1.5 w-1.5 rounded-full bg-muted transition-all"
              }
            />
          ))}
        </div>

        <DialogFooter className="gap-2 sm:justify-between">
          <Button variant="ghost" size="sm" onClick={complete} data-testid="welcome-tour-skip">
            Skip
          </Button>
          <div className="flex gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => setIdx((i) => Math.max(0, i - 1))}
              disabled={isFirst}
              data-testid="welcome-tour-back"
            >
              Back
            </Button>
            {isLast ? (
              <Button size="sm" onClick={complete} data-testid="welcome-tour-done">
                Done
              </Button>
            ) : (
              <Button
                size="sm"
                onClick={() => setIdx((i) => Math.min(steps.length - 1, i + 1))}
                data-testid="welcome-tour-next"
              >
                Next
              </Button>
            )}
          </div>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
