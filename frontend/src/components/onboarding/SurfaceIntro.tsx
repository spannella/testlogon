// Dismissible per-surface intro callout shown once at the top of a new trading /
// investing page. Persisted via the shared `onboarding.v1` seen-set (keyed
// "intro:<surfaceId>"), so once dismissed it stays gone until the user resets
// intros from Settings. Additive + reversible.

import { Info, X } from "lucide-react";

import { Alert, AlertTitle, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { surfaceIntro, useOnboarding, shouldShow } from "@/lib/onboarding";

interface SurfaceIntroProps {
  /** Raw surface id from TRADING_SURFACES, e.g. "invest" / "strategies". */
  surfaceId: string;
}

/**
 * Renders a one-paragraph "what this is + key action" callout for `surfaceId`,
 * or nothing once it has been dismissed (or if the id is unknown).
 */
export default function SurfaceIntro({ surfaceId }: SurfaceIntroProps) {
  const entry = surfaceIntro(surfaceId);
  const { seen, mark } = useOnboarding();

  if (!entry) return null;
  if (!shouldShow(entry.id, seen)) return null;

  return (
    <Alert className="relative pr-10" data-testid={`surface-intro-${surfaceId}`}>
      <Info className="h-4 w-4" />
      <AlertTitle>{entry.title}</AlertTitle>
      <AlertDescription className="text-sm leading-relaxed">{entry.body}</AlertDescription>
      <Button
        variant="ghost"
        size="icon"
        className="absolute right-1.5 top-1.5 h-7 w-7 text-muted-foreground"
        onClick={() => mark(entry.id)}
        aria-label="Dismiss"
        data-testid={`surface-intro-dismiss-${surfaceId}`}
      >
        <X className="h-4 w-4" />
      </Button>
    </Alert>
  );
}
