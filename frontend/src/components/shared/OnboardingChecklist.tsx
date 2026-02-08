import { useState, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { Check, X, Sparkles } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

const STORAGE_KEY = "onboarding_state";

interface ChecklistItem {
  id: string;
  label: string;
  path: string;
}

const CHECKLIST: ChecklistItem[] = [
  { id: "profile", label: "Complete your profile", path: "/profile" },
  { id: "payment", label: "Add a payment method", path: "/billing" },
  { id: "mfa", label: "Set up MFA", path: "/security" },
  { id: "message", label: "Send your first message", path: "/messages" },
];

interface OnboardingState {
  dismissed: boolean;
  completed: string[];
}

function loadState(): OnboardingState {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) {
      const parsed = JSON.parse(raw) as OnboardingState;
      return {
        dismissed: !!parsed.dismissed,
        completed: Array.isArray(parsed.completed) ? parsed.completed : [],
      };
    }
  } catch {
    // ignore
  }
  return { dismissed: false, completed: [] };
}

function saveState(state: OnboardingState) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

export function OnboardingChecklist() {
  const navigate = useNavigate();
  const [state, setState] = useState(loadState);

  const completedSet = useMemo(() => new Set(state.completed), [state.completed]);
  const completedCount = state.completed.length;
  const total = CHECKLIST.length;
  const allDone = completedCount >= total;

  if (state.dismissed) return null;

  const toggleItem = (id: string) => {
    const next = completedSet.has(id)
      ? state.completed.filter((c) => c !== id)
      : [...state.completed, id];
    const newState = { ...state, completed: next };
    setState(newState);
    saveState(newState);
  };

  const dismiss = () => {
    const newState = { ...state, dismissed: true };
    setState(newState);
    saveState(newState);
  };

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-primary" />
          <CardTitle className="text-base">
            {allDone ? "All set!" : "Get Started"}
          </CardTitle>
        </div>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          onClick={dismiss}
          aria-label="Dismiss onboarding"
        >
          <X className="h-4 w-4" />
        </Button>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Progress bar */}
        <div className="space-y-1">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>{completedCount} of {total} complete</span>
            <span>{Math.round((completedCount / total) * 100)}%</span>
          </div>
          <div className="h-2 overflow-hidden rounded-full bg-muted">
            <div
              className="h-full rounded-full bg-primary transition-all duration-300"
              style={{ width: `${(completedCount / total) * 100}%` }}
            />
          </div>
        </div>

        {allDone ? (
          <p className="text-sm text-muted-foreground">
            You&apos;ve completed all the getting started steps. Welcome aboard!
          </p>
        ) : (
          <ul className="space-y-2">
            {CHECKLIST.map((item) => {
              const done = completedSet.has(item.id);
              return (
                <li
                  key={item.id}
                  className="flex items-center justify-between rounded-lg border px-3 py-2"
                >
                  <div className="flex items-center gap-3">
                    <button
                      onClick={() => toggleItem(item.id)}
                      className={cn(
                        "flex h-5 w-5 shrink-0 items-center justify-center rounded border transition-colors",
                        done
                          ? "border-primary bg-primary text-primary-foreground"
                          : "border-input hover:border-primary",
                      )}
                    >
                      {done && <Check className="h-3 w-3" />}
                    </button>
                    <span
                      className={cn(
                        "text-sm",
                        done && "text-muted-foreground line-through",
                      )}
                    >
                      {item.label}
                    </span>
                  </div>
                  {!done && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="h-7 text-xs"
                      onClick={() => navigate(item.path)}
                    >
                      Go
                    </Button>
                  )}
                </li>
              );
            })}
          </ul>
        )}
      </CardContent>
    </Card>
  );
}
