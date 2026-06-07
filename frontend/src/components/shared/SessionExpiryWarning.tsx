import * as React from "react";
import { AlertTriangle, Timer } from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { refreshSession, logout as apiLogout } from "@/api/endpoints/auth";
import { useAuthStore } from "@/stores/authStore";

// Must match the server-side UI_INACTIVITY_SECONDS (default 7200 = 2 hours).
// The client tracks user-interaction idle time; any activity resets the clock.
const INACTIVITY_MS = 2 * 60 * 60 * 1000; // 2 hours
const WARN_BANNER_MS = 5 * 60 * 1000; // show banner 5 min before expiry
const WARN_DIALOG_MS = 2 * 60 * 1000; // show dialog 2 min before expiry

function formatCountdown(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${m}:${s.toString().padStart(2, "0")}`;
}

/** Parse the `exp` claim (UTC epoch seconds) from a JWT, or null if unparseable. */
function getJwtExpMs(token: string | null): number | null {
  if (!token) return null;
  try {
    const parts = token.split(".");
    if (parts.length !== 3) return null;
    const encoded = parts[1];
    if (!encoded) return null;
    const payload = JSON.parse(atob(encoded.replace(/-/g, "+").replace(/_/g, "/"))) as Record<string, unknown>;
    if (typeof payload.exp !== "number") return null;
    return payload.exp * 1000;
  } catch {
    return null;
  }
}

export function SessionExpiryWarning() {
  const lastActivityRef = React.useRef<number>(Date.now());
  const [remainingMs, setRemainingMs] = React.useState<number>(INACTIVITY_MS);
  const [extending, setExtending] = React.useState(false);
  const hasLoggedOutRef = React.useRef(false);
  const autoRefreshingRef = React.useRef(false);
  const { logout, accessToken, setAccessToken } = useAuthStore();
  const navigate = useNavigate();

  // Reset inactivity clock on any user interaction OR successful API call.
  React.useEffect(() => {
    const resetActivity = () => {
      lastActivityRef.current = Date.now();
    };
    const events = [
      "mousemove",
      "mousedown",
      "keydown",
      "touchstart",
      "scroll",
      "click",
      "api-activity",
    ] as const;
    for (const e of events) {
      window.addEventListener(e, resetActivity, { passive: true });
    }
    return () => {
      for (const e of events) {
        window.removeEventListener(e, resetActivity);
      }
    };
  }, []);

  // Tick every second. Compute the effective remaining time as the minimum of
  // inactivity-based remaining time and JWT expiry remaining time.
  React.useEffect(() => {
    hasLoggedOutRef.current = false;
    const update = () => {
      const now = Date.now();
      const idleMs = now - lastActivityRef.current;
      const inactivityRemaining = Math.max(0, INACTIVITY_MS - idleMs);

      const jwtExpMs = getJwtExpMs(accessToken);
      const jwtRemaining = jwtExpMs != null ? Math.max(0, jwtExpMs - now) : Infinity;

      const effective = Math.min(inactivityRemaining, jwtRemaining);
      setRemainingMs(effective);

      // Proactive refresh: if the user is still active (inactivity is NOT the
      // binding constraint) but the access token is nearing expiry, silently
      // re-mint it so an active user is never logged out mid-session. A truly
      // idle user (inactivityRemaining <= jwtRemaining) is left to expire.
      if (
        jwtRemaining > 0 &&
        jwtRemaining <= WARN_BANNER_MS &&
        inactivityRemaining > jwtRemaining &&
        !autoRefreshingRef.current
      ) {
        autoRefreshingRef.current = true;
        void refreshSession()
          .then((r) => {
            if (r?.access_token) setAccessToken(r.access_token);
          })
          .catch(() => {})
          .finally(() => {
            autoRefreshingRef.current = false;
          });
      }

      // Force logout when timer hits 0
      if (effective === 0 && !hasLoggedOutRef.current) {
        hasLoggedOutRef.current = true;
        void apiLogout().catch(() => {});
        logout("session_expired");
        navigate("/login", { replace: true });
      }
    };
    update();
    const id = setInterval(update, 1000);
    return () => clearInterval(id);
  }, [accessToken, logout, navigate, setAccessToken]);

  const handleStayLoggedIn = async () => {
    setExtending(true);
    try {
      const r = await refreshSession();
      if (r?.access_token) setAccessToken(r.access_token);
      // Reset local idle clock so the warning disappears immediately.
      lastActivityRef.current = Date.now();
      setRemainingMs(INACTIVITY_MS);
    } catch {
      // Refresh failed — force logout cleanly.
      await apiLogout().catch(() => {});
      logout("session_expired");
      navigate("/login", { replace: true });
    } finally {
      setExtending(false);
    }
  };

  const handleLogout = async () => {
    await apiLogout().catch(() => {});
    logout();
    navigate("/login", { replace: true });
  };

  const showBanner = remainingMs <= WARN_BANNER_MS && remainingMs > WARN_DIALOG_MS;
  const showDialog = remainingMs > 0 && remainingMs <= WARN_DIALOG_MS;

  if (remainingMs > WARN_BANNER_MS) return null;

  return (
    <>
      {/* Amber banner — visible from 5 min down to 2 min */}
      {showBanner && (
        <div className="flex items-center justify-between gap-3 border-b border-amber-300/60 bg-amber-50 px-4 py-2 text-sm text-amber-800 dark:border-amber-700/40 dark:bg-amber-950/40 dark:text-amber-300">
          <div className="flex items-center gap-2">
            <Timer className="h-4 w-4 shrink-0" />
            <span>
              Session expires in{" "}
              <strong className="tabular-nums">{formatCountdown(remainingMs)}</strong> — click{" "}
              <em>Stay logged in</em> to extend
            </span>
          </div>
          <Button
            size="sm"
            variant="outline"
            onClick={() => void handleStayLoggedIn()}
            disabled={extending}
            className="border-amber-400 bg-transparent text-amber-800 hover:bg-amber-100 dark:border-amber-600 dark:text-amber-300 dark:hover:bg-amber-900/40"
          >
            {extending ? "Extending…" : "Stay logged in"}
          </Button>
        </div>
      )}

      {/* Dialog — appears at 2 min, blocks interaction until resolved */}
      <Dialog open={showDialog}>
        <DialogContent
          onInteractOutside={(e) => e.preventDefault()}
          onEscapeKeyDown={(e) => e.preventDefault()}
          className="max-w-sm"
        >
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              Session expiring soon
            </DialogTitle>
            <DialogDescription>
              You will be automatically logged out in{" "}
              <strong className="tabular-nums text-foreground">
                {formatCountdown(remainingMs)}
              </strong>
              . Click <em>Stay logged in</em> to continue your session, or{" "}
              <em>Log out</em> to end it now.
            </DialogDescription>
          </DialogHeader>
          <DialogFooter className="gap-2 sm:gap-0">
            <Button variant="ghost" onClick={() => void handleLogout()}>
              Log out
            </Button>
            <Button onClick={() => void handleStayLoggedIn()} disabled={extending}>
              {extending ? "Extending…" : "Stay logged in"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}
