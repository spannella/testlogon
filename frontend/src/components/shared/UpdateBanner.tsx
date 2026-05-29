import { useState, useEffect, useCallback } from "react";
import { RefreshCw } from "lucide-react";
import { Button } from "@/components/ui/button";

/**
 * Banner shown when a new service worker version is activated.
 * Prompts the user to reload to pick up the latest code.
 *
 * Rendered in AppShell alongside OfflineBanner. The banner is
 * non-dismissible (the only action is "Refresh") because running
 * old JS against a new SW can cause cache inconsistencies.
 */
export function UpdateBanner() {
  const [showUpdate, setShowUpdate] = useState(false);

  useEffect(() => {
    const handler = () => setShowUpdate(true);
    window.addEventListener("sw-updated", handler);
    return () => window.removeEventListener("sw-updated", handler);
  }, []);

  const handleRefresh = useCallback(() => {
    window.location.reload();
  }, []);

  if (!showUpdate) return null;

  return (
    <div
      className="flex w-full items-center justify-center gap-2 bg-blue-500 px-4 py-2 text-white text-sm font-medium animate-in slide-in-from-top duration-200"
      role="alert"
      aria-live="polite"
    >
      <RefreshCw className="h-4 w-4" aria-hidden />
      <span>A new version is available.</span>
      <Button
        size="sm"
        variant="secondary"
        onClick={handleRefresh}
        className="h-7 px-3 text-xs font-semibold"
      >
        Refresh
      </Button>
    </div>
  );
}
