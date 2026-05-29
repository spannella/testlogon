import { useState, useEffect } from "react";
import { WifiOff } from "lucide-react";
import { useOfflineStore } from "@/stores/offlineStore";

export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const queue = useOfflineStore((s) => s.queue);
  const queueCount = queue.length;
  const failedCount = queue.filter((a) => a.__status === "failed").length;
  const pendingCount = queueCount - failedCount;

  useEffect(() => {
    const goOffline = () => setOffline(true);
    const goOnline = () => setOffline(false);
    window.addEventListener("offline", goOffline);
    window.addEventListener("online", goOnline);
    return () => {
      window.removeEventListener("offline", goOffline);
      window.removeEventListener("online", goOnline);
    };
  }, []);

  if (!offline && failedCount === 0) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-warning px-4 py-2 text-warning-foreground text-sm font-medium animate-in slide-in-from-top duration-200">
      <WifiOff className="h-4 w-4" />
      {offline ? (
        <>
          <span>You&apos;re offline &mdash; showing cached data</span>
          {pendingCount > 0 && (
            <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
              {pendingCount} queued
            </span>
          )}
        </>
      ) : null}
      {failedCount > 0 && (
        <span className="ml-1 rounded-full bg-destructive/20 px-2 py-0.5 text-xs font-semibold text-destructive">
          {failedCount} failed
        </span>
      )}
    </div>
  );
}
