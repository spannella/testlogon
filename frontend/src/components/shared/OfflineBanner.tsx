import { useState, useEffect } from "react";
import { WifiOff } from "lucide-react";
import { useOfflineStore } from "@/stores/offlineStore";

export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);
  const queueCount = useOfflineStore((s) => s.queue.length);

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

  if (!offline) return null;

  return (
    <div className="flex w-full items-center justify-center gap-2 bg-warning px-4 py-2 text-warning-foreground text-sm font-medium animate-in slide-in-from-top duration-200">
      <WifiOff className="h-4 w-4" />
      You&apos;re offline &mdash; actions will be sent when reconnected
      {queueCount > 0 && (
        <span className="ml-1 rounded-full bg-warning-foreground/20 px-2 py-0.5 text-xs font-semibold">
          {queueCount} queued
        </span>
      )}
    </div>
  );
}
