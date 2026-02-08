import { useState, useEffect } from "react";
import { WifiOff } from "lucide-react";

export function OfflineBanner() {
  const [offline, setOffline] = useState(!navigator.onLine);

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
      You&apos;re offline &mdash; some features may be unavailable
    </div>
  );
}
