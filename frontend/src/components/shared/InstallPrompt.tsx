import { useState } from "react";
import { Download, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import { useInstallPrompt } from "@/hooks/useInstallPrompt";

/**
 * PWA install banner. Shows when:
 * 1. Browser fires `beforeinstallprompt` (Chromium only)
 * 2. App is NOT already in standalone mode
 * 3. User has not dismissed within the last 30 days
 *
 * On iOS Safari, this component never renders (no `beforeinstallprompt`).
 */
export function InstallPrompt() {
  const { canInstall, isInstalled, dismissed, promptInstall, dismiss } =
    useInstallPrompt();
  const [installing, setInstalling] = useState(false);

  const handleInstall = async () => {
    setInstalling(true);
    try {
      await promptInstall();
    } finally {
      setInstalling(false);
    }
  };

  if (!canInstall || isInstalled || dismissed) return null;

  return (
    <div
      className="flex w-full items-center justify-center gap-3 bg-primary px-4 py-2.5 text-primary-foreground text-sm font-medium animate-in slide-in-from-top duration-300"
      role="banner"
      aria-label="Install application prompt"
      data-testid="install-prompt"
    >
      <Download className="h-4 w-4 shrink-0" aria-hidden />
      <span>Install Control Panel for quick access</span>
      <Button
        size="sm"
        variant="secondary"
        onClick={handleInstall}
        disabled={installing}
        className="h-7 px-3 text-xs font-semibold"
      >
        {installing ? "Installing..." : "Install"}
      </Button>
      <button
        onClick={dismiss}
        className="ml-1 rounded p-1 hover:bg-primary-foreground/10 transition-colors"
        aria-label="Dismiss install prompt"
      >
        <X className="h-4 w-4" />
      </button>
    </div>
  );
}
