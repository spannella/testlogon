import { useState, useEffect, useRef, useCallback } from "react";

const DISMISS_KEY = "pwa_install_dismissed";
const COOLDOWN_MS = 30 * 86400 * 1000; // 30 days

/**
 * React hook for managing the PWA install prompt.
 *
 * - Listens for `beforeinstallprompt` (Chromium browsers only)
 * - Stashes the event for later use via `promptInstall()`
 * - Checks `display-mode: standalone` for `isInstalled`
 * - Persists dismissal in `localStorage` with a 30-day cooldown
 */
export function useInstallPrompt() {
  const [canInstall, setCanInstall] = useState(false);
  const [isInstalled, setIsInstalled] = useState(false);
  const [dismissed, setDismissed] = useState(false);
  const promptRef = useRef<BeforeInstallPromptEvent | null>(null);

  // Check if already installed (standalone mode)
  useEffect(() => {
    const mq = window.matchMedia("(display-mode: standalone)");
    setIsInstalled(mq.matches || (navigator as any).standalone === true);
    const handler = (e: MediaQueryListEvent) => setIsInstalled(e.matches);
    mq.addEventListener("change", handler);
    return () => mq.removeEventListener("change", handler);
  }, []);

  // Check dismissal cooldown
  useEffect(() => {
    const ts = localStorage.getItem(DISMISS_KEY);
    if (ts && Date.now() - Number(ts) < COOLDOWN_MS) {
      setDismissed(true);
    }
  }, []);

  // Listen for beforeinstallprompt
  useEffect(() => {
    if (isInstalled) return;

    const onBeforeInstall = (e: Event) => {
      e.preventDefault(); // Suppress Chrome's mini-infobar
      const prompt = e as BeforeInstallPromptEvent;
      promptRef.current = prompt;
      setCanInstall(true);
    };

    const onInstalled = () => {
      setCanInstall(false);
      setIsInstalled(true);
      promptRef.current = null;
    };

    window.addEventListener("beforeinstallprompt", onBeforeInstall);
    window.addEventListener("appinstalled", onInstalled);

    return () => {
      window.removeEventListener("beforeinstallprompt", onBeforeInstall);
      window.removeEventListener("appinstalled", onInstalled);
    };
  }, [isInstalled]);

  const promptInstall = useCallback(async (): Promise<"accepted" | "dismissed" | null> => {
    const prompt = promptRef.current;
    if (!prompt) return null;

    try {
      await prompt.prompt();
      const choice = await prompt.userChoice;

      if (choice.outcome === "accepted") {
        setCanInstall(false);
        promptRef.current = null;
      } else {
        // User dismissed -- set 30-day cooldown
        localStorage.setItem(DISMISS_KEY, String(Date.now()));
        setDismissed(true);
      }

      return choice.outcome;
    } catch {
      // prompt() can throw if already called or prompt expired
      return null;
    }
  }, []);

  const dismiss = useCallback(() => {
    localStorage.setItem(DISMISS_KEY, String(Date.now()));
    setDismissed(true);
  }, []);

  return {
    canInstall,
    isInstalled,
    dismissed,
    promptInstall,
    dismiss,
  };
}
