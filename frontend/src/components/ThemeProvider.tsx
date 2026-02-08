import { useEffect } from "react";
import { useUiStore } from "@/stores/uiStore";

/**
 * Applies the correct `dark` class to <html> based on the theme
 * preference stored in uiStore. Listens for OS-level changes when
 * the preference is "system".
 */
export function ThemeProvider({ children }: { children: React.ReactNode }) {
  const theme = useUiStore((s) => s.theme);

  useEffect(() => {
    const root = document.documentElement;

    function apply(isDark: boolean) {
      root.classList.toggle("dark", isDark);
    }

    if (theme === "dark") {
      apply(true);
      return;
    }

    if (theme === "light") {
      apply(false);
      return;
    }

    // "system" — match OS preference and listen for changes
    const mq = window.matchMedia("(prefers-color-scheme: dark)");
    apply(mq.matches);

    function onChange(e: MediaQueryListEvent) {
      apply(e.matches);
    }

    mq.addEventListener("change", onChange);
    return () => mq.removeEventListener("change", onChange);
  }, [theme]);

  return <>{children}</>;
}
