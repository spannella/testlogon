// Polyfill crypto.randomUUID for non-secure HTTP contexts (local dev over plain HTTP).
// crypto.subtle is available but randomUUID requires a secure context in some browsers.
if (typeof crypto !== "undefined" && typeof crypto.randomUUID !== "function") {
  (crypto as { randomUUID?: () => string }).randomUUID = function (): string {
    const bytes = new Uint8Array(16);
    crypto.getRandomValues(bytes);
    bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
    bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
    const hex = Array.from(bytes).map((b) => b.toString(16).padStart(2, "0"));
    return `${hex.slice(0, 4).join("")}-${hex.slice(4, 6).join("")}-${hex.slice(6, 8).join("")}-${hex.slice(8, 10).join("")}-${hex.slice(10, 16).join("")}`;
  };
}

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { BrowserRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ThemeProvider } from "@/components/ThemeProvider";
import { TooltipProvider } from "@/components/ui/tooltip";
import { Toaster } from "@/components/ui/sonner";
import App from "./App";
import "./globals.css";

// Initialize i18n before rendering
import "./i18n";
import { RTLProvider } from "@/components/layout/RTLProvider";

// ── Referral attribution cookie (AFFILIATE-001) ────────────────
// If the URL contains ?ref=CODE, store it in a 30-day cookie so the
// backend can attribute the signup when the user registers.
(() => {
  try {
    const params = new URLSearchParams(window.location.search);
    const refCode = params.get("ref");
    if (refCode && /^[A-Za-z0-9]{8}$/.test(refCode)) {
      document.cookie = `ref_attribution=${refCode}; path=/; max-age=${30 * 86400}; SameSite=Lax`;
    }
  } catch {
    // Ignore — attribution is best-effort.
  }
})();

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 30_000,
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <TooltipProvider delayDuration={300}>
          <RTLProvider>
            <BrowserRouter>
              <App />
            </BrowserRouter>
            <Toaster richColors position="top-right" />
          </RTLProvider>
        </TooltipProvider>
      </ThemeProvider>
    </QueryClientProvider>
  </StrictMode>,
);
