import React from "react";
import ReactDOM from "react-dom/client";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import DevToolsLogUiPage from "@/pages/devtools/DevToolsLogUiPage";
import { ThemeProvider } from "@/components/ThemeProvider";
import "./globals.css";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: { retry: 1, staleTime: 10_000 },
  },
});

ReactDOM.createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <ThemeProvider>
      <QueryClientProvider client={queryClient}>
        <div className="min-h-screen bg-background">
          <div className="mx-auto max-w-7xl p-6">
            <DevToolsLogUiPage />
          </div>
        </div>
      </QueryClientProvider>
    </ThemeProvider>
  </React.StrictMode>,
);
