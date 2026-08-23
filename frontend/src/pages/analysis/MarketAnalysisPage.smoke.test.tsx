import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return {
    ...actual,
    api: vi.fn(() => Promise.reject(new actual.ApiError(404, "Not found"))),
  };
});

import MarketAnalysisPage from "@/pages/analysis/MarketAnalysisPage";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <MarketAnalysisPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("MarketAnalysisPage render smoke (degrade path)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("mounts and shows its heading without throwing when symbols/history 404", async () => {
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: /Analysis/i }),
    ).toBeInTheDocument();
  });
});
