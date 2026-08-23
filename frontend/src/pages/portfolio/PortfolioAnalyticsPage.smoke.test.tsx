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

import PortfolioAnalyticsPage from "@/pages/portfolio/PortfolioAnalyticsPage";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <PortfolioAnalyticsPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("PortfolioAnalyticsPage render smoke (degrade path)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("mounts and shows its heading without throwing when every source 404s", async () => {
    renderPage();
    expect(
      await screen.findByRole("heading", { level: 1, name: /Portfolio Risk/i }),
    ).toBeInTheDocument();
  });
});
