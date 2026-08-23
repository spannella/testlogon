import { describe, expect, it, vi, beforeEach } from "vitest";
import { MemoryRouter } from "react-router-dom";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, screen } from "@testing-library/react";

// Degrade path: the shared api leaf rejects with a 404 ApiError for every read.
// ApiError / withApiBase / normalizeErrorDetail stay REAL so instanceof checks
// and any imports keep working.
vi.mock("@/api/client", async () => {
  const actual = await vi.importActual<typeof import("@/api/client")>("@/api/client");
  return {
    ...actual,
    api: vi.fn(() => Promise.reject(new actual.ApiError(404, "Not found"))),
  };
});

import InvestHubPage from "@/pages/invest/InvestHubPage";

function renderPage() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <MemoryRouter>
      <QueryClientProvider client={qc}>
        <InvestHubPage />
      </QueryClientProvider>
    </MemoryRouter>,
  );
}

describe("InvestHubPage render smoke (degrade path)", () => {
  beforeEach(() => vi.clearAllMocks());

  it("mounts and shows its heading without throwing when every read 404s", async () => {
    renderPage();
    expect(await screen.findByRole("heading", { level: 1, name: /^Invest$/i })).toBeInTheDocument();
    expect(screen.getByTestId("discover-search")).toBeInTheDocument();
  });
});
